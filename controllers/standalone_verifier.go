package controllers

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/intel-secl/sample-sgx-attestation/v3/config"
	"github.com/pkg/errors"
	"intel/isecl/sqvs/v3/resource/parser"
	"intel/isecl/sqvs/v3/resource/utils"
	"intel/isecl/sqvs/v3/resource/verifier"
	"io/ioutil"
	"net/http"
)

// StandaloneVerifier verifies quotes when SGX Attestation service is operating in standalone mode
type StandaloneVerifier struct {
	Config *config.Configuration
}

func (ev StandaloneVerifier) VerifyQuote(quoteData string) error {
	// for standalone mode, pass quote to the SQVS stub
	parsedBlob := parser.ParseSkcQuoteBlob(quoteData)
	if parsedBlob == nil {
		return errors.New("controllers/standalone_verifier:VerifyQuote() Error parsing quote")
	}

	if parsedBlob.GetQuoteType() == parser.QuoteTypeEcdsa {
		return sgxEcdsaQuoteVerify(parsedBlob, ev.Config)
	} else if parsedBlob.GetQuoteType() == parser.QuoteTypeSw {
		return swQuoteVerify(parsedBlob, ev.Config)
	} else {
		return &resourceError{Message: "cannot find sw/ecdsa quote",
			StatusCode: http.StatusBadRequest}
	}
}

func swQuoteVerify(skcBlobParser *parser.SkcBlobParsed, conf *config.Configuration) error {
	_, err := skcBlobParser.GetRsaPubKey()
	if err != nil {
		return &resourceError{Message: "GetRsaPubKey: Error: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	return nil
}

func sgxEcdsaQuoteVerify(skcBlobParser *parser.SkcBlobParsed, conf *config.Configuration) error {
	if len(skcBlobParser.GetQuoteBlob()) == 0 {
		return &resourceError{Message: "invalid sgx ecdsa quote", StatusCode: http.StatusBadRequest}
	}

	quoteObj := parser.ParseEcdsaQuoteBlob(skcBlobParser.GetQuoteBlob())
	if quoteObj == nil {
		return &resourceError{Message: "invalid sgx ecdsa quote", StatusCode: http.StatusBadRequest}
	}

	// pull self-signed trusted root CA
	trustedRootCABytes, err := ioutil.ReadFile(conf.TrustedRootCAPath)
	if err != nil {
		return errors.New("sgxEcdsaQuoteVerify: Failed to read self-signed CA cert: " + conf.TrustedRootCAPath + " : " + err.Error())
	}
	block, _ := pem.Decode([]byte(trustedRootCABytes))
	if block == nil {
		return errors.New("sgxEcdsaQuoteVerify: Pem Decode error")
	}
	trustedRootCACert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("sgxEcdsaQuoteVerify: ParseCertificate error: " + err.Error())
	}

	pckCertBytes, err := utils.GetCertPemData(quoteObj.GetQuotePckCertObj())
	if err != nil {
		return &resourceError{Message: "invalid sgx ecdsa quote: " + err.Error(),
			StatusCode: http.StatusBadRequest}
	}

	certObj := parser.NewPCKCertObj(pckCertBytes)
	if certObj == nil {
		return &resourceError{Message: "Invalid PCK Certificate Buffer", StatusCode: http.StatusBadRequest}
	}

	_, err = verifier.VerifyPCKCertificate(quoteObj.GetQuotePckCertObj(), quoteObj.GetQuotePckCertInterCAList(),
		quoteObj.GetQuotePckCertRootCAList(), certObj.GetPckCrlObj(), trustedRootCACert)
	if err != nil {
		return &resourceError{Message: "cannot verify pck cert: " + err.Error(),
			StatusCode: http.StatusBadRequest}
	}

	_, err = verifier.VerifyPckCrl(certObj.GetPckCrlUrl(), certObj.GetPckCrlObj(), certObj.GetPckCrlInterCaList(),
		certObj.GetPckCrlRootCaList(), trustedRootCACert)
	if err != nil {
		return &resourceError{Message: "cannot verify pck crl: " + err.Error(),
			StatusCode: http.StatusBadRequest}
	}

	tcbObj, err := parser.NewTcbInfo(certObj.GetFmspcValue())
	if err != nil {
		return &resourceError{Message: "Get TCB Info data parsing/fetch failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	err = verifyTcbInfo(certObj, tcbObj, trustedRootCACert)
	if err != nil {
		return &resourceError{Message: "TCBInfo Verification failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	tcbUptoDateStatus := tcbObj.GetTcbUptoDateStatus(certObj.GetPckCertTcbLevels())
	defaultLog.Info("Current Tcb-Upto-Date Status is : ", tcbUptoDateStatus)

	qeIdObj, err := parser.NewQeIdentity()
	if err != nil {
		return &resourceError{Message: "QEIdentity Parsing failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifyQeIdentity(qeIdObj, quoteObj, trustedRootCACert)
	if err != nil {
		return &resourceError{Message: "verifyQeIdentity failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = skcBlobParser.GetRsaPubKey()
	if err != nil {
		return &resourceError{Message: "GetRsaPubKey: Error: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifier.VerifiySHA256Hash(quoteObj.GetSHA256Hash(), skcBlobParser.GetPubKeyBlob())
	if err != nil {
		defaultLog.Error(err.Error())
		return &resourceError{Message: "VerifiySHA256Hash failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	blob1, err := quoteObj.GetRawBlob1()
	if err != nil {
		defaultLog.Error(err.Error())
		return &resourceError{Message: "Invalid Raw Blob data in SGX ECDSA Quote: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifier.VerifySGXECDSASign1(quoteObj.GetECDSASignature1(), blob1, certObj.GetECDSAPublicKey())
	if err != nil {
		return &resourceError{Message: "SGX ECDSA Signature Verification(1) failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}
	blob2, err := quoteObj.GetRawBlob2()
	if err != nil {
		defaultLog.Error(err.Error())
		return &resourceError{Message: "Invalid Raw Blob 2 data in SGX ECDSA Quote: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	_, err = verifier.VerifySGXECDSASign2(quoteObj.GetECDSASignature2(), blob2, quoteObj.GetECDSAPublicKey2())
	if err != nil {
		defaultLog.Error(err.Error())
		return &resourceError{Message: "SGX ECDSA Signature Verification(2) failed: " + err.Error(),
			StatusCode: http.StatusInternalServerError}
	}

	defaultLog.Info("Sgx Ecdsa Quote Verification completed")
	return nil
}

func verifyQeIdentityReport(qeIdObj *parser.QeIdentityData, quoteObj *parser.SgxQuoteParsed) (bool, error) {
	_, err := verifier.VerifyMiscSelect(quoteObj.GetQeReportMiscSelect(), qeIdObj.GetQeIdMiscSelect(),
		qeIdObj.GetQeIdMiscSelectMask())
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentityReport: ")
	}

	_, err = verifier.VerifyAttributes(quoteObj.GetQeReportAttributes(), qeIdObj.GetQeIdAttributes(),
		qeIdObj.GetQeIdAttributesMask())
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentityReport:")
	}

	_, err = verifier.VerifyReportAttrSize(quoteObj.GetQeReportMrSigner(), "MrSigner", qeIdObj.GetQeIdMrSigner())
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentityReport")
	}

	if quoteObj.GetQeReportProdId() < qeIdObj.GetQeIdIsvProdId() {
		defaultLog.Info("Qe Prod Id in ecdsa quote is below the minimum prod id expected for QE")
	}

	if quoteObj.GetQeReportIsvSvn() < qeIdObj.GetQeIdIsvSvn() {
		defaultLog.Info("IsvSvn in ecdsa quote is below the minimum IsvSvn expected for QE")
	}
	return true, nil
}

func verifyQeIdentity(qeIdObj *parser.QeIdentityData, quoteObj *parser.SgxQuoteParsed,
	trustedRootCA *x509.Certificate) (bool, error) {

	if qeIdObj == nil || quoteObj == nil {
		return false, errors.New("verifyQeIdentity: QEIdentity/Quote Object is empty")
	}
	_, err := verifier.VerifyQeIdCertChain(qeIdObj.GetQeInfoInterCaList(), qeIdObj.GetQeInfoRootCaList(),
		trustedRootCA)
	if err != nil {
		return false, errors.Wrap(err, "verifyQeIdentity: VerifyQeIdCertChain")
	}

	status := qeIdObj.GetQeIdentityStatus()
	if status == false {
		return false, errors.New("verifyQeIdentity: GetQeIdentityStatus is invalid")
	}

	if utils.CheckDate(qeIdObj.GetQeIdIssueDate(), qeIdObj.GetQeIdNextUpdate()) == false {
		return false, errors.New("verifyQeIdentity: Date Check validation failed")
	}

	return verifyQeIdentityReport(qeIdObj, quoteObj)
}

func verifyTcbInfo(certObj *parser.PckCert, tcbObj *parser.TcbInfoStruct, trustedRootCA *x509.Certificate) error {
	if tcbObj.GetTcbInfoFmspc() != certObj.GetFmspcValue() {
		return errors.New("verifyTcbInfo: FMSPC in TCBInfoStruct does not match with PCK Cert FMSPC")
	}

	_, err := verifier.VerifyTcbInfoCertChain(tcbObj.GetTcbInfoInterCaList(), tcbObj.GetTcbInfoRootCaList(),
		trustedRootCA)
	if err != nil {
		return errors.Wrap(err, "verifyTcbInfo: failed to verify Tcbinfo Certchain")
	}

	if utils.CheckDate(tcbObj.GetTcbInfoIssueDate(), tcbObj.GetTcbInfoNextUpdate()) == false {
		return errors.New("verifyTcbInfo: Date Check validation failed")
	}

	return nil
}
