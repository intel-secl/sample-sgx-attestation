/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tcpmsglib"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/constants"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v3/crypt"
	"intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/sqvs/v3/resource/parser"
	"io/ioutil"
	"strconv"
	"strings"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type resourceError struct {
	StatusCode int
	Message    string
}

func (e resourceError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type AppVerifierController struct {
	TenantAppSocketAddr string
	Config              *config.Configuration
	SaVerifier          StandaloneVerifier
	SgxQuotePolicyPath  string
}

func (ca AppVerifierController) VerifyTenantAndShareSecret() bool {
	defaultLog.Trace("controllers/app_verifier_controller:VerifyTenantAndShareSecret() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:VerifyTenantAndShareSecret() Leaving")

	defaultLog.Printf("Forming request to connect to Tenant App")

	//Following are dummy credentials which are not going to be validated in tenant app
	params := map[uint8][]byte{
		constants.ParamTypeUsername: []byte(constants.TenantUsername), //username
		constants.ParamTypePassword: []byte(constants.TenantPassword), //password
	}
	connectRequest := tcpmsglib.MarshalRequest(constants.ReqTypeConnect, params)

	// send the connect request to tenant app
	defaultLog.Printf("Sending request to connect to Tenant App and for SGX quote")
	connectResponseBytes, err := tcpmsglib.SendMessageAndGetResponse(ca.TenantAppSocketAddr, connectRequest)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error connecting to Tenant app")
		return false
	}

	// parse connect request response from tenant app
	connectResponse, err := tcpmsglib.UnmarshalResponse(connectResponseBytes)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error while unmarshalling response for connect from Tenant app")
		return false
	}
	if connectResponse != nil && connectResponse.RespCode == constants.ResponseCodeSuccess {
		defaultLog.Printf("Connected to tenant app successfully")

		var enclavePublicKey []byte
		var sgxQuote []byte
		for _, v := range connectResponse.Elements {
			if v.Type == constants.ResponseElementTypeSGXQuote {
				sgxQuote = v.Payload
			}
		}
		defaultLog.Printf("Verifying SGX quote")
		err := ca.verifySgxQuote(sgxQuote)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error while verifying SGX quote")
			return false
		}
		defaultLog.Printf("Verified SGX quote successfully")

		// extract enclave pub key from quote
		enclavePublicKey, err = parser.ParseSkcQuoteBlob(base64.StdEncoding.EncodeToString(sgxQuote)).GetRsaPubKey()
		if err != nil {
			defaultLog.WithError(err).Errorf("Failed to extract enclave public key from extended quote")
			return false
		}

		defaultLog.Printf("Generating SWK")
		swk, err := generateSWK()
		if err != nil {
			defaultLog.Printf("Error while generating SWK")
			return false
		}
		defaultLog.Printf("Generated SWK successfully")

		defaultLog.Printf("Wrapping SWK by Tenant Enclave Public Key")
		pubkeyWrappedSWK, err := wrapSWKByPublicKey(swk, enclavePublicKey)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error while wrapping SWK by Tenant enclave public key")
			return false
		}
		defaultLog.Printf("Wrapped SWK by Tenant Enclave Public Key")

		defaultLog.Printf("Forming request to send Wrapped SWK to Tenant App")
		params = map[uint8][]byte{
			constants.ParamTypePubkeyWrappedSwk: pubkeyWrappedSWK,
		}
		wrappedSWKRequest := tcpmsglib.MarshalRequest(constants.ReqTypePubkeyWrappedSWK, params)

		defaultLog.Debugf("Sending request to send Wrapped SWK to Tenant App")
		wrappedSWKResponseBytes, err := tcpmsglib.SendMessageAndGetResponse(ca.TenantAppSocketAddr, wrappedSWKRequest)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error while getting response for wrapped SWK from Tenant app")
			return false
		}
		wrappedSWKResponse, err := tcpmsglib.UnmarshalResponse(wrappedSWKResponseBytes)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error while unmarshalling response for wrapped SWK from Tenant app")
			return false
		}
		if wrappedSWKResponse != nil && wrappedSWKResponse.RespCode == constants.ResponseCodeSuccess {
			defaultLog.Info("Wrapped SWK sent to Tenant App successfully")
		} else {
			defaultLog.WithError(err).Errorf("Failed to send Wrapped SWK sent to Tenant App")
			return false
		}

		defaultLog.Printf("Generating new secret")
		secret, err := generateSecret(constants.DefaultSecretLength)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error while generating secret")
			return false
		}
		defaultLog.Printf("Generated new secret successfully")

		defaultLog.Printf("Wrapping secret by SWK")
		swkWrappedSecret, err := wrapSecretBySWK(secret, swk)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error while wrapping secret by SWK")
			return false
		}
		defaultLog.Printf("Wrapped secret by SWK successfully")

		defaultLog.Printf("Forming request to send Wrapped Secret by SWK to Tenant App")
		params = map[uint8][]byte{
			constants.ParamTypeSwkWrappedSecret: swkWrappedSecret, //SwkWrappedSecret
		}
		defaultLog.Printf("Sending request to send Wrapped Secret SWK to Tenant App")
		SWKWrappedSecretRequest := tcpmsglib.MarshalRequest(constants.ReqTypeSWKWrappedSecret, params)

		SWKWrappedSecretResponseBytes, err := tcpmsglib.SendMessageAndGetResponse(ca.TenantAppSocketAddr, SWKWrappedSecretRequest)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error while getting response for SWK wrapped secret from Tenant app")
			return false
		}
		SWKWrappedSecretResponse, err := tcpmsglib.UnmarshalResponse(SWKWrappedSecretResponseBytes)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error while unmarshalling response for SWK wrapped secret from Tenant app")
			return false
		}
		if SWKWrappedSecretResponse != nil && SWKWrappedSecretResponse.RespCode == constants.ResponseCodeSuccess {
			defaultLog.Info("Wrapped Secret by SWK sent to Tenant App successfully")
			return SWKWrappedSecretResponse.RespCode == constants.ResponseCodeSuccess
		} else {
			defaultLog.WithError(err).Errorf("Failed to send Wrapped Secret by SWK sent to Tenant App")
			return false
		}
	} else {
		defaultLog.WithError(err).Errorf("Failed to connect to Tenant App")
	}
	return false
}

//wrapSecretBySWK wraps a key using the RFC 3394 AES Key Wrap Algorithm.
func wrapSecretBySWK(wrapkey, keyBytes []byte) ([]byte, error) {
	defaultLog.Trace("controllers/app_verifier_controller:wrapSecretBySWK() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:wrapSecretBySWK() Leaving")

	if len(keyBytes)%8 != 0 {
		return nil, errors.New("controllers/app_verifier_controller:wrapSecretBySWK() Data to be wrapped not correct.")
	}

	cipher, err := aes.NewCipher(wrapkey)
	if err != nil {
		return nil, err
	}

	nblocks := len(keyBytes) / 8

	// 1) Initialize variables.
	var block [aes.BlockSize]byte
	// - Set A = IV, an initial value (see 2.2.3)
	for i := 0; i < 8; i++ {
		block[i] = 0xA6
	}

	// - For i = 1 to n
	// -   Set R[i] = P[i]
	intermediate := make([]byte, len(keyBytes))
	copy(intermediate, keyBytes)

	// 2) Calculate intermediate values.
	for i := 0; i < 6; i++ {
		for j := 0; j < nblocks; j++ {
			// - B = AES(K, A | R[i])
			copy(block[8:], intermediate[j*8:j*8+8])
			cipher.Encrypt(block[:], block[:])

			// - A = MSB(64, B) ^ t where t = (n*j)+1
			t := uint64(i*nblocks + j + 1)
			blockValue := binary.BigEndian.Uint64(block[:8]) ^ t
			binary.BigEndian.PutUint64(block[:8], blockValue)

			// - R[i] = LSB(64, B)
			copy(intermediate[j*8:j*8+8], block[8:])
		}
	}

	// 3) Output results.
	// - Set C[0] = A
	// - For i = 1 to n
	// -   C[i] = R[i]
	return append(block[:8], intermediate...), nil
}

func generateSecret(length int) ([]byte, error) {
	defaultLog.Trace("controllers/app_verifier_controller:generateSecret() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:generateSecret() Leaving")

	return crypt.GetRandomBytes(length / 8)
}

func wrapSWKByPublicKey(swk []byte, key []byte) ([]byte, error) {
	defaultLog.Trace("controllers/app_verifier_controller:wrapSWKByPublicKey() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:wrapSWKByPublicKey() Leaving")

	pemBlock, _ := pem.Decode(key)
	rsaPubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/app_verifier_controller:wrapSWKByPublicKey() %s : Public key decode failed", commLogMsg.InvalidInputBadParam)
		return nil, errors.Wrap(err, "Failed to decode public key")
	}

	rsaKey, ok := (rsaPubKey).(*rsa.PublicKey)
	if !ok {
		return nil, errors.Wrap(err, "controllers/app_verifier_controller:wrapSWKByPublicKey() Invalid PEM passed in from user, should be RSA.")
	}

	cipherText, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaKey, swk, nil)
	if err != nil {
		return nil, errors.Wrap(err, "controllers/app_verifier_controller:wrapSWKByPublicKey() Failed to create cipher key")
	}
	return cipherText, nil
}

func generateSWK() ([]byte, error) {
	defaultLog.Trace("controllers/app_verifier_controller:generateSWK() Entering")
	defer defaultLog.Trace("session/app_verifier_controller:generateSWK() Leaving")

	//create an AES Key here of 256 bytes
	keyBytes := make([]byte, 32)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "session/session_management:SessionCreateSwk() Failed to read the key bytes")
	}

	return keyBytes, nil
}

// verifySgxQuote verifies the quote
func (ca AppVerifierController) verifySgxQuote(quote []byte) error {
	defaultLog.Trace("controllers/app_verifier_controller:verifyQuote() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:verifyQuote() Leaving")

	var err error

	// convert byte array to string
	qData := base64.StdEncoding.EncodeToString(quote)

	defaultLog.Printf("Standalone mode is set to %s", strconv.FormatBool(ca.Config.StandAloneMode))

	// based on the operation mode - standalone or non-standalone mode
	if !ca.Config.StandAloneMode {
		// ExternalVerifier when implemented would forward the call to SQVS
		err = errors.New("Non-standalone mode is not supported in this release")
	} else {
		// call is handled by stub
		defaultLog.Printf("Calling out to StandaloneVerifier")
		err = ca.SaVerifier.VerifyQuote(qData)
	}

	if err != nil {
		return errors.Wrap(err, "controllers/app_verifier_controller:verifyQuote() Error in quote verification")
	}

	defaultLog.Printf("Post extended quote verification - "+
		"checking against quote policy stored in %s", ca.SgxQuotePolicyPath)

	// load quote policy from path
	qpRaw, err := ioutil.ReadFile(ca.SgxQuotePolicyPath)
	if err != nil {
		return errors.Wrap(err, "controllers/app_verifier_controller:verifyQuote() Error in reading quote policy file")
	}

	// split by newline
	lines := strings.Split(string(qpRaw), constants.EndLine)
	var mreValue, mrSignerValue, cpusvnValue string
	for _, line := range lines {
		// split by :
		lv := strings.Split(strings.TrimSpace(line), constants.PolicyFileDelim)
		if len(lv) != 2 {
			continue
		}
		// switch by field name
		switch lv[0] {
		case constants.MREnclaveField:
			mreValue = lv[1]
		case constants.MRSignerField:
			mrSignerValue = lv[1]
		case constants.CpuSvnField:
			cpusvnValue = lv[1]
		}
	}

	defaultLog.Printf("Quote policy has values MREnclaveField = %s | MRSignerField = %s | CpuSvnField = %s",
		mreValue, mrSignerValue, cpusvnValue)

	// for standalone mode, we extract the fields from the quote and compare
	// against a subset of the fields in the report
	parsedBlob := parser.ParseSkcQuoteBlob(qData)
	if parsedBlob == nil {
		return errors.New("controllers/app_verifier_controller:verifyQuote() Error parsing quote")
	}

	// compare against hardcoded SGX quote policy
	parsedQBlob := parser.ParseEcdsaQuoteBlob(parsedBlob.GetQuoteBlob())
	if parsedQBlob != nil {
		return errors.Wrap(err, "controllers/app_verifier_controller:verifyQuote() Error parsing quote")
	}

	// verify against the quote policy
	if fmt.Sprintf("%02x", parsedQBlob.Header.ReportBody.MrEnclave) != mreValue {
		err = errors.Errorf("controllers/app_verifier_controller:verifyQuote() Quote policy mismatch in %s", constants.MREnclaveField)
	}
	if fmt.Sprintf("%02x", parsedQBlob.Header.ReportBody.CpuSvn) != cpusvnValue {
		err = errors.Errorf("controllers/app_verifier_controller:verifyQuote() Quote policy mismatch in %s", constants.MREnclaveField)
	}
	if fmt.Sprintf("%02x", parsedQBlob.Header.ReportBody.MrSigner) != mrSignerValue {
		err = errors.Errorf("controllers/app_verifier_controller:verifyQuote() Quote policy mismatch in %s", constants.MREnclaveField)
	}

	if err != nil {
		defaultLog.Printf("Actual quote has values MREnclaveField = %s | MRSignerField = %s | CpuSvnField = %s",
			mreValue, mrSignerValue, cpusvnValue)
	}

	return err
}