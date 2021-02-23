/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/base64"
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tcpmsglib"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/constants"
	"github.com/pkg/errors"
	"io/ioutil"
	log "github.com/sirupsen/logrus"
	"strings"
)

type resourceError struct {
	StatusCode int
	Message    string
}

type QuoteVerifyAttributes struct {
	Message                        string `json:"Message"`
	ReportData                     string `json:"reportData"`
	UserDataMatch                  string `json:"userDataMatch"`
	EnclaveIssuer                  string `json:"EnclaveIssuer"`
	EnclaveIssuerProductID         string `json:"EnclaveIssuerProdID"`
	EnclaveIssuerExtendedProductID string `json:"EnclaveIssuerExtProdID"`
	EnclaveMeasurement             string `json:"EnclaveMeasurement"`
	ConfigSvn                      string `json:"ConfigSvn"`
	IsvSvn                         string `json:"IsvSvn"`
	ConfigID                       string `json:"ConfigId"`
	TCBLevel                       string `json:"TcbLevel"`
}

func (e resourceError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type AppVerifierController struct {
	TenantAppSocketAddr string
	Config              *config.Configuration
	ExtVerifier         ExternalVerifier
	SgxQuotePolicyPath  string
}

func (ca AppVerifierController) VerifyTenantAndShareSecret() bool {
	log.Trace("controllers/app_verifier_controller:VerifyTenantAndShareSecret() Entering")
	defer log.Trace("controllers/app_verifier_controller:VerifyTenantAndShareSecret() Leaving")

	//Following are dummy credentials which are not going to be validated in tenant app
	params := map[uint8][]byte{
		constants.ParamTypeUsername: []byte(constants.TenantUsername), //username
		constants.ParamTypePassword: []byte(constants.TenantPassword), //password
	}

	connectRequest := tcpmsglib.MarshalRequest(constants.ReqTypeConnect, params)

	// send the connect request to tenant app
	log.Info("Sending request to connect to Tenant App and for SGX quote...")
	connectResponseBytes, err := tcpmsglib.SendMessageAndGetResponse(ca.TenantAppSocketAddr, connectRequest)
	if err != nil {
		log.WithError(err).Errorf("Error connecting to Tenant app")
		return false
	}

	// parse connect request response from tenant app
	connectResponse, err := tcpmsglib.UnmarshalResponse(connectResponseBytes)
	if err != nil {
		log.WithError(err).Errorf("Error while unmarshalling response for connect from Tenant app")
		return false
	}
	if connectResponse != nil && connectResponse.RespCode == constants.ResponseCodeSuccess {
		log.Info("Connected to tenant app successfully.")

		var enclavePublicKey []byte
		var sgxQuote []byte
		for _, v := range connectResponse.Elements {
			if v.Type == constants.ResponseElementTypeSGXQuote {
				sgxQuote = v.Payload
			} else if v.Type == constants.ResponseElementTypeEnclavePubKey {
				enclavePublicKey = v.Payload
			}
		}

		log.Info("Verifying SGX quote...")
		err := ca.verifySgxQuote(sgxQuote, enclavePublicKey)
		if err != nil {
			log.WithError(err).Errorf("Error while verifying SGX quote")
			return false
		}
		log.Info("Verified SGX quote successfully.")

	} else {
		log.WithError(err).Errorf("Failed to connect to Tenant App.")
	}
	return false
}


// verifySgxQuote verifies the quote
func (ca AppVerifierController) verifySgxQuote(quote []byte, publicKey []byte) error {
	log.Trace("controllers/app_verifier_controller:verifySgxQuote() Entering")
	defer log.Trace("controllers/app_verifier_controller:verifySgxQuote() Leaving")

	var err error

	// Convert byte array to string.
	qData := base64.StdEncoding.EncodeToString(quote)
	key := base64.StdEncoding.EncodeToString(publicKey)

	var responseAttributes QuoteVerifyAttributes
	responseAttributes, err = ca.ExtVerifier.VerifyQuote(qData, key)

	if err != nil {
		return errors.Wrap(err, "controllers/app_verifier_controller:verifySgxQuote() Error in quote verification")
	}

	log.Printf("Post extended quote verification - "+
		"checking against quote policy stored in %s", ca.SgxQuotePolicyPath)

	// Load quote policy from path
	qpRaw, err := ioutil.ReadFile(ca.SgxQuotePolicyPath)
	if err != nil {
		return errors.Wrap(err, "controllers/app_verifier_controller:verifySgxQuote() Error in reading quote policy file")
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

	log.Info("Quote policy has values MREnclaveField = %s | MRSignerField = %s | CpuSvnField = %s",
		mreValue, mrSignerValue, cpusvnValue)


	if responseAttributes.EnclaveIssuer != mrSignerValue {
		err = errors.Errorf("controllers/app_verifier_controller:verifySgxQuote() Quote policy mismatch in %s", constants.MRSignerField)
		return err
	}

	if responseAttributes.ConfigSvn != cpusvnValue {
		err = errors.Errorf("controllers/app_verifier_controller:verifySgxQuote() Quote policy mismatch in %s", constants.CpuSvnField)
		return err
	}

	if responseAttributes.EnclaveMeasurement != mreValue {
		err = errors.Errorf("controllers/app_verifier_controller:verifySgxQuote() Quote policy mismatch in %s", constants.MREnclaveField)
		return err
	}

	if responseAttributes.UserDataMatch != "true" {
		err = errors.Errorf("controllers/app_verifier_controller:verifySgxQuote() The hash value dont match")
		return err
	}
	return err
}

func reverse(s []interface{}) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
