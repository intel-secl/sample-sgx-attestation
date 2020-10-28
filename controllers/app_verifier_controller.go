/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/util"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/intel-secl/sample-sgx-attestation/v3/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cast"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/sqvs/v3/resource/parser"
	"net/http"
)

type AppVerifierController struct {
	Address string
	Config  *config.Configuration
}

type AppVerifier struct {
	Status bool
}

func (ca AppVerifierController) Verify(w http.ResponseWriter, r *http.Request) {
	defaultLog.Trace("controllers/app_verifier_controller:Create() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:Create() Leaving")
	result := ca.VerifyTenantAndShareSecret()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AppVerifier{Status: result})
}

func (ca AppVerifierController) VerifyTenantAndShareSecret() bool {
	defaultLog.Trace("controllers/app_verifier_controller:VerifyTenantAndShareSecret() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:VerifyTenantAndShareSecret() Leaving")

	defaultLog.Printf("Forming request to connect to Tenant App")
	//Following are dummy credential which are not going to evaluate in tenant app
	params := map[uint8][]byte{
		constants.ParamTypeUsername: []byte(constants.ServiceUserName), //username
		constants.ParamTypePassword: []byte("password"),                //password
	}
	connectRequest := marshalRequest(constants.ReqTypeConnect, params)
	tenantAppClient := NewSgxSocketClient(ca.Address)

	defaultLog.Printf("Sending request to connect to Tenant App and for SGX quote")
	connectResponseBytes, err := tenantAppClient.socketRequest(connectRequest)
	if err != nil {
		defaultLog.Printf("Error connecting to Tenant app")
		return false
	}
	connectResponse, err := unmarshalResponse(connectResponseBytes)
	if err != nil {
		defaultLog.Printf("Error while unmarshalling response for connect from Tenant app")
		return false
	}
	if connectResponse != nil && connectResponse.RespCode == constants.ResponseCodeSuccess {
		defaultLog.Printf("Connected to tenant app successfully")

		var enclavePublicKey []byte
		var sgxQuote []byte
		for _, v := range connectResponse.Elements {
			if v.Type == constants.ResponseElementTypeEnclavePubKey {
				enclavePublicKey = v.Payload
			}
			if v.Type == constants.ResponseElementTypeSGXQuote {
				sgxQuote = v.Payload
			}
		}
		defaultLog.Printf("Verifying SGX quote")
		err := ca.verifySgxQuote(sgxQuote)
		if err != nil {
			defaultLog.Printf("Error while verifying SGX quote")
			return false
		}
		defaultLog.Printf("Verified SGX quote successfully")

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
			defaultLog.Printf("Error while wrapping SWK by Tenant enclave ublic key")
			return false
		}
		defaultLog.Printf("Wrappped SWK by Tenant Enclave Public Key")

		defaultLog.Printf("Forming request to send Wrapped SWK to Tenant App")
		params = map[uint8][]byte{
			constants.ParamTypePubkeyWrappedSwk: pubkeyWrappedSWK, //PubkeyWrappedSWK
		}
		wrappedSWKRequest := marshalRequest(constants.ReqTypePubkeyWrappedSWK, params)

		defaultLog.Printf("Sending request to send Wrapped SWK to Tenant App")
		wrappedSWKResponseBytes, err := tenantAppClient.socketRequest(wrappedSWKRequest)
		if err != nil {
			defaultLog.Printf("Error while getting response for wrapped SWK from Tenant app")
			return false
		}
		wrappedSWKResponse, err := unmarshalResponse(wrappedSWKResponseBytes)
		if err != nil {
			defaultLog.Printf("Error while unmarshalling response for wrapped SWK from Tenant app")
			return false
		}
		if wrappedSWKResponse != nil && wrappedSWKResponse.RespCode == constants.ResponseCodeSuccess {
			defaultLog.Printf("Wrapped SWK sent to Tenant App successfully")
		} else {
			defaultLog.Printf("Failed to send Wrapped SWK sent to Tenant App")
			return false
		}

		defaultLog.Printf("Generating new secret")
		secret, err := generateSecret(constants.DefaultSecretLength)
		if err != nil {
			defaultLog.Printf("Error while generating secret")
			return false
		}
		defaultLog.Printf("Generated new secret successfully")

		defaultLog.Printf("Wrapping secret by SWK")
		swkWrappedSecret, err := wrapSecretBySWK(secret, swk)
		if err != nil {
			defaultLog.Printf("Error while wrapping SWK by Tenant enclave ublic key")
			return false
		}
		defaultLog.Printf("Wrapped secret by SWK successfully")

		defaultLog.Printf("Forming request to send Wrapped Secret by SWK to Tenant App")
		params = map[uint8][]byte{
			constants.ParamTypeSwkWrappedSecret: swkWrappedSecret, //SwkWrappedSecret
		}
		defaultLog.Printf("Sending request to send Wrapped Secret SWK to Tenant App")
		SWKWrappedSecretRequest := marshalRequest(constants.ReqTypeSWKWrappedSecret, params)

		SWKWrappedSecretResponseBytes, err := tenantAppClient.socketRequest(SWKWrappedSecretRequest)
		if err != nil {
			defaultLog.Printf("Error while getting response for SWK wrapped secret from Tenant app")
			return false
		}
		SWKWrappedSecretResponse, err := unmarshalResponse(SWKWrappedSecretResponseBytes)
		if err != nil {
			defaultLog.Printf("Error while unmarshalling response for SWK wrapped secret from Tenant app")
			return false
		}
		if SWKWrappedSecretResponse != nil && SWKWrappedSecretResponse.RespCode == constants.ResponseCodeSuccess {
			defaultLog.Printf("Wrapped Secret by SWK sent to Tenant App successfully")
			return SWKWrappedSecretResponse.RespCode == constants.ResponseCodeSuccess
		} else {
			defaultLog.Printf("Failed to send Wrapped Secret by SWK sent to Tenant App")
			return false
		}
	} else {
		defaultLog.Printf("Failed to connect to Tenant App")
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

	rsaPubKey, err := crypt.GetPublicKeyFromPem(key)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/app_verifier_controller:wrapSWKByPublicKey() %s : Public key decode failed", commLogMsg.InvalidInputBadParam)
		return nil, errors.Wrap(err, "Failed to decode public key")
	}

	rsaKey, ok := rsaPubKey.(*rsa.PublicKey)
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

func (ca AppVerifierController) verifySgxQuote(quote []byte) error {
	defaultLog.Trace("controllers/app_verifier_controller:verifyQuote() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:verifyQuote() Leaving")

	cfg := ca.Config

	// based on the operation mode - standalone or non-standalone mode
	// either reach out to SQVS
	if !ca.Config.StandAloneMode {
		url := cfg.SqvsUrl + constants.VerifyQuote
		quoteData := string(quote)

		caCerts, err := crypt.GetCertsFromDir(constants.CaCertsDir)
		if err != nil {
			return errors.Wrap(err, "controllers/app_verifier_controller:verifyQuote() Error in retrieving CA certificates")
		}

		buffer := new(bytes.Buffer)
		err = json.NewEncoder(buffer).Encode(quoteData)
		if err != nil {
			return errors.Wrap(err, "controllers/app_verifier_controller:verifyQuote() Error in encoding the quote")
		}

		req, err := http.NewRequest("POST", url, buffer)
		if err != nil {
			return errors.Wrap(err, "controllers/app_verifier_controller:verifyQuote() Error in Creating request")
		}
		req.Header.Add("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		response, err := util.SendRequest(req, cfg.AASApiUrl, cfg.Service.Username, cfg.Service.Password, caCerts)
		var responseAttributes *kbs.QuoteVerifyAttributes

		err = json.Unmarshal(response, &responseAttributes)
		if err != nil {
			return errors.Wrap(err, "controllers/app_verifier_controller:verifyQuote() Error in unmarshalling response")
		}
		defaultLog.Info("controllers/app_verifier_controller:verifyQuote() Successfully verified quote in non-standalone mode")
	} else {
		// for standalone mode, pass quote to the SQVS stub
		parsedBlob := parser.ParseSkcQuoteBlob(string(quote))
		if parsedBlob == nil {
			return errors.New("controllers/app_verifier_controller:verifyQuote() Error parsing quote")
		}
	}
	return nil
}

func getLengthInBytes(length int) []byte {
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, cast.ToUint16(length))
	return lengthBytes
}
