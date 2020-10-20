/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/binary"
	"encoding/json"
	"github.com/intel-secl/sample-sgx-attestation/v3/constants"
	"github.com/spf13/cast"
	"log"
	"net/http"
)

type AppVerifierController struct {
	Address string
}

type AppVerifier struct {
	Status bool
}

func (ca AppVerifierController) Verify(w http.ResponseWriter, r *http.Request) {
	defaultLog.Trace("controllers/app_verifier_controller:Create() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:Create() Leaving")
	result := ca.VerifyTenantAndShareSecret()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AppVerifier{Status: result})
}


func (ca AppVerifierController) VerifyTenantAndShareSecret() bool {
	defaultLog.Trace("controllers/app_verifier_controller:VerifyTenantAndShareSecret() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:VerifyTenantAndShareSecret() Leaving")

	log.Printf("Forming request to connect to Tenant App")
	//Following are dummy credential which are not going to evaluate in tenant app
	params := map[uint8][]byte{
		constants.ParamTypeUsername: []byte(constants.ServiceUserName), //username
		constants.ParamTypePassword: []byte("password"), //password
	}
	connectRequest := marshalRequest(constants.ReqTypeConnect, params)
	tenantAppClient := NewSgxSocketClient(ca.Address)

	log.Printf("Sending request to connect to Tenant App and for SGX quote")
	connectResponseBytes, err := tenantAppClient.socketRequest(connectRequest)
	if err != nil {
		log.Printf("Error connecting to Tenant app")
		return false
	}
	connectResponse, err := unmarshalResponse(connectResponseBytes)
	if err != nil {
		log.Printf("Error while unmarshaling response for connect from Tenant app")
		return false
	}
	if connectResponse != nil && connectResponse.RespCode == constants.ResponseCodeSuccess {
		log.Printf("Connected to tenant app successfully")

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
		log.Printf("Verifying SGX quote")
		err := verifySgxQuote(sgxQuote)
		if err != nil {
			log.Printf("Error while verifying SGX quote")
			return false
		}
		log.Printf("Verified SGX quote successfully")

		log.Printf("Generating SWK")
		swk, err := generateSWK()
		if err != nil {
			log.Printf("Error while generating SWK")
			return false
		}
		log.Printf("Generated SWK successfully")

		log.Printf("Wrapping SWK by Tenant Enclave Public Key")
		pubkeyWrappedSWK, err := wrapSWKByPublicKey(swk, enclavePublicKey)
		if err != nil {
			log.Printf("Error while wrapping SWK by Tenant enclave ublic key")
			return false
		}
		log.Printf("Wrappped SWK by Tenant Enclave Public Key")

		log.Printf("Forming request to send Wrapped SWK to Tenant App")
		params = map[uint8][]byte{
			constants.ParamTypePubkeyWrappedSwk: pubkeyWrappedSWK, //PubkeyWrappedSWK
		}
		wrappedSWKRequest := marshalRequest(constants.ReqTypePubkeyWrappedSWK, params)

		log.Printf("Sending request to send Wrapped SWK to Tenant App")
		wrappedSWKResponseBytes, err := tenantAppClient.socketRequest(wrappedSWKRequest)
		if err != nil {
			log.Printf("Error while getting response for wrapped SWK from Tenant app")
			return false
		}
		wrappedSWKResponse, err := unmarshalResponse(wrappedSWKResponseBytes)
		if err != nil {
			log.Printf("Error while unmarshaling response for wrapped SWK from Tenant app")
			return false
		}
		if wrappedSWKResponse != nil && wrappedSWKResponse.RespCode == constants.ResponseCodeSuccess {
			log.Printf("Wrapped SWK sent to Tenant App successfully")
		} else {
			log.Printf("Failed to send Wrapped SWK sent to Tenant App")
			return false
		}

		log.Printf("Generating new secret")
		secret, err := generateSecret()
		if err != nil {
			log.Printf("Error while generating secret")
			return false
		}
		log.Printf("Generated new secret successfully")

		log.Printf("Wrapping secret by SWK")
		swkWrappedSecret, err := wrapSecretBySWK(secret, swk)
		if err != nil {
			log.Printf("Error while wrapping SWK by Tenant enclave ublic key")
			return false
		}
		log.Printf("Wrapped secret by SWK successfully")

		log.Printf("Forming request to send Wrapped Secret by SWK to Tenant App")
		params = map[uint8][]byte{
			constants.ParamTypeSwkWrappedSecret: swkWrappedSecret, //SwkWrappedSecret
		}
		log.Printf("Sending request to send Wrapped Secret SWK to Tenant App")
		SWKWrappedSecretRequest := marshalRequest(constants.ReqTypeSWKWrappedSecret, params)

		SWKWrappedSecretResponseBytes, err := tenantAppClient.socketRequest(SWKWrappedSecretRequest)
		if err != nil {
			log.Printf("Error while getting response for SWK wrapped secret from Tenant app")
			return false
		}
		SWKWrappedSecretResponse, err := unmarshalResponse(SWKWrappedSecretResponseBytes)
		if err != nil {
			log.Printf("Error while unmarshaling response for SWK wrapped secret from Tenant app")
			return false
		}
		if SWKWrappedSecretResponse != nil && SWKWrappedSecretResponse.RespCode == constants.ResponseCodeSuccess {
			log.Printf("Wrapped Secret by SWK sent to Tenant App successfully")
			return SWKWrappedSecretResponse.RespCode == constants.ResponseCodeSuccess
		} else {
			log.Printf("Failed to send Wrapped Secret by SWK sent to Tenant App")
			return false
		}
	} else {
		log.Printf("Failed to connect to Tenant App")
	}
	return false
}

func wrapSecretBySWK(secret []byte, swk []byte) ([]byte, error) {
	//TODO: Implement me
	return nil, nil
}

func generateSecret() ([]byte, error) {
	//TODO: Implement me
	return nil, nil
}

func wrapSWKByPublicKey(swk []byte, key []byte) ([]byte, error) {
	//TODO: Implement me
	return nil, nil
}

func generateSWK() ([]byte, error) {
	//TODO: Implement me
	return nil, nil
}

func verifySgxQuote(quote []byte) error {
	//TODO: Implement me
	return nil
}

func getLengthInBytes(length int) []byte {
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, cast.ToUint16(length))
	return lengthBytes
}