/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controller

// #cgo CFLAGS: -I /opt/intel/sgxsdk/include
// #cgo LDFLAGS: -L /usr/lib64 -l app
// #cgo LDFLAGS: -L /usr/lib64 -l sgx_qe3_logic
// #cgo LDFLAGS: -L /usr/lib64 -l sgx_pce_logic
// #cgo LDFLAGS: -L /usr/lib64 -l sgx_dcap_ql
// #cgo LDFLAGS: -L /usr/lib64/ -l sgx_urts
// #include "App_Func.h"
import "C"

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantapp/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/domain"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v3/log"
	"unsafe"
)

var (
	defaultLog        = log.GetDefaultLogger()
	enclaveInitStatus C.int
	ePubKey           crypto.PublicKey
)

func init() {
	// initialize enclave
	enclaveInitStatus = C.init(C.bool(true))
}

type SocketHandler struct {
	Config *config.Configuration
}

func (sh SocketHandler) HandleConnect(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
	defaultLog.Trace("controller/socket_handler:HandleConnect Entering")
	defer defaultLog.Trace("controller/socket_handler:HandleConnect Leaving")
	var resp domain.TenantAppResponse
	var err error

	if enclaveInitStatus != 0 {
		return nil, errors.Errorf("controller/socket_handler:HandleConnect Error initializing enclave - error code %d", enclaveInitStatus)
	}

	resp.RequestType = req.RequestType

	// make sure it is a connect request
	if req.RequestType != constants.ReqTypeConnect {
		return nil, errors.New("controller/socket_handler:HandleConnect Invalid request type")
	}

	var username, password string
	// extract the user credentials
	for _, paramValue := range req.Elements {
		switch paramValue.Type {
		case constants.ParamTypeUsername:
			username = string(paramValue.Payload)
		case constants.ParamTypePassword:
			password = string(paramValue.Payload)
		}
	}

	defaultLog.Debugf("controller/socket_handler:HandleConnect Received credentials %s | %s", username, password)
	if username != constants.TenantUsername || password != constants.TenantPassword {
		resp.RespCode = constants.ResponseCodeFailure
		err = errors.New("controller/socket_handler:HandleConnect Invalid credentials")
	}

	defaultLog.Print("Getting quote from the Tenant App Enclave")

	var qSize C.int
	var qBytes []byte
	var qPtr *C.u_int8_t
	qPtr = C.get_SGX_Quote(&qSize)
	qBytes = C.GoBytes(unsafe.Pointer(qPtr), qSize)

	// since we are not getting the enclave public key in the response,
	// we must generate it
	_, ePubKey, err = crypt.GenerateKeyPair(constants.DefaultKeyAlgorithm, constants.DefaultKeyLength)
	if err != nil {
		return nil, errors.Wrap(err, "controller/socket_handler:HandleConnect Failed to fetch enclave key")
	}

	// marshal before transmission
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(ePubKey)
	if err != nil {
		return nil, errors.Wrap(err, "controller/socket_handler:HandleConnect Failed to marshal public key bytes")
	}

	// convert to PEM
	pemBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	enclaveKeyBytes := pem.EncodeToMemory(&pemBlock)

	defaultLog.Printf("Fetched quote is of length %d", len(qBytes))
	if qBytes == nil || enclaveKeyBytes == nil {
		resp.RespCode = constants.ResponseCodeFailure
		err = errors.New("controller/socket_handler:HandleConnect Error fetching Tenant App Quote")
	} else {
		resp.RespCode = constants.ResponseCodeSuccess
		resp.Elements = []domain.TenantAppMessageElement{
			{
				Type:    constants.ResponseElementTypeSGXQuote,
				Length:  uint16(len(qBytes)),
				Payload: qBytes,
			},
			{
				Type:    constants.ResponseElementTypeEnclavePubKey,
				Length:  uint16(len(enclaveKeyBytes)),
				Payload: enclaveKeyBytes,
			},
		}
		resp.ParamLength = uint16(len(resp.Elements))
	}

	return &resp, err
}

// HandlePubkeyWrappedSWK receives the SWK used for wrapping public key
func (sh SocketHandler) HandlePubkeyWrappedSWK(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
	defaultLog.Trace("controller/socket_handler:HandlePubkeyWrappedSWK Entering")
	defer defaultLog.Trace("controller/socket_handler:HandlePubkeyWrappedSWK Leaving")

	var resp domain.TenantAppResponse
	var err error

	resp.RequestType = req.RequestType

	// make sure it is a ReqTypePubkeyWrappedSWK request
	if req.RequestType != constants.ReqTypePubkeyWrappedSWK {
		resp.RespCode = constants.ResponseCodeFailure
		err = errors.New("controller/socket_handler:HandlePubkeyWrappedSWK Invalid request type")
	} else {

		var pubKeyWrappedSwk string
		// extract the params
		for _, paramValue := range req.Elements {
			if paramValue.Type == constants.ParamTypePubkeyWrappedSwk {
				pubKeyWrappedSwk = string(paramValue.Payload)
			}
		}

		defaultLog.Printf("Length of the wrapped SWK is %d", len(pubKeyWrappedSwk))
		// ideally we should be passing the wrapped key here
		C.unwrap_SWK()
		result := true

		// construct the response
		if result {
			resp.RespCode = constants.ResponseCodeSuccess
		} else {
			resp.RespCode = constants.ResponseCodeFailure
		}
	}

	return &resp, err

}

// HandleSWKWrappedSecret takes the wrapped secret from verifier app and unwraps it in the enclave
func (sh SocketHandler) HandleSWKWrappedSecret(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
	defaultLog.Trace("controller/socket_handler:HandleSWKWrappedSecret Entering")
	defer defaultLog.Trace("controller/socket_handler:HandleSWKWrappedSecret Leaving")

	var resp domain.TenantAppResponse
	var err error

	resp.RequestType = req.RequestType

	// make sure it is a ReqTypeSWKWrappedSecret request
	if req.RequestType != constants.ReqTypeSWKWrappedSecret {
		resp.RespCode = constants.ResponseCodeFailure
		err = errors.New("controller/socket_handler:HandleSWKWrappedSecret Invalid request type")
	} else {

		var swkWrappedSecret string
		// extract the params
		for _, paramValue := range req.Elements {
			if paramValue.Type == constants.ParamTypeSwkWrappedSecret {
				swkWrappedSecret = string(paramValue.Payload)
			}
		}

		defaultLog.Printf("Length of the wrapped secret is %d", len(swkWrappedSecret))

		// ideally we should be passing the wrapped secret here
		C.unwrap_Secret()
		result := true

		// construct the response
		if result {
			resp.RespCode = constants.ResponseCodeSuccess
		} else {
			resp.RespCode = constants.ResponseCodeFailure
		}
	}

	return &resp, err
}
