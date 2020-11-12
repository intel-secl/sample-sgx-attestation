/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controller

// #cgo CFLAGS: -I /opt/intel/sgxsdk/include
// #cgo LDFLAGS: -L /usr/lib64 -l app
// #include "../../../tenantApp/App/App_Func.h"
import "C"

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/domain"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/constants"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"unsafe"
)

var (
	defaultLog        = log.GetDefaultLogger()
	secLog            = log.GetSecurityLogger()
	enclaveInitStatus C.int
)

func (sh *SocketHandler) EnclaveInit() error {
	defaultLog.Trace("controller/socket_handler:EnclaveInit Entering")
	defer defaultLog.Trace("controller/socket_handler:EnclaveInit Leaving")

	// initialize enclave
	enclaveInitStatus = C.init(C.bool(true))

	if enclaveInitStatus != 0 {
		return errors.Errorf("controller/socket_handler:EnclaveInit Failed to initialize enclave. Error code: %d", enclaveInitStatus)
	}

	defaultLog.Info("controller/socket_handler:EnclaveInit Initialized enclave")

	return nil
}

func (sh *SocketHandler) EnclaveDestroy() error {
	defaultLog.Trace("controller/socket_handler:EnclaveDestroy Entering")
	defer defaultLog.Trace("controller/socket_handler:EnclaveDestroy Leaving")

	// destroy enclave
	enclaveDestroyStatus := C.destroy_Enclave()

	if enclaveDestroyStatus != 0 {
		return errors.Errorf("controller/socket_handler:EnclaveInit Failed to destroy enclave. Error code: %d", enclaveDestroyStatus)
	}

	defaultLog.Info("controller/socket_handler:EnclaveInit Destroyed enclave")

	return nil
}

type SocketHandler struct {
	Config *config.Configuration
}

func (sh *SocketHandler) HandleConnect(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
	defaultLog.Trace("controller/socket_handler:HandleConnect Entering")
	defer defaultLog.Trace("controller/socket_handler:HandleConnect Leaving")

	var resp domain.TenantAppResponse
	var err error

	if enclaveInitStatus != 0 {
		return nil, errors.Errorf("controller/socket_handler:HandleConnect Error initializing enclave - error code %d", enclaveInitStatus)
	}

	resp.RequestType = req.RequestType

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

	if username != constants.TenantUsername || password != constants.TenantPassword {
		resp.RespCode = constants.ResponseCodeFailure
		err = errors.New("controller/socket_handler:HandleConnect Invalid credentials")
		secLog.WithError(err).Info("controller/socket_handler:HandleConnect " + commLogMsg.AuthenticationFailed)
	} else {
		secLog.Infof("controller/socket_handler:HandleConnect " + commLogMsg.AuthenticationSuccess)
		defaultLog.Print("Getting quote from the Tenant App Enclave")

		var qSize C.int
		var qBytes []byte
		var qPtr *C.u_int8_t
		qPtr = C.get_SGX_Quote(&qSize)
		qBytes = C.GoBytes(unsafe.Pointer(qPtr), qSize)

		defaultLog.Printf("Fetched quote is of length %d", len(qBytes))
		if qBytes == nil {
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
			}
			resp.ParamLength = uint16(len(resp.Elements))
		}
		secLog.Info("controller/socket_handler:HandleConnect Sending response" + commLogMsg.AuthorizedAccess)
	}

	return &resp, err
}

// HandlePubkeyWrappedSWK receives the SWK used for wrapping public key
func (sh *SocketHandler) HandlePubkeyWrappedSWK(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
	defaultLog.Trace("controller/socket_handler:HandlePubkeyWrappedSWK Entering")
	defer defaultLog.Trace("controller/socket_handler:HandlePubkeyWrappedSWK Leaving")

	var resp domain.TenantAppResponse
	var err error

	resp.RequestType = req.RequestType

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

	secLog.Info("controller/socket_handler:HandlePubkeyWrappedSWK Sending response" + commLogMsg.AuthorizedAccess)

	return &resp, err

}

// HandleSWKWrappedSecret takes the wrapped secret from verifier app and unwraps it in the enclave
func (sh *SocketHandler) HandleSWKWrappedSecret(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
	defaultLog.Trace("controller/socket_handler:HandleSWKWrappedSecret Entering")
	defer defaultLog.Trace("controller/socket_handler:HandleSWKWrappedSecret Leaving")

	var resp domain.TenantAppResponse
	var err error

	resp.RequestType = req.RequestType

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
		resp.ParamLength = 0
	} else {
		resp.RespCode = constants.ResponseCodeFailure
		resp.ParamLength = 0
	}

	secLog.Info("controller/socket_handler:HandleSWKWrappedSecret Sending response" + commLogMsg.AuthorizedAccess)

	return &resp, err
}
