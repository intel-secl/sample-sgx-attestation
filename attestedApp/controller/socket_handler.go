/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controller

// #cgo CFLAGS: -I /opt/intel/sgxsdk/include
// #cgo LDFLAGS: -L /usr/lib64 -l untrusted
// #include "../lib/Untrusted/Untrusted.h"
import "C"

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/domain"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/constants"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"unsafe"
)


// SocketHandler holds
type SocketHandler struct {
	Config *config.Configuration
}

// EnclaveInit initializes the tenant app enclave
func (sh *SocketHandler) EnclaveInit() error {
	log.Trace("controller/socket_handler:EnclaveInit Entering")
	defer log.Trace("controller/socket_handler:EnclaveInit Leaving")

	var enclaveInitStatus C.int

	// initialize enclave
	log.Info("Initializing enclave...")
	enclaveInitStatus = C.init()

	if enclaveInitStatus != 0 {
		return errors.Errorf("EnclaveInit Failed to initialize enclave. Error code: %d", enclaveInitStatus)
	}

	log.Info("Enclave initialized.")

	return nil
}

// EnclaveDestroy cleans up the tenant enclave on exit
func (sh *SocketHandler) EnclaveDestroy() error {
	log.Trace("controller/socket_handler:EnclaveDestroy Entering")
	defer log.Trace("controller/socket_handler:EnclaveDestroy Leaving")

	// destroy enclave
	enclaveDestroyStatus := C.destroy_Enclave()

	if enclaveDestroyStatus != 0 {
		return errors.Errorf("Failed to destroy enclave. Error code: %d", enclaveDestroyStatus)
	}

	log.Info("controller/socket_handler:EnclaveInit Destroyed enclave")

	return nil
}

// HandleConnect handles connect request from Verifier app
func (sh *SocketHandler) HandleConnect(req domain.VerifierAppRequest) (*domain.TenantAppResponse, error) {
	log.Trace("controller/socket_handler:HandleConnect Entering")
	defer log.Trace("controller/socket_handler:HandleConnect Leaving")

	var resp domain.TenantAppResponse
	var err error

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
		err = errors.New("Verifier Invalid credentials")
		log.WithError(err).Info("Verifier Authentication Failed")
	} else {
		log.Info("Authenticated verifier connection.")
		log.Info("Getting quote from the Tenant App Enclave...")

		var qBytes []byte
		var kBytes []byte
		// qSize holds the length of the quote byte array returned from enclave
		var qSize C.int
		var keySize C.int
		// qPtr holds the bytes array of the quote returned from enclave
		var qPtr *C.u_int8_t

		qPtr = C.get_SGX_Quote(&qSize, &keySize)
		qBytes = C.GoBytes(unsafe.Pointer(qPtr), qSize)
		kBytes = C.GoBytes(unsafe.Pointer(qPtr), qSize+keySize)

		log.Printf("Quote is of length %d bytes.", len(qBytes))
		log.Printf("Public key is of length %d bytes.", len(kBytes))

		if qBytes == nil || qSize == C.int(0) {
			resp.RespCode = constants.ResponseCodeFailure
			err = errors.New("Error fetching Tenant App Quote")
		} else if kBytes == nil || keySize == C.int(0) {
			resp.RespCode = constants.ResponseCodeFailure
			err = errors.New("Error fetching Tenant Public Key")
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
					Length:  uint16(keySize),
					Payload: kBytes[len(qBytes):],
				},
			}
			resp.ParamLength = uint16(len(resp.Elements))
		}
		log.Info("Responding with Tenant App Quote..")
	}

	return &resp, err
}
