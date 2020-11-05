/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controller

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/domain"
	"github.com/pkg/errors"
	"io/ioutil"
)

type SocketHandler struct {
	SgxQuotePath string
}

func (sh SocketHandler) HandleConnect(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
	var resp domain.TenantAppResponse
	var err error

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

	if username != constants.TenantUsername || password != constants.TenantPassword {
		resp.RespCode = constants.ResponseCodeFailure
		err = errors.New("controller/socket_handler:HandleConnect Invalid credentials")
	}

	// return the preset quote from file
	qBytes, err := ioutil.ReadFile(sh.SgxQuotePath)

	if err != nil {
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

	return &resp, err
}

func (sh SocketHandler) HandlePubkeyWrappedSWK(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
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
			if paramValue.Type == constants.ReqTypePubkeyWrappedSWK {
				pubKeyWrappedSwk = string(paramValue.Payload)
			}
		}

		// pass this to the tenant app
		passToTenantApp(pubKeyWrappedSwk)

		// construct the response
		respPayload := []byte("")
		resp.RespCode = constants.ResponseCodeSuccess
		resp.Elements = []domain.TenantAppMessageElement{
			{
				Type:    constants.ParamTypePubkeyWrappedSwk,
				Length:  uint16(len(respPayload)),
				Payload: respPayload,
			},
		}
		resp.ParamLength = uint16(len(resp.Elements))
	}

	return &resp, err

}

func (sh SocketHandler) HandleSWKWrappedSecret(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
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
			if paramValue.Type == constants.ParamTypePubkeyWrappedSwk {
				swkWrappedSecret = string(paramValue.Payload)
			}
		}

		// pass this to the tenant app
		passToTenantApp(swkWrappedSecret)

		// construct the response
		respPayload := []byte("")
		resp.RespCode = constants.ResponseCodeSuccess
		resp.Elements = []domain.TenantAppMessageElement{
			{
				Type:    constants.ParamTypePubkeyWrappedSwk,
				Length:  uint16(len(respPayload)),
				Payload: respPayload,
			},
		}
		resp.ParamLength = uint16(len(resp.Elements))
	}

	return &resp, err
}

func passToTenantApp(key string) error {
	// TODO: Need to forward the request to the tenant app - via the Go-C bridge
	return nil
}
