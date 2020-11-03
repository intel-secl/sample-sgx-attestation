/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controller

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/domain"
)

type SocketHandler struct {
	Port    string
	Address string
	Config  *config.Configuration
}

func (sh SocketHandler) HandleConnect(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
	var resp domain.TenantAppResponse

	return &resp, nil
}

func (sh SocketHandler) HandlePubkeyWrappedSWK(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
	var resp domain.TenantAppResponse

	return &resp, nil
}

func (sh SocketHandler) HandleSWKWrappedSecret(req domain.TenantAppRequest) (*domain.TenantAppResponse, error) {
	var resp domain.TenantAppResponse

	return &resp, nil
}
