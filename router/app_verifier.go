/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/sample-sgx-attestation/v3/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/controllers"
	"strconv"
	"strings"
)

func SetAppVerifierRoutes(router *mux.Router, config *config.Configuration) *mux.Router {
	defaultLog.Trace("router/app_verifier:SetAppVerifierRoutes() Entering")
	defer defaultLog.Trace("router/app_verifier:SetAppVerifierRoutes() Leaving")

	caCertController := controllers.AppVerifierController{
		Address: strings.Join([]string{"127.0.0.1", strconv.Itoa(999)}, ":"),
		Config:  config,
		ExtVerifier: controllers.ExternalVerifier{
			Config:     config,
			CaCertsDir: constants.CaCertsDir,
		},
		SaVerifier: controllers.StandaloneVerifier{},
	}
	router.HandleFunc("/verify", caCertController.Verify).Methods("GET")
	return router
}
