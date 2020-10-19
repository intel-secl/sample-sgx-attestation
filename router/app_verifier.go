/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/sample-sgx-attestation/v3/controllers"
)

func SetAppVerifierRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/app_verifier:SetAppVerifierRoutes() Entering")
	defer defaultLog.Trace("router/app_verifier:SetAppVerifierRoutes() Leaving")

	caCertController := controllers.AppVerifierController{}
	router.HandleFunc("/verify", caCertController.Verify).Methods("GET")
	return router
}
