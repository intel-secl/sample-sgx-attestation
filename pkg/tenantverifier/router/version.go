/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/controllers"
)

func SetVersionRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/version:SetVersionRoutes() Entering")
	defer defaultLog.Trace("router/version:SetVersionRoutes() Leaving")
	versionController := controllers.VersionController{}

	router.HandleFunc("/version", versionController.GetVersion).Methods("GET")
	return router
}
