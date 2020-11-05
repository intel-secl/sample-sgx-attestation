/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/version"
	"intel/isecl/lib/common/v3/log"
	"net/http"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type VersionController struct {
}

func (v VersionController) GetVersion(w http.ResponseWriter, r *http.Request) {
	defaultLog.Trace("controllers/version_controller:GetVersion() Entering")
	defer defaultLog.Trace("controllers/version_controller:GetVersion() Leaving")

	verStr := fmt.Sprintf("%s-%s", version.Version, version.GitHash)
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(verStr))
}
