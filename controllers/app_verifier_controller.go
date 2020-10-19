/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"net/http"
)

type AppVerifierController struct {
}

type AppVerifier struct {
	Status bool
}

func (ca AppVerifierController) Verify(w http.ResponseWriter, r *http.Request) {
	defaultLog.Trace("controllers/app_verifier_controller:Create() Entering")
	defer defaultLog.Trace("controllers/app_verifier_controller:Create() Leaving")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AppVerifier{Status: true})
}
