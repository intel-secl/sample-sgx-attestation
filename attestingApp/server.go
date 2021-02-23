/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/controllers"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
)


func (a *App) startVerifier() error {
	log.Trace("app:startVerifier() Entering")
	defer log.Trace("app:startVerifier() Leaving")

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}

	log.Info("Starting Tenant App Verifier server")

	// start the quote verification
	verifyController := controllers.AppVerifierController{
		TenantAppSocketAddr: strings.Join([]string{constants.DefaultTenantAppListenHost, strconv.Itoa(constants.DefaultAppListenerPort)}, ":"),
		Config:              c,
		ExtVerifier:         controllers.ExternalVerifier{c, constants.CaCertsDir},
		SgxQuotePolicyPath:  constants.SgxQuotePolicyPath,
	}

	// Initiate veriery workflow
	verifyController.VerifyTenantAndShareSecret()

	return nil
}
