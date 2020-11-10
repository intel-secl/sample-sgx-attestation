/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/controllers"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"strconv"
	"strings"
	"time"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (a *App) startServer() error {
	defaultLog.Trace("app:startServer() Entering")
	defer defaultLog.Trace("app:startServer() Leaving")

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}
	// initialize log
	if err := a.configureLogs(c.Log.EnableStdout, false); err != nil {
		return err
	}

	defaultLog.Info("Starting Tenant App Verifier server")

	// start the quote verification
	verifyController := controllers.AppVerifierController{
		TenantAppSocketAddr: strings.Join([]string{constants.DefaultTenantAppListenHost, strconv.Itoa(constants.DefaultAppListenerPort)}, ":"),
		Config:              c,
		ExtVerifier: controllers.ExternalVerifier{
			Config:     c,
			CaCertsDir: constants.CaCertsDir,
		},
		SaVerifier:         controllers.StandaloneVerifier{},
		SgxQuotePolicyPath: constants.SgxQuotePolicyPath,
	}
	// kick off the workflow
	for !verifyController.VerifyTenantAndShareSecret() {
		time.Sleep(time.Second * 1)
	}

	secLog.Info(commLogMsg.ServiceStop)
	return nil
}
