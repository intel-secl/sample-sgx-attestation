/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantapp"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/controllers"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"os"
	"strconv"
	"strings"
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

	tenantApp := tenantapp.TenantServiceApp{
		LogWriter: os.Stdout,
		Config:    c,
	}
	// dispatch Tenant App service
	go tenantApp.StartServer()
	/*	if err != nil {
		defaultLog.WithError(err).Errorf("app:startServer() Error starting TenantApp")
		return err
	}*/

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
	verifyController.VerifyTenantAndShareSecret()

	secLog.Info(commLogMsg.ServiceStop)
	return nil
}
