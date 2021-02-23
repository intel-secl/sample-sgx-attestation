/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"os"
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/version"
)

const helpStr = `Usage:
	sgx-tenantapp-service <command> [arguments]
	
Available Commands:
	help|-h|--help              Show this help message
        version|-v|--version        Print version information
	setup [-f <answer-file>]    Initializes the app configuration. If answer file is not provided, defaults are loaded.
	run    		Run tenant app.

`

func (a *App) printUsage() {
	fmt.Fprintln(os.Stdout, helpStr)
}

func (a *App) printUsageWithError(err error) {
	fmt.Fprintln(os.Stderr, "Application returned with error:", err.Error())
	fmt.Fprintln(os.Stderr, helpStr)
}

func (a *App) printVersion() {
	fmt.Fprintf(os.Stdout, "%s %s-%s\nBuilt %s\n", constants.ServiceName, version.Version, version.GitHash, version.BuildDate)
}
