/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"os"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/constants"

	"github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/version"
)

const helpStr = `Usage:
	sgx-app-verifier <command> [arguments]
	
Available Commands:
	help|-h|--help              Show this help message
	version|-v|--version        Show the version of current sgx-app-verifier build
	run                         Run sgx-app-verifier workflow

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