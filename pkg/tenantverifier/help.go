/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"

	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/version"
)

const helpStr = `Usage:
	sgx-app-verifier <command> [arguments]
	
Available Commands:
	help|-h|--help         Show this help message
	version|-v|--version   Show the version of current sgx-app-verifier build
	start                  Start sgx-app-verifier
	uninstall              Uninstall sgx-app-verifier
`

func (a *App) printUsage() {
	fmt.Fprintln(a.consoleWriter(), helpStr)
}

func (a *App) printUsageWithError(err error) {
	fmt.Fprintln(a.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(a.errorWriter(), helpStr)
}

func (a *App) printVersion() {
	fmt.Fprintf(a.consoleWriter(), "SGX App Verifier Service %s-%s\nBuilt %s\n", version.Version, version.GitHash, version.BuildDate)
}
