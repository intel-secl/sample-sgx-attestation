/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"

	"github.com/intel-secl/sample-sgx-attestation/v3/version"
)

const helpStr = `Usage:
	sgx-app-verifier <command> [arguments]
	
Available Commands:
	help|-h|--help         Show this help message
	version|-v|--version   Show the version of current sgx-app-verifier build
	setup <task>           Run setup task
	start                  Start sgx-app-verifier
	status                 Show the status of sgx-app-verifier
	stop                   Stop sgx-app-verifier
	uninstall [--purge]    Uninstall sgx-app-verifier	

Usage of sgx-app-verifier setup:
	sgx-app-verifier setup <task> [--help] [--force] [-f <answer-file>]
		--help                      show help message for setup task
		--force                     existing configuration will be overwritten if this flag is set

Available Tasks for setup:
	all                             Runs all setup tasks
	server                          Setup http server on given port
	download_ca_cert                Download CMS root CA certificate
	download_cert tls               Download CA certificate from CMS for tls
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
