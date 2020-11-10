/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/version"
)

const helpStr = `Usage:
	sgx-tenantapp-service <command> [arguments]
	
Available Commands:
	help|-h|--help         Show this help message
	version|-v|--version   Show the version of current sgx-tenantapp-service build
	setup <task>           Run setup task
	start                  Start sgx-tenantapp-service
	status                 Show the status of sgx-tenantapp-service
	stop                   Stop sgx-tenantapp-service
	uninstall [--purge]    Uninstall sgx-tenantapp-service	

Usage of sgx-tenantapp-service setup:
	sgx-tenantapp-service setup <task> [--help] [--force] [-f <answer-file>]
		--help                      show help message for setup task
		--force                     existing configuration will be overwritten if this flag is set

Available Tasks for setup:
	all                             Runs all setup tasks`

func (a *App) printUsage() {
	fmt.Fprintln(a.consoleWriter(), helpStr)
}

func (a *App) printUsageWithError(err error) {
	fmt.Fprintln(a.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(a.errorWriter(), helpStr)
}

func (a *App) printVersion() {
	fmt.Fprintf(a.consoleWriter(), "SGX Tenant App Service %s-%s\nBuilt %s\n", version.Version, version.GitHash, version.BuildDate)
}
