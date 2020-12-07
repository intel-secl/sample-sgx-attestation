/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"

	. "github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/constants"
)

func openLogFiles() (logFile *os.File, secLogFile *os.File, err error) {

	logFile, err = os.OpenFile(LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, err
	}
	if err = os.Chmod(LogFile, 0664); err != nil {
		return nil, nil, err
	}

	secLogFile, err = os.OpenFile(SecurityLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, err
	}
	if err = os.Chmod(SecurityLogFile, 0664); err != nil {
		return nil, nil, err
	}

	serviceUser, err := user.Lookup(ServiceUserName)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not find user '%s'", ServiceUserName)
	}

	uid, err := strconv.Atoi(serviceUser.Uid)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not parse sgx-app-verifier user uid '%s'", serviceUser.Uid)
	}

	gid, err := strconv.Atoi(serviceUser.Gid)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not parse sgx-app-verifier user gid '%s'", serviceUser.Gid)
	}
	err = os.Chown(SecurityLogFile, uid, gid)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not change file ownership for file: '%s'", SecurityLogFile)
	}
	err = os.Chown(LogFile, uid, gid)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not change file ownership for file: '%s'", LogFile)
	}
	return
}

func main() {
	l, s, err := openLogFiles()
	var app *App
	if err != nil {
		app = &App{
			LogWriter: os.Stdout,
		}
	} else {
		defer l.Close()
		defer s.Close()
		app = &App{
			LogWriter:    l,
			SecLogWriter: s,
		}
	}

	err = app.Run(os.Args)
	if err != nil {
		fmt.Println("Tenant Verifier Application returned with error:", err.Error())
		os.Exit(1)
	}
}