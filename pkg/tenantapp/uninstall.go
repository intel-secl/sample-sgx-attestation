/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tenantapp

import (
	"fmt"
	"os"

	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/constants"
	e "intel/isecl/lib/common/v3/exec"
)

func (a *TenantServiceApp) executablePath() string {
	if a.ExecutablePath != "" {
		return a.ExecutablePath
	}
	exc, err := os.Executable()
	if err != nil {
		// if we can't find self-executable path, we're probably in a state that is panic() worthy
		panic(err)
	}
	return exc
}

func (a *TenantServiceApp) homeDir() string {
	if a.HomeDir != "" {
		return a.HomeDir
	}
	return constants.HomeDir
}

func (a *TenantServiceApp) configDir() string {
	if a.ConfigDir != "" {
		return a.ConfigDir
	}
	return constants.ConfigDir
}

func (a *TenantServiceApp) logDir() string {
	if a.LogDir != "" {
		return a.LogDir
	}
	return constants.LogDir
}

func (a *TenantServiceApp) execLinkPath() string {
	if a.ExecLinkPath != "" {
		return a.ExecLinkPath
	}
	return constants.ExecLinkPath
}

func (a *TenantServiceApp) runDirPath() string {
	if a.RunDirPath != "" {
		return a.RunDirPath
	}
	return constants.RunDirPath
}

func (a *TenantServiceApp) uninstall(purge bool) error {
	fmt.Println("Uninstalling Service Service")
	// remove service
	_, _, err := e.RunCommandWithTimeout(constants.ServiceRemoveCmd, 5)
	if err != nil {
		fmt.Println("Could not disable Service Service")
		fmt.Println("Error : ", err)
	}

	fmt.Println("removing : ", a.executablePath())
	err = os.Remove(a.executablePath())
	if err != nil {
		defaultLog.WithError(err).Error("error removing executable")
	}
	fmt.Println("removing : ", a.runDirPath())
	err = os.Remove(a.runDirPath())
	if err != nil {
		defaultLog.WithError(err).Error("error removing ", a.runDirPath())
	}
	fmt.Println("removing : ", a.execLinkPath())
	err = os.Remove(a.execLinkPath())
	if err != nil {
		defaultLog.WithError(err).Error("error removing ", a.execLinkPath())
	}
	// if purge is set
	if purge {
		fmt.Println("removing : ", a.configDir())
		err = os.RemoveAll(a.configDir())
		if err != nil {
			defaultLog.WithError(err).Error("error removing config dir")
		}
	}
	fmt.Println("removing : ", a.logDir())
	err = os.RemoveAll(a.logDir())
	if err != nil {
		defaultLog.WithError(err).Error("error removing log dir")
	}
	fmt.Println("removing : ", a.homeDir())
	err = os.RemoveAll(a.homeDir())
	if err != nil {
		defaultLog.WithError(err).Error("error removing home dir")
	}
	fmt.Fprintln(a.consoleWriter(), "Tenant TenantServiceApp Service uninstalled")
	a.stop()
	return nil
}
