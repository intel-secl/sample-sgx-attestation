/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantapp/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantapp/constants"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	commLogInt "intel/isecl/lib/common/v3/log/setup"
)

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string

	Config *config.Configuration

	ConsoleWriter io.Writer
	ErrorWriter   io.Writer
	LogWriter     io.Writer
	SecLogWriter  io.Writer
}

func (a *App) Run(args []string) error {
	/*	defer func() {
		if err := recover(); err != nil {
			defaultLog.Errorf("Panic occurred: %+v", err)
		}
	}()*/
	if len(args) < 2 {
		err := errors.New("Invalid usage of " + constants.ServiceName)
		a.printUsageWithError(err)
		return err
	}

	cmd := args[1]
	switch cmd {
	default:
		err := errors.New("Invalid command: " + cmd)
		a.printUsageWithError(err)
		return err
	case "help", "-h", "--help":
		a.printUsage()
		return nil
	case "version", "--version", "-v":
		a.printVersion()
		return nil
	}
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) errorWriter() io.Writer {
	if a.ErrorWriter != nil {
		return a.ErrorWriter
	}
	return os.Stderr
}

func (a *App) secLogWriter() io.Writer {
	if a.SecLogWriter != nil {
		return a.SecLogWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	viper.AddConfigPath(a.configDir())
	c, err := config.LoadConfiguration()
	if err == nil {
		a.Config = c
		return a.Config
	}
	return nil
}

func (a *App) configureLogs(stdOut, logFile bool) error {
	var ioWriterDefault io.Writer
	ioWriterDefault = a.logWriter()
	if stdOut {
		if logFile {
			ioWriterDefault = io.MultiWriter(os.Stdout, a.logWriter())
		} else {
			ioWriterDefault = os.Stdout
		}
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.secLogWriter())

	logConfig := a.Config.Log
	lv, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		return errors.Wrap(err, "Failed to initiate loggers. Invalid log level: "+logConfig.Level)
	}
	f := commLog.LogFormatter{MaxLength: logConfig.MaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, lv, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, lv, &f, ioWriterSecurity, false)

	secLog.Info(commLogMsg.LogInit)
	defaultLog.Info(commLogMsg.LogInit)
	return nil
}

func (a *App) start() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start sgx-tenant-app-service"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "start", "sgx-tenant-app-service"}, os.Environ())
}

func (a *App) stop() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop sgx-tenant-app-service"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "stop", "sgx-tenant-app-service"}, os.Environ())
}

func (a *App) status() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status sgx-tenant-app-service"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "status", "sgx-tenant-app-service"}, os.Environ())
}
