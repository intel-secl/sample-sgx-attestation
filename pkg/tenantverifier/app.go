/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"crypto/x509/pkix"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/tasks"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	commLogInt "intel/isecl/lib/common/v3/log/setup"
	"intel/isecl/lib/common/v3/setup"
)

var errInvalidCmd = errors.New("Invalid input after command")

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
	HTTPLogWriter io.Writer
}

func (a *App) Run(args []string) error {
	defer func() {
		if err := recover(); err != nil {
			defaultLog.Errorf("Panic occurred: %+v", err)
		}
	}()
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
	case "run":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.startServer()
	case "start":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.start()
	case "stop":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.stop()
	case "status":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.status()
	case "uninstall":
		// the only allowed flag is --purge
		purge := false
		if len(args) == 3 {
			if args[2] != "--purge" {
				return errors.New("Invalid flag: " + args[2])
			}
			purge = true
		} else if len(args) != 2 {
			return errInvalidCmd
		}
		return a.uninstall(purge)
	case "setup":
		if len(args) < 2 {
			return errors.New("Invalid usage of setup")
		}
		// look for cli flags
		var ansFile string
		for i, s := range args {
			if s == "-f" || s == "--file" {
				if i+1 < len(args) {
					ansFile = args[i+1]
					break
				} else {
					return errors.New("Invalid answer file name")
				}
			}
		}
		// dump answer file to env
		if ansFile != "" {
			err := tasks.ReadAnswerFileToEnv(ansFile)
			if err != nil {
				return errors.Wrap(err, "Failed to read answer file")
			}
		}

		viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
		viper.AutomaticEnv()
		if a.configuration() == nil {
			a.Config = defaultConfig()
			a.Config.Save(constants.DefaultConfigFilePath)
		}

		if args[2] != "download_ca_cert" &&
			args[2] != "download_cert" &&
			args[2] != "service" &&
			args[2] != "all" {
			a.printUsage()
			return errors.New("No such setup task")
		}

		task := strings.ToLower(args[2])
		setupRunner := &setup.Runner{
			Tasks: []setup.Task{
				&tasks.Service{
					SvcConfigPtr:        &a.Config.Service,
					AASApiUrlPtr:        &a.Config.AASApiUrl,
					CMSBaseURLPtr:       &a.Config.CMSBaseURL,
					CmsTlsCertDigestPtr: &a.Config.CmsTlsCertDigest,
					ServiceConfig: config.ServiceConfig{
						Username: viper.GetString("service-username"),
						Password: viper.GetString("service-password"),
					},
					AASApiUrl:        viper.GetString("aas-base-url"),
					CMSBaseURL:       viper.GetString("cms-base-url"),
					CmsTlsCertDigest: viper.GetString("cms-tls-cert-sha384"),
					ConsoleWriter:    os.Stdout,
				},
			},
			AskInput: false,
		}
		if !a.Config.StandAloneMode {
			setupRunner.Tasks = append(setupRunner.Tasks, &setup.Download_Ca_Cert{
				CaCertDirPath:        constants.CaCertsDir,
				ConsoleWriter:        a.consoleWriter(),
				CmsBaseURL:           viper.GetString("cms-base-url"),
				TrustedTlsCertDigest: viper.GetString("cms-tls-cert-sha384"),
			},
				&setup.Download_Cert{
					KeyFile:            a.Config.TLS.KeyFile,
					CertFile:           a.Config.TLS.CertFile,
					KeyAlgorithm:       constants.DefaultKeyAlgorithm,
					KeyAlgorithmLength: constants.DefaultKeyLength,
					CmsBaseURL:         a.Config.CMSBaseURL,
					Subject: pkix.Name{
						CommonName: a.Config.TLS.CommonName,
					},
					SanList:       a.Config.TLS.SANList,
					CertType:      "TLS",
					CaCertsDir:    constants.CaCertsDir,
					BearerToken:   "",
					ConsoleWriter: os.Stdout,
				})
		} else {
			setupRunner.Tasks = append(setupRunner.Tasks, &tasks.Tls{
				StandAloneMode: a.Config.StandAloneMode,
				CommonName:     a.Config.TLS.CommonName,
				Validity:       constants.DefaultSelfSignedCertValidityYears,
				ConsoleWriter:  a.consoleWriter(),
			})
		}
		var err error
		if task == "all" {
			err = setupRunner.RunTasks()
		} else {
			err = setupRunner.RunTasks(task)
		}
		if err != nil {
			fmt.Println("Error running setup: ", err)
			return errors.Wrap(err, "app:Run() Error running setup")
		}
	}
	return nil
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

func (a *App) httpLogWriter() io.Writer {
	if a.HTTPLogWriter != nil {
		return a.HTTPLogWriter
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
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start sgx-app-verifier"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "start", "sgx-app-verifier"}, os.Environ())
}

func (a *App) stop() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop sgx-app-verifier"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "stop", "sgx-app-verifier"}, os.Environ())
}

func (a *App) status() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status sgx-app-verifier"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "status", "sgx-app-verifier"}, os.Environ())
}
