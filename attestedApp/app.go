/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/constants"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var errInvalidCmd = errors.New("Invalid input after command")

type App struct {
	HomeDir        string
	ConfigDir      string

	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string

	Config *config.Configuration

	ConsoleWriter io.Writer
}

func (a *App) Run(args []string) error {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("Panic occurred: %+v", err)
		}
	}()
	var err error
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
			// err := tasks.ReadAnswerFileToEnv(ansFile)
			// if err != nil {
			// 	return errors.Wrap(err, "Failed to read answer file")
			// }
		}

		viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
		viper.AutomaticEnv()
		if a.configuration() == nil {
			a.Config = defaultConfig()
		}

		err = a.Config.Save(constants.DefaultConfigFilePath)
		if err != nil {
			fmt.Println("Error running setup: ", err)
			return errors.Wrap(err, "app:Run() Error running setup")
		}
		fmt.Println("Setup completed successfully")
	}
	return nil
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	//FIXME : Get the right config path
	viper.AddConfigPath("./")
	c, err := config.LoadConfiguration()
	if err == nil {
		a.Config = c
		return a.Config
	}
	return nil
}
