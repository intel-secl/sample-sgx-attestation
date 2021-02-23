/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/constants"
	"github.com/spf13/viper"
)

// this func sets the default values for viper keys
func init() {
	viper.SetDefault("tenantservice-host", constants.DefaultTenantAppListenHost)
	viper.SetDefault("tenantservice-port", constants.DefaultAppListenerPort)

	// set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogEntryMaxlength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", "info")
}

func defaultConfig() *config.Configuration {
	// support old service env
	return &config.Configuration{
		TenantServiceHost: viper.GetString("tenantservice-host"),
		TenantServicePort: viper.GetInt("tenantservice-port"),

		Log: config.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
			Level:        viper.GetString("log-level"),
		},
	}
}
