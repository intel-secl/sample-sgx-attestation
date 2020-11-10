/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/constants"
	"github.com/spf13/viper"
)

// this func sets the default values for viper keys
func init() {
	// set default values for stand alone mode
	viper.SetDefault("stand-alone-mode", constants.DefaultStandAloneMode)
	viper.SetDefault("tenant-service-host", constants.DefaultTenantAppListenHost)
	viper.SetDefault("tenant-service-port", constants.DefaultAppListenerPort)

	// set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogEntryMaxlength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", "info")
}

func defaultConfig() *config.Configuration {
	// support old service env
	return &config.Configuration{
		StandAloneMode:    viper.GetBool("stand-alone-mode"),
		TenantServiceHost: viper.GetString("tenant-service-host"),
		TenantServicePort: viper.GetInt("tenant-service-port"),

		Log: config.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
			Level:        viper.GetString("log-level"),
		},
	}
}
