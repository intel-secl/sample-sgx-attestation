/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/constants"
	"github.com/spf13/viper"
)

// this func sets the default values for viper keys
func init() {
	// set default values for stand alone mode
	viper.SetDefault("standalone-mode", constants.DefaultStandAloneMode)
	viper.SetDefault("tenantservice-host", constants.DefaultTenantAppListenHost)
	viper.SetDefault("tenantservice-port", constants.DefaultAppListenerPort)

	// set default values for tls
	viper.SetDefault("tls-cert-file", constants.DefaultTLSCertFile)
	viper.SetDefault("tls-key-file", constants.DefaultTLSKeyFile)
	viper.SetDefault("tls-common-name", constants.DefaultAppTlsCn)
	viper.SetDefault("tls-san-list", constants.DefaultAppTlsSan)

	// set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogEntryMaxlength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", "info")

	// set default values for server
	viper.SetDefault("server-port", constants.DefaultAppListenerPort)
	viper.SetDefault("server-read-timeout", constants.DefaultReadTimeout)
	viper.SetDefault("server-read-header-timeout", constants.DefaultReadHeaderTimeout)
	viper.SetDefault("server-write-timeout", constants.DefaultWriteTimeout)
	viper.SetDefault("server-idle-timeout", constants.DefaultIdleTimeout)
	viper.SetDefault("server-max-header-bytes", constants.DefaultMaxHeaderBytes)
}

func defaultConfig() *config.Configuration {
	// support old service env
	return &config.Configuration{
		StandAloneMode:    viper.GetBool("standalone-mode"),
		TenantServiceHost: viper.GetString("tenantservice-host"),
		TenantServicePort: viper.GetInt("tenantservice-port"),
		AASApiUrl:         viper.GetString("aas-base-url"),
		CMSBaseURL:        viper.GetString("cms-base-url"),
		CmsTlsCertDigest:  viper.GetString("cms-tls-cert-sha384"),
		SqvsUrl:           viper.GetString("sqvs-url"),
		Service: config.ServiceConfig{
			Username: viper.GetString("service-username"),
			Password: viper.GetString("service-password"),
		},
		Server: config.ServerConfig{
			ReadTimeout:       viper.GetDuration("server-read-timeout"),
			ReadHeaderTimeout: viper.GetDuration("server-read-header-timeout"),
			WriteTimeout:      viper.GetDuration("server-write-timeout"),
			IdleTimeout:       viper.GetDuration("server-idle-timeout"),
			MaxHeaderBytes:    viper.GetInt("server-max-header-bytes"),
		},
		TLS: config.TLSCertConfig{
			CertFile:   viper.GetString("tls-cert-file"),
			KeyFile:    viper.GetString("tls-key-file"),
			CommonName: viper.GetString("tls-common-name"),
			SANList:    viper.GetString("tls-san-list"),
		},
		Log: config.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
			Level:        viper.GetString("log-level"),
		},
	}
}
