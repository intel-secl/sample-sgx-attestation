/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"time"
	"github.com/pkg/errors"
	"github.com/spf13/viper"

	log "github.com/sirupsen/logrus"
)

type Configuration struct {
	TenantServiceHost string        `yaml:"tenantservice-host" mapstructure:"tenantservice-host"`
	TenantServicePort int           `yaml:"tenantservice-port" mapstructure:"tenantservice-port"`
	SqvsUrl           string        `yaml:"sqvs-url" mapstructure:"sqvs-url"`
	Service           ServiceConfig `yaml:"service" mapstructure:"service"`
	Server            ServerConfig  `yaml:"server" mapstructure:"server"`
}

type ServerConfig struct {
	ReadTimeout       time.Duration `yaml:"read-timeout" mapstructure:"read-timeout"`
	ReadHeaderTimeout time.Duration `yaml:"read-header-timeout" mapstructure:"read-header-timeout"`
	WriteTimeout      time.Duration `yaml:"write-timeout" mapstructure:"write-timeout"`
	IdleTimeout       time.Duration `yaml:"idle-timeout" mapstructure:"idle-timeout"`
	MaxHeaderBytes    int           `yaml:"max-header-bytes" mapstructure:"max-header-bytes"`
}

type ServiceConfig struct {
	Username string `yaml:"verifier-username" mapstructure:"verifier-username"`
	Password string `yaml:"verifier-password" mapstructure:"verifier-password"`
}

// this function sets the configure file name and type
func init() {

}

// config is application specific
func LoadConfiguration() (*Configuration, error) {
	viper.AddConfigPath(".")
	viper.AddConfigPath("./")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	var ret Configuration
	// Find and read the config file
	if err := viper.ReadInConfig(); err != nil {
		log.Info ("Error : " , err)
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			return &ret, errors.Wrap(err, "Config file not found")
		}
		return &ret, errors.Wrap(err, "Failed to load config")
	}

	if err := viper.Unmarshal(&ret); err != nil {
		log.Info ("Error : " , err)
		return &ret, errors.Wrap(err, "Failed to unmarshal config")
	}
	return &ret, nil
}
