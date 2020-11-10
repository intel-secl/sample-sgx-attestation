/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/constants"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"os"
)

type Configuration struct {
	StandAloneMode    bool      `yaml:"stand-alone-mode" mapstructure:"stand-alone-mode"`
	TenantServiceHost string    `yaml:"tenant-service-host" mapstructure:"tenant-service-host"`
	TenantServicePort int       `yaml:"tenant-service-port" mapstructure:"tenant-service-port"`
	Log               LogConfig `yaml:"log" mapstructure:"log"`
	TrustedRootCAPath string    `yaml:"trusted-root-ca-path" mapstructure:"trusted-root-ca-path"`
}

type LogConfig struct {
	MaxLength    int    `yaml:"max-length" mapstructure:"max-length"`
	EnableStdout bool   `yaml:"enable-stdout" mapstructure:"enable-stdout"`
	Level        string `yaml:"level" mapstructure:"level"`
}

// this function sets the configure file name and type
func init() {
	viper.SetConfigName(constants.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
}

// config is application specific
func LoadConfiguration() (*Configuration, error) {
	ret := Configuration{}
	// Find and read the config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			return &ret, errors.Wrap(err, "Config file not found")
		}
		return &ret, errors.Wrap(err, "Failed to load config")
	}
	if err := viper.Unmarshal(&ret); err != nil {
		return &ret, errors.Wrap(err, "Failed to unmarshal config")
	}
	return &ret, nil
}

func (c *Configuration) Save(filename string) error {
	configFile, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer configFile.Close()
	err = yaml.NewEncoder(configFile).Encode(c)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}
	return nil
}
