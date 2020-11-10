/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

// general SGX APP VERIFIER constants
const (
	ServiceName     = "SGX Sample Tenant App Service"
	ServiceDir      = "sgx-tenantapp-service/"
	ServiceUserName = "sgx-tenantapp-service"
	SystemCtlUnit   = "sgx-tenantapp-service"
	TenantUsername  = "tenantusername"
	TenantPassword  = "tenantpassw0rd"

	// service remove command
	ServiceRemoveCmd           = "systemctl disable " + SystemCtlUnit
	DefaultTenantAppListenHost = "127.0.0.1"
)

// these are used only when uninstalling service
const (
	HomeDir      = "/opt/" + ServiceDir
	RunDirPath   = "/run/" + ServiceDir
	ExecLinkPath = "/usr/bin/" + ServiceUserName
	LogDir       = "/var/log/" + ServiceDir
)

// file and directory constants
const (
	ConfigDir             = "/etc/" + ServiceDir
	DefaultConfigFilePath = ConfigDir + "config.yml"
	ConfigFile            = "config"
)

// tls constants
const (
	// default locations for tls certificate and key
	DefaultKeyAlgorithm = "rsa"
	DefaultKeyLength    = 3072
)

// general constants for stand alone mode
const (
	DefaultStandAloneMode = true
)

// server constants
const (
	DefaultAppListenerPort = 9999
)

// log constants
const (
	DefaultLogEntryMaxlength = 1500
	LogFile                  = LogDir + ServiceUserName + ".log"
	SecurityLogFile          = LogDir + ServiceUserName + "-security.log"
)

//Protocol
const (
	ProtocolTcp string = "tcp4"
)

//Protocol type
const (
	ReqTypeConnect          uint8 = 1
	ReqTypePubkeyWrappedSWK uint8 = 2
	ReqTypeSWKWrappedSecret uint8 = 3
)

//Param type
const (
	ParamTypeUsername         uint8 = 1
	ParamTypePassword         uint8 = 2
	ParamTypePubkeyWrappedSwk uint8 = 3
	ParamTypeSwkWrappedSecret uint8 = 4
)

//Response code
const (
	ResponseCodeSuccess uint8 = 1
	ResponseCodeFailure uint8 = 2
)

//Response Element
const (
	ResponseElementTypeSGXQuote      uint8 = 1
	ResponseElementTypeEnclavePubKey uint8 = 2
)

const (
	EndLine = "\n"
)
