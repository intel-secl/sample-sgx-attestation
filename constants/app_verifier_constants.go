/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package constants

import "time"

// general SGX APP VERIFIER constants
const (
	ServiceName     = "SGX APP VERIFIER"
	ServiceDir      = "sgx-app-verifier/"
	ServiceUserName = "sgx-app-verifier"
	ApiVersion      = "/v1"
	// service remove command
	ServiceRemoveCmd = "systemctl disable sgx-app-verifier"
	VerifyQuote      = "/verifyQuote"
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
	CaCertsDir            = ConfigDir + "ca-certs"
	DefaultConfigFilePath = ConfigDir + "config.yml"
	ConfigFile            = "config"
)

// tls constants
const (
	// default locations for tls certificate and key
	DefaultTLSKeyFile                  = ConfigDir + "tls.key"
	DefaultTLSCertFile                 = ConfigDir + "tls-cert.pem"
	DefaultAppTlsCn                    = "SGX APP VERIFIER TLS Certificate"
	DefaultAppTlsSan                   = "127.0.0.1,localhost"
	DefaultKeyAlgorithm                = "rsa"
	DefaultKeyLength                   = 3072
	DefaultSelfSignedCertValidityYears = 1
)

// general constants for stand alone mode
const (
	DefaultStandAloneMode = true
)

// server costants
const (
	DefaultAppListenerPort   = 999
	DefaultReadTimeout       = 30 * time.Second
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 10 * time.Second
	DefaultMaxHeaderBytes    = 1 << 20
)

// log constants
const (
	DefaultLogEntryMaxlength = 1500
	LogFile                  = LogDir + ServiceUserName + ".log"
	HttpLogFile              = LogDir + ServiceUserName + "-http.log"
	SecurityLogFile          = LogDir + ServiceUserName + "-security.log"
)

// jwt constants
const (
	JWTCertsCacheTime = "1m"
)

//Protocol
const (
	ProtocolTcp string = "tcp"
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
	StopCharacter = "\r\n\r\n"
)
