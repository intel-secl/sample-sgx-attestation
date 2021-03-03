/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

const (
	AppUsername            = "foobar"
	AppPassword            = "21345h8askjdf"
	DefaultAttestedAppHost = "127.0.0.1"
	DefaultAttestedAppPort = 9999
	ProtocolTcp            = "tcp"
)

const (
	ConfigDir             = "./"
	CaCertsDir            = "./"
	DefaultConfigFilePath = ConfigDir + "config.yml"
	ConfigFile            = "config"
	SgxQuotePolicyPath    = ConfigDir + "sgx-quote-policy.txt"
	EndLine               = "\n"
	VerifyQuote           = "/sgx_qv_verify_quote"
	SWKSize               = 16
)

// SGX Policy
const (
	MREnclaveField  = "MREnclave"
	MRSignerField   = "MRSigner"
	CpuSvnField     = "CPU_SVN"
	PolicyFileDelim = ":"
)

// Message definitions

const (
	MsgTypeConnect          uint8 = 1
	MsgTypePubkeyQuote      uint8 = 2
	MsgTypePubkeyWrappedSWK uint8 = 3
	MsgTypeSWKWrappedSecret uint8 = 4
)

type PayloadConnect struct {
	Username string
	Password string
}

type PayloadPubkeyQuote struct {
	Pubkey []byte
	Quote  []byte
}

type PayloadPubkeyWrappedSWK struct {
	WrappedSWK []byte
}

type PayloadSWKWrappedSecret struct {
	WrappedSecret []byte
}

type Message struct {
	Type             uint8
	ResponseCode     int
	ConnectRequest   PayloadConnect
	PubkeyQuote      PayloadPubkeyQuote
	PubkeyWrappedSWK PayloadPubkeyWrappedSWK
	SWKWrappedSecret PayloadSWKWrappedSecret
}
