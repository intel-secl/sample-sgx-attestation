/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tcpmsglib

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
