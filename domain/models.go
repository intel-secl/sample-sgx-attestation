/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

type TenantAppResponseElement struct {
	Type    uint8
	Length  uint16
	Payload []byte
}

type TenantAppResponse struct {
	RequestType uint8
	RespCode    uint8
	ParamLength uint16
	Elements    []TenantAppResponseElement
}

type SwResponse struct {
	Status                string
	Message               string
	SwIssuer              string
	ChallengeKeyType      string
	ChallengeRsaPublicKey string
}
