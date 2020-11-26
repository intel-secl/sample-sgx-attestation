/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

type TenantAppMessageElement struct {
	Type    uint8
	Length  uint16
	Payload []byte
}

type TenantAppResponse struct {
	RequestType uint8
	RespCode    uint8
	ParamLength uint16
	Elements    []TenantAppMessageElement
}

type VerifierAppRequest struct {
	RequestType uint8
	ParamLength uint16
	Elements    []TenantAppMessageElement
}

type SwResponse struct {
	Status                string
	Message               string
	SwIssuer              string
	ChallengeKeyType      string
	ChallengeRsaPublicKey string
}
