/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/base64"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/config"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestStandaloneVerifier_VerifyQuote(t *testing.T) {
	sv := StandaloneVerifier{Config: &config.Configuration{TrustedRootCAPath: "../test/rootcacerts/root_ca.pem"}}
	quoteRaw, _ := ioutil.ReadFile("../test/tenant_extended_quote.dat")
	// we need to convert to base64 before sending to verifier
	assert.NoError(t, sv.VerifyQuote(base64.StdEncoding.EncodeToString(quoteRaw)))
}
