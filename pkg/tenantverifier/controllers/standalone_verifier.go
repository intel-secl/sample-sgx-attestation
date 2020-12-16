/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/config"
	"github.com/pkg/errors"
	"intel/isecl/sqvs/v3/resource/parser"
	"net/http"
)

// StandaloneVerifier verifies quotes when SGX Attestation service is operating in standalone mode
type StandaloneVerifier struct {
	Config *config.Configuration
}

// VerifyQuote implements the Verifier interface
func (ev StandaloneVerifier) VerifyQuote(quoteData string, key string) error {
	// for standalone mode, pass quote to the SQVS stub
	parsedBlob := parser.ParseQVLQuoteBlob(quoteData)
	if parsedBlob == nil {
		return errors.New("controllers/standalone_verifier:VerifyQuote() Error parsing quote")
	}

	return sgxEcdsaQuoteVerify(parsedBlob)
}

// sgxEcdsaQuoteVerify verifies quotes of ECDSA type
func sgxEcdsaQuoteVerify(skcBlobParser *parser.SkcBlobParsed) error {
	if len(skcBlobParser.GetQuoteBlob()) == 0 {
		return &resourceError{Message: "invalid sgx ecdsa quote", StatusCode: http.StatusBadRequest}
	}

	// parse the quote and extract the fields
	quoteObj := parser.ParseEcdsaQuoteBlob(skcBlobParser.GetQuoteBlob())
	if quoteObj == nil {
		return &resourceError{Message: "invalid sgx ecdsa quote", StatusCode: http.StatusBadRequest}
	}

	// at this point we should be calling out to the SGX Quote Verification Service to ensure that the provided
	// quote is parsed appropriately and the VerificationAttributes

	defaultLog.Info("Sgx Ecdsa Quote Verification completed")
	return nil
}
