package controllers

import (
	"github.com/pkg/errors"
	"intel/isecl/sqvs/v3/resource/parser"
)

// StandaloneVerifier verifies quotes when SGX Attestation service is operating in standalone mode
type StandaloneVerifier struct {
}

func (ev StandaloneVerifier) VerifyQuote(quoteData string) error {
	// for standalone mode, pass quote to the SQVS stub
	parsedBlob := parser.ParseSkcQuoteBlob(quoteData)
	if parsedBlob == nil {
		return errors.New("controllers/standalone_verifier:VerifyQuote() Error parsing quote")
	}

	return nil
}
