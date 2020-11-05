package controllers

import (
	"encoding/base64"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/config"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestStandaloneVerifier_VerifyQuote(t *testing.T) {
	sv := StandaloneVerifier{Config: &config.Configuration{TrustedRootCAPath: "../test/root_ca.pem"}}
	quoteRaw, _ := ioutil.ReadFile("../../tenantapp/build/linux/tenant_sgx_quote.dat")
	// we need to convert to base64 before sending to verifier
	assert.NoError(t, sv.VerifyQuote(base64.StdEncoding.EncodeToString(quoteRaw)))
}
