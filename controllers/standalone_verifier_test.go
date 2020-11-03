package controllers

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/config"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestStandaloneVerifier_VerifyQuote(t *testing.T) {
	sv := StandaloneVerifier{Config: &config.Configuration{}}
	quoteRaw, _ := ioutil.ReadFile("../pkg/tenantapp/resources/quote.dat")
	assert.NoError(t, sv.VerifyQuote(string(quoteRaw)))
}
