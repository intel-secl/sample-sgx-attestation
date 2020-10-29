package controllers

import (
	"bytes"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/util"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/intel-secl/sample-sgx-attestation/v3/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/constants"
	"github.com/pkg/errors"
	"net/http"
)

// ExternalVerifier verifies quotes when SGX Attestation service is NOT operating in standalone mode
// in cooperation with CMS, AAS, SQVS etc.
type ExternalVerifier struct {
	Config     *config.Configuration
	CaCertsDir string
}

func (ev ExternalVerifier) VerifyQuote(quoteData string) error {
	url := ev.Config.SqvsUrl + constants.VerifyQuote

	caCerts, err := crypt.GetCertsFromDir(ev.CaCertsDir)
	if err != nil {
		return errors.Wrap(err, "controllers/external_verifier:VerifyQuote() Error in retrieving CA certificates")
	}

	buffer := new(bytes.Buffer)
	err = json.NewEncoder(buffer).Encode(quoteData)
	if err != nil {
		return errors.Wrap(err, "controllers/external_verifier:VerifyQuote() Error in encoding the quote")
	}

	req, err := http.NewRequest("POST", url, buffer)
	if err != nil {
		return errors.Wrap(err, "controllers/external_verifier:VerifyQuote() Error in Creating request")
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	response, err := util.SendRequest(req, ev.Config.AASApiUrl, ev.Config.Service.Username, ev.Config.Service.Password, caCerts)
	var responseAttributes *kbs.QuoteVerifyAttributes

	err = json.Unmarshal(response, &responseAttributes)
	if err != nil {
		return errors.Wrap(err, "controllers/external_verifier:VerifyQuote() Error in unmarshalling response")
	}
	defaultLog.Info("controllers/external_verifier:VerifyQuote() Successfully verified quote in non-standalone mode")

	return nil
}
