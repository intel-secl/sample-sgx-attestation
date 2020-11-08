/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"

	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/config"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v3/setup"
)

type Service struct {
	config.ServiceConfig
	StandAloneMode    bool
	AASApiUrl         string
	CMSBaseURL        string
	CmsTlsCertDigest  string
	SqvsUrl           string
	TrustedRootCAPath string

	SvcConfigPtr         *config.ServiceConfig
	AASApiUrlPtr         *string
	CMSBaseURLPtr        *string
	CmsTlsCertDigestPtr  *string
	SqvsUrlPtr           *string
	TrustedRootCAPathPtr *string

	ConsoleWriter io.Writer

	commandName string
}

const svcEnvHelpPrompt = "Following environment variables are required for Service setup:"

var svcEnvHelp = map[string]string{
	"SERVICE_USERNAME":         "The service username for SGX APP VERIFIER configured in AAS for non stand alone mode",
	"SERVICE_PASSWORD":         "The service password for SGX APP VERIFIER configured in AAS for non stand alone mode",
	"AAS_BASE_URL":             "The url to AAS",
	"CMS_BASE_URL":             "The url to CMS",
	"CMS_TLS_CERT_SHA384":      "The certificate sha384 digest of CMS",
	"SQVS_URL":                 "The url to SQVS",
	"SGX_TRUSTED_ROOT_CA_PATH": "SQVS Trusted Root CA path",
}

func (t *Service) Run(c setup.Context) error {
	if t.SvcConfigPtr == nil ||
		t.AASApiUrlPtr == nil ||
		t.CMSBaseURLPtr == nil ||
		t.SqvsUrlPtr == nil ||
		t.TrustedRootCAPathPtr == nil ||
		t.CmsTlsCertDigestPtr == nil {
		return errors.New("Pointer to service configuration structure can not be nil")
	}

	if !t.StandAloneMode {
		if t.Username == "" {
			return errors.New("SGX APP VERIFIER configuration not provided: VERIFIER_SERVICE_USERNAME is not set")
		}
		if t.Password == "" {
			return errors.New("SGX APP VERIFIER configuration not provided: VERIFIER_SERVICE_PASSWORD is not set")
		}
		if t.SqvsUrl == "" {
			return errors.New("SGX APP VERIFIER configuration not provided: SQVS_URL is not set")
		}
		t.SvcConfigPtr.Username = t.Username
		t.SvcConfigPtr.Password = t.Password
	}

	if t.AASApiUrl == "" {
		return errors.New("SGX APP VERIFIER configuration not provided: AAS_BASE_URL is not set")
	}
	if t.CMSBaseURL == "" {
		return errors.New("SGX APP VERIFIER configuration not provided: CMS_BASE_URL is not set")
	}
	if t.CmsTlsCertDigest == "" {
		return errors.New("SGX APP VERIFIER configuration not provided: CMS_TLS_CERT_SHA384 is not set")
	}

	*t.AASApiUrlPtr = t.AASApiUrl
	*t.CMSBaseURLPtr = t.CMSBaseURL
	*t.CmsTlsCertDigestPtr = t.CmsTlsCertDigest
	*t.SqvsUrlPtr = t.SqvsUrl
	*t.TrustedRootCAPathPtr = t.TrustedRootCAPath
	return nil
}

func (t *Service) Validate(c setup.Context) error {
	if t.SvcConfigPtr == nil ||
		t.AASApiUrlPtr == nil ||
		t.CMSBaseURLPtr == nil ||
		t.CmsTlsCertDigestPtr == nil {
		return errors.New("Pointer to service configuration structure can not be nil")
	}
	if *t.AASApiUrlPtr == "" ||
		*t.CMSBaseURLPtr == "" ||
		*t.CmsTlsCertDigestPtr == "" ||
		*t.SqvsUrlPtr == "" {
		return errors.New("Configured service CMS-AAS config is not valid")
	}
	if !t.StandAloneMode {
		if t.SvcConfigPtr.Username == "" ||
			t.SvcConfigPtr.Password == "" {
			return errors.New("Configured service username/password is not valid")
		}
	}

	return nil
}

func (t *Service) PrintHelp(w io.Writer) {
	fmt.Fprintln(w, svcEnvHelpPrompt)
	for k, d := range svcEnvHelp {
		fmt.Fprintln(w, k+"\t"+d)
	}
}

func (t *Service) SetName(n, e string) {
	t.commandName = n
}
