/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/controllers"
	"github.com/intel-secl/sample-sgx-attestation/v3/common"
	"github.com/pkg/errors"
	"net"
	"strconv"
	"strings"
	"time"
)

func (a *App) startVerifier() error {
	log.Trace("app:startVerifier() Entering")
	defer log.Trace("app:startVerifier() Leaving")

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration!")
	}

	log.Info("Starting Attesting App ...")

	verifyController := controllers.AppVerifierController{
		Config:             c,
		ExtVerifier:        controllers.ExternalVerifier{Config: c, CaCertsDir: common.CaCertsDir},
		SgxQuotePolicyPath: common.SgxQuotePolicyPath,
	}

	// Connect to the Attested App
	conn, err := net.Dial(common.ProtocolTcp, strings.Join([]string{c.AttestedAppServiceHost, strconv.Itoa(c.AttestedAppServicePort)}, ":"))
	if err != nil {
		return err
	}
	log.Info("Connected to AttestedApp.")

	// Send a connect message and receive SGX Quote + Public key
	status, respMsg := verifyController.ConnectAndReceiveQuote(conn)
	log.Info("Received public key and SGX quote from AttestedApp.")

	// Verify SGX Quote
	status = verifyController.VerifySGXQuote(respMsg.PubkeyQuote.Quote, respMsg.PubkeyQuote.Pubkey)
	if !status {
		err = errors.New("SGX Quote verification failed!")
		log.Error("SGX Quote verification failed!")
		return err
	}

	// Generate a SWK
	log.Info("Generating SWK ...")
	swk, err := verifyController.GenerateSWK()
	if err != nil {
		log.Error("SWK Generation Failed.")
		return err
	}

	// Share SWK with  the Attested App
	err = verifyController.SharePubkeyWrappedSWK(conn, respMsg.PubkeyQuote.Pubkey, swk)
	if err != nil {
		log.Error("Sending Pubkey Wrapped SWK failed!")
		return err
	}

	log.Info("SWK Shared.")

	// We wait before sending the next message so that
	// the enclave has time to unwrap the SWK before it
	// can receive the secret.
	time.Sleep(1 * time.Second)

	// Share secret with the Attested App
	log.Info("Sharing secret ...")
	secret := "For your eyes only!"
	err = verifyController.ShareSWKWrappedSecret(conn, swk, []byte(secret))
	if err != nil {
		log.Error("Sending SWK Wrapped Secret failed!")
		return err
	}

	log.Info("Secret shared.")

	return nil
}
