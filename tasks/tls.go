/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/constants"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v3/crypt"
	"intel/isecl/lib/common/v3/setup"
	"io"
	"math/big"
	"time"
)

type Tls struct {
	StandAloneMode bool
	CommonName     string
	Validity       int

	ConsoleWriter io.Writer
	commandName string
}

func (t *Tls) Run(c setup.Context) error {
	if t.StandAloneMode {
		if t.CommonName == "" {
			return errors.New("Pointer to service configuration structure can not be nil")
		}
		privKey, pubKey, err := crypt.GenerateKeyPair(constants.DefaultKeyAlgorithm, constants.DefaultKeyLength)
		if err != nil {
			return errors.Wrap(err, "tasks/tls:Run() Could not create tls key pair")
		}
		pkcs8Der, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return errors.Wrap(err, "tasks/tls:Run() Could not marshal private key to pkcs8 format error")
		}
		tlsTemplate := x509.Certificate{
			Subject: pkix.Name{
				CommonName:   t.CommonName,
			},
			SerialNumber: big.NewInt(0),
			Issuer: pkix.Name{
				CommonName: t.CommonName,
			},
			NotBefore: time.Now(),
			NotAfter: time.Now().AddDate(t.Validity, 0, 0),

			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		tlsTemplate.SignatureAlgorithm, err = crypt.GetSignatureAlgorithm(pubKey)
		if err != nil {
			return errors.Wrap(err, "tasks/tls:Run() Could not read signature from Public Key")
		}

		tlsCert, err := x509.CreateCertificate(rand.Reader, &tlsTemplate, &tlsTemplate, pubKey, privKey)
		if err != nil {
			return errors.Wrap(err, "tasks/tls:Run() Could not create self signed TLS certificate")
		}
		err = crypt.SavePrivateKeyAsPKCS8(pkcs8Der, constants.DefaultTLSKeyFile)
		if err != nil {
			return errors.Wrap(err, "tasks/tls:Run() Could not save TLS private key")
		}
		err = crypt.SavePemCertChain(constants.DefaultTLSCertFile, tlsCert)
		if err != nil {
			return errors.Wrap(err, "tasks/tls:Run() Could not save TLS certificate")
		}

	}

	return nil
}

func (t *Tls) Validate(c setup.Context) error {
	if t.StandAloneMode {
		if t.CommonName == "" {
			return errors.New("Configured TLS common Name is not valid")
		}
	}

	return nil
}

func (t *Tls) PrintHelp(w io.Writer) {
	fmt.Fprintln(w, "This task is intended to generate self signed TLS certificate")
}

func (t *Tls) SetName(n, e string) {
	t.commandName = n
}