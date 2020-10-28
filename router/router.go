/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/intel-secl/sample-sgx-attestation/v3/config"
	"github.com/intel-secl/sample-sgx-attestation/v3/constants"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v3/crypt"
	"intel/isecl/lib/common/v3/log"
	cmw "intel/isecl/lib/common/v3/middleware"
	cos "intel/isecl/lib/common/v3/os"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type Router struct {
	cfg *config.Configuration
}

// InitRoutes registers all routes for the application.
func InitRoutes(cfg *config.Configuration) *mux.Router {
	defaultLog.Trace("router/router:InitRoutes() Entering")
	defer defaultLog.Trace("router/router:InitRoutes() Leaving")

	// Create public routes that does not need any authentication
	router := mux.NewRouter()

	router.SkipClean(true)
	serviceApi := "/" + strings.ToLower(constants.ServiceUserName) + constants.ApiVersion
	subRouter := router.PathPrefix(serviceApi).Subrouter()
	subRouter = SetVersionRoutes(subRouter)

	subRouter = router.PathPrefix(serviceApi).Subrouter()
	cfgRouter := Router{cfg: cfg}
	var cacheTime, _ = time.ParseDuration(constants.JWTCertsCacheTime)

	subRouter.Use(cmw.NewTokenAuth(constants.CaCertsDir,
		constants.CaCertsDir, cfgRouter.fnGetJwtCerts,
		cacheTime))
	subRouter = SetAppVerifierRoutes(subRouter, cfg)

	return router
}

// Fetch JWT certificate from AAS
func (r *Router) fnGetJwtCerts() error {
	defaultLog.Trace("router/router:fnGetJwtCerts() Entering")
	defer defaultLog.Trace("router/router:fnGetJwtCerts() Leaving")

	cfg := r.cfg
	if !strings.HasSuffix(cfg.AASApiUrl, "/") {
		cfg.AASApiUrl = cfg.AASApiUrl + "/"
	}
	url := cfg.AASApiUrl + "noauth/jwt-certificates"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not create http request")
	}
	req.Header.Add("accept", "application/x-pem-file")
	rootCaCertPems, err := cos.GetDirFileContents(constants.CaCertsDir, "*.pem")
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not read root CA certificate")
	}

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, rootCACert := range rootCaCertPems {
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			return err
		}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				RootCAs:            rootCAs,
			},
		},
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not retrieve jwt certificate")
	}
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	err = crypt.SavePemCertWithShortSha1FileName(body, constants.CaCertsDir)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not store Certificate")
	}
	return nil
}
