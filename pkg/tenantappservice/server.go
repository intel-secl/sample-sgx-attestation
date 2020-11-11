/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"bufio"
	"encoding/base64"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/domain"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/lib"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/controller"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (a *App) handleConnection(c net.Conn, sh *controller.SocketHandler) {
	defaultLog.Trace("app:handleConnection() Entering")
	defer defaultLog.Trace("app:handleConnection() Leaving")

	var resp *domain.TenantAppResponse

	defer c.Close()

	if sh == nil {
		defaultLog.Fatalf("server:handleConnection SocketHandler not initialized")
	}

	defaultLog.Printf("Serving %s\n", c.RemoteAddr().String())
	b64Req, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		defaultLog.WithError(err).Errorf("server:handleConnection failed to read request body")
		resp = &domain.TenantAppResponse{
			RequestType: constants.ReqTypeConnect,
			RespCode:    constants.ResponseCodeFailure,
		}
	} else {

		// base64 decode the request
		rawReq, err := base64.StdEncoding.DecodeString(string(b64Req))
		if err != nil {
			defaultLog.WithError(err).Errorf("server:handleConnection request base64 decode failed")
		}

		taRequest := lib.UnmarshalRequest(rawReq)

		switch taRequest.RequestType {
		case constants.ReqTypeConnect:
			resp, err = sh.HandleConnect(taRequest)
		case constants.ReqTypePubkeyWrappedSWK:
			resp, err = sh.HandlePubkeyWrappedSWK(taRequest)
		case constants.ReqTypeSWKWrappedSecret:
			resp, err = sh.HandleSWKWrappedSecret(taRequest)
		}

		if err != nil {
			defaultLog.WithError(err).Error("server:handleConnection Error processing request")
		}
	}

	if err != nil {
		defaultLog.Info("server:handleConnection Sending failure response")
		resp = &domain.TenantAppResponse{
			RequestType: constants.ReqTypeConnect,
			RespCode:    constants.ResponseCodeFailure,
		}
	} else {
		defaultLog.Info("server:handleConnection Sending success response")
	}

	// send base64 encoded response
	c.Write([]byte(base64.StdEncoding.EncodeToString(lib.MarshalResponse(*resp)) + constants.EndLine))
}

func (a *App) startServer() error {
	defaultLog.Trace("app:startServer() Entering")
	defer defaultLog.Trace("app:startServer() Leaving")

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}
	// initialize log
	if err := a.configureLogs(c.Log.EnableStdout, true); err != nil {
		return err
	}

	if !c.StandAloneMode {
		secLog.Fatal(errors.New("Non-standalone mode is not supported in this release"))
	}

	defaultLog.Info("Starting TenantAppService")

	// check if socket can be opened up
	listenAddr := c.TenantServiceHost + ":" + strconv.Itoa(c.TenantServicePort)
	defaultLog.Infof("app:startServer Binding to %s", listenAddr)
	l, err := net.Listen(constants.ProtocolTcp, listenAddr)
	if err != nil {
		defaultLog.Error(errors.Wrapf(err, "app:startServer() Error binding to socket %s", listenAddr))
		return err
	}
	defer l.Close()

	sh := controller.SocketHandler{Config: a.Config}
	err = sh.EnclaveInit()
	if err != nil {
		defaultLog.WithError(err).Error("app:startServer() Error initializing enclave")
		return err
	}

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL)

	// method invoked upon seeing signal
	go func() {
		s := <-stop
		defaultLog.Infof("app:startServer() Received signal %s", s)

		// let's destroy enclave and exit
		sh.EnclaveDestroy()

		secLog.Info(commLogMsg.ServiceStop)
		os.Exit(0)
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			defaultLog.Error(errors.Wrapf(err, "app:startServer() Error binding to socket %s", listenAddr))
			break
		}

		go a.handleConnection(conn, &sh)
	}

	secLog.Info(commLogMsg.ServiceStop)
	if err := l.Close(); err != nil {
		defaultLog.WithError(err).Info("Failed to gracefully shutdown TCP socket")
		return err
	}

	return nil
}
