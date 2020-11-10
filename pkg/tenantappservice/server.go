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

func (a *App) handleConnection(c net.Conn) {
	var resp *domain.TenantAppResponse

	defer c.Close()

	defaultLog.Printf("Serving %s\n", c.RemoteAddr().String())
	b64Req, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		defaultLog.WithError(err).Errorf("server:handleConnection failed to read request body")
		return
	}

	sh := controller.SocketHandler{Config: a.Config}

	// base64 decode the request
	rawReq, err := base64.StdEncoding.DecodeString(string(b64Req))
	if err != nil {
		defaultLog.WithError(err).Errorf("server:handleConnection request base64 decode failed")
		return
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
		return
	}

	defaultLog.Print("server:handleConnection Sending response")
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

	if !c.StandAloneMode {
		secLog.Fatal(errors.New("Non-standalone mode is not supported in this release"))
	}

	defaultLog.Info("Starting TenantAppService")

	// check if socket can be opened up
	listenAddr := c.TenantServiceHost + ":" + strconv.Itoa(c.TenantServicePort)
	defaultLog.Infof("app:startServer Binding to %s", listenAddr)
	l, err := net.Listen(constants.ProtocolTcp, listenAddr)
	if err != nil {
		err = errors.Wrapf(err, "app:startServer() Error binding to socket %s", listenAddr)
		defaultLog.Error(err)
	}

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	done := false
	for !done {
		select {
		case <-stop:
			done = true
		default:
			conn, err := l.Accept()
			if err != nil {
				defaultLog.Error(errors.Wrapf(err, "app:startServer() Error binding to socket %s", listenAddr))
				break
			}

			go a.handleConnection(conn)
		}
	}

	secLog.Info(commLogMsg.ServiceStop)
	if err := l.Close(); err != nil {
		defaultLog.WithError(err).Info("Failed to gracefully shutdown TCP socket")
		return err
	}

	return nil
}
