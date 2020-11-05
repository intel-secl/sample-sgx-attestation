/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"bufio"
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/controllers"
	"github.com/intel-secl/sample-sgx-attestation/v3/domain"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantapp/controller"
	"github.com/pkg/errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func handleConnection(c net.Conn) {
	var resp *domain.TenantAppResponse

	fmt.Printf("Serving %s\n", c.RemoteAddr().String())
	defer c.Close()
	for {
		rawData, err := bufio.NewReader(c).ReadBytes('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		sh := controller.SocketHandler{
			SgxQuotePath: constants.SgxQuotePolicyPath,
		}

		taRequest := controllers.UnmarshalRequest(rawData)

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
		c.Write(controllers.MarshalResponse(*resp))
		c.Write([]byte(constants.EndLine))
	}
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

	defaultLog.Info("Starting server")

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// check if socket can be opened up
	port := ":" + string(c.Server.Port)
	l, err := net.Listen("tcp4", port)
	if err != nil {
		err = errors.Wrap(err, "app:startServer() Error binding to socket port")
		return err
	}

	// dispatch tcp socket server handle routine
	conn, err := l.Accept()
	if err != nil {
		fmt.Println(err)
	}
	go handleConnection(conn)

	secLog.Info(commLogMsg.ServiceStart)
	<-stop

	if err := l.Close(); err != nil {
		defaultLog.WithError(err).Info("Failed to gracefully shutdown TCP server")
		return err
	}
	secLog.Info(commLogMsg.ServiceStop)
	return nil
}
