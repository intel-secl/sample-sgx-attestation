/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"bufio"
	"encoding/base64"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/domain"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tcpmsglib"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/controller"
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"

	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

func (a *App) handleConnection(connection net.Conn, sh *controller.SocketHandler) {
	log.Trace("app:handleConnection() Entering")
	defer log.Trace("app:handleConnection() Leaving")

	var resp *domain.TenantAppResponse

	defer connection.Close()

	if sh == nil {
		log.Fatalf("server:handleConnection SocketHandler not initialized")
	}

	log.Printf("Serving %s\n", connection.RemoteAddr().String())
	b64Req, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		log.WithError(err).Errorf("server:handleConnection failed to read request body")
		resp = &domain.TenantAppResponse{
			RequestType: constants.ReqTypeConnect,
			RespCode:    constants.ResponseCodeFailure,
			ParamLength: 0,
		}
	} else {

		// base64 decode the request
		rawReq, err := base64.StdEncoding.DecodeString(string(b64Req))
		if err != nil {
			log.WithError(err).Errorf("server:handleConnection request base64 decode failed")
		}

		taRequest := tcpmsglib.UnmarshalRequest(rawReq)

		switch taRequest.RequestType {
		case constants.ReqTypeConnect:
			resp, err = sh.HandleConnect(taRequest)
		}

		if err != nil {
			log.WithError(err).Error("server:handleConnection Error processing request")
		}
	}

	if err != nil {
		log.Info("server:handleConnection Sending failure response")
		resp = &domain.TenantAppResponse{
			RequestType: constants.ReqTypeConnect,
			RespCode:    constants.ResponseCodeFailure,
			ParamLength: 0,
		}
	} else {
		log.Info("server:handleConnection Sending success response")
	}

	// send base64 encoded response
	connection.Write([]byte(base64.StdEncoding.EncodeToString(tcpmsglib.MarshalResponse(*resp)) + constants.EndLine))
}

func (a *App) startServer() error {
	log.Trace("app:startServer() Entering")
	defer log.Trace("app:startServer() Leaving")

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}

	log.Info("Starting TenantAppService")

	// check if socket can be opened up
	listenAddr := c.TenantServiceHost + ":" + strconv.Itoa(c.TenantServicePort)
	log.Infof("app:startServer Binding to %s", listenAddr)
	listener, err := net.Listen(constants.ProtocolTcp, listenAddr)
	if err != nil {
		log.Error(errors.Wrapf(err, "app:startServer() Error binding to socket %s", listenAddr))
		return err
	}
	defer listener.Close()

	sh := controller.SocketHandler{Config: a.Config}
	err = sh.EnclaveInit()
	if err != nil {
		log.WithError(err).Error("app:startServer() Error initializing enclave")
		return err
	}

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL)

	go func() {
		for {
			conn, err := listener.Accept()

			if err != nil {
				log.Error(errors.Wrapf(err, "app:startServer() Error binding to socket %s", listenAddr))
				break
			}
			go a.handleConnection(conn, &sh)
		}
		done <- true
	}()

	go func() {
		sig := <-stop
		log.Infof("app:startServer() Received signal %s", sig)
		done <- true
	}()

	<-done
	// let's destroy enclave and exit
	err = sh.EnclaveDestroy()

	if err != nil {
		log.WithError(err).Info("app:startServer() Error destroying enclave")
	}

	return nil
}
