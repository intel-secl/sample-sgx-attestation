/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tenantapp

import (
	"bufio"
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantapp/controller"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/controllers"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/domain"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"math/rand"
	"net"
	"strconv"
	"time"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (a *TenantServiceApp) handleConnection(c net.Conn) {
	var resp *domain.TenantAppResponse

	defer c.Close()

	fmt.Printf("Serving %s\n", c.RemoteAddr().String())
	rawData, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		fmt.Println(err)
		return
	}

	sh := controller.SocketHandler{Config: a.Config}

	taRequest := controllers.UnmarshalRequest(rawData)

	switch taRequest.RequestType {
	case constants.ReqTypeConnect:
		resp, err = sh.HandleConnect(taRequest)
	case constants.ReqTypePubkeyWrappedSWK:
		resp, err = sh.HandlePubkeyWrappedSWK(taRequest)
	case constants.ReqTypeSWKWrappedSecret:
		resp, err = sh.HandleSWKWrappedSecret(taRequest)
		break
	}

	if err != nil {
		defaultLog.WithError(err).Error("server:handleConnection Error processing request")
	}
	c.Write(controllers.MarshalResponse(*resp))
	c.Write([]byte(constants.EndLine))
}

func (a *TenantServiceApp) StartServer() error {
	defaultLog.Trace("app:startServer() Entering")
	defer defaultLog.Trace("app:startServer() Leaving")

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}

	defaultLog.Info("Starting TenantAppService")

	// dispatch tcp socket server handle
	go func() {
		// check if socket can be opened up
		listenAddr := c.TenantServiceHost + ":" + strconv.Itoa(c.TenantServicePort)
		l, err := net.Listen("tcp4", listenAddr)
		if err != nil {
			err = errors.Wrapf(err, "app:startServer() Error binding to socket %s", listenAddr)
			defaultLog.Error(err)
		}

		rand.Seed(time.Now().Unix())

		defer secLog.Info(commLogMsg.ServiceStop)
		defer l.Close()

		for {
			conn, err := l.Accept()
			if err != nil {
				defaultLog.Error(errors.Wrapf(err, "app:startServer() Error binding to socket %s", listenAddr))
				break
			}

			go a.handleConnection(conn)
		}
	}()
	return nil
}
