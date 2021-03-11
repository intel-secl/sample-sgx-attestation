/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

// #cgo CFLAGS: -I /opt/intel/sgxsdk/include -I /usr/lib/
// #cgo LDFLAGS: -L/root/src/sample-sgx-attestation/attestedApp/out/ -L /usr/lib64 -luntrusted -lssl -lcrypto
// #include "./libenclave/Untrusted/Untrusted.h"
import "C"

import (
	"encoding/gob"
	"github.com/intel-secl/sample-sgx-attestation/v3/common"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"unsafe"
)

func (a *App) getPubkeyFromEnclave() []byte {
	var keyBuffer []byte
	var pubKeySize C.int
	var keyPtr *C.u_int8_t

	keyPtr = C.get_pubkey(&pubKeySize)
	log.Info("getPubkeyFromEnclave : Pub key length : ", pubKeySize)

	keyBuffer = C.GoBytes(unsafe.Pointer(keyPtr), pubKeySize)

	return keyBuffer
}

func (a *App) getQuoteAndPubkeyFromEnclave() ([]byte, []byte) {
	var qBytes []byte
	var kBytes []byte

	// qSize holds the length of the quote byte array returned from enclave
	var qSize C.int
	var keySize C.int

	// qPtr holds the bytes array of the quote returned from enclave
	var qPtr *C.u_int8_t

	qPtr = C.get_SGX_Quote(&qSize, &keySize)
	log.Printf("Quote size : %d", qSize)
	qBytes = C.GoBytes(unsafe.Pointer(qPtr), qSize)
	kBytes = C.GoBytes(unsafe.Pointer(qPtr), qSize+keySize)

	return kBytes, qBytes
}

func (a *App) receiveConnectRequest(connection net.Conn) (error, bool) {
	authenticated := false

	gobDecoder := gob.NewDecoder(connection)
	requestMsg := new(common.Message)
	err := gobDecoder.Decode(requestMsg)
	if err != nil {
		log.Error("Decoding connect message failed!")
		return err, authenticated
	}

	if requestMsg.Type != common.MsgTypeConnect {
		err = errors.New("Incorrect message type!")
		log.Error("Incorrect message type!")
		return err, authenticated
	}

	if requestMsg.ConnectRequest.Username == common.AppUsername &&
		requestMsg.ConnectRequest.Password == common.AppPassword {
		authenticated = true
	}

	return err, authenticated
}

func (a *App) sendPubkeySGXQuote(connection net.Conn) error {

	// Get the quote from Enclave
	pubKey, sgxQuote := a.getQuoteAndPubkeyFromEnclave()

	// Get public key from Enclave.
	pubKey = a.getPubkeyFromEnclave()

	// Prepare response with SGX Quote and Enclave
	log.Info("Sending Pubkey and SGX Quote message...")
	gobEncoder := gob.NewEncoder(connection)
	responseMsg := new(common.Message)
	responseMsg.Type = common.MsgTypePubkeyQuote
	responseMsg.PubkeyQuote.Pubkey = pubKey
	responseMsg.PubkeyQuote.Quote = sgxQuote

	// Send quote + public key to attestingApp
	err := gobEncoder.Encode(responseMsg)
	if err != nil {
		log.Error("Encoding Pubkey Quote message failed!")
	}

	return err
}

func (a *App) receivePubkeyWrappedSWK(connection net.Conn) error {
	log.Info("Receiving Pubkey wrapped SWK message...")
	gobWrappedSWKDecoder := gob.NewDecoder(connection)
	wrappedSWKMsg := new(common.Message)
	err := gobWrappedSWKDecoder.Decode(wrappedSWKMsg)
	if err != nil {
		log.Error("Decoding Pubkey wapped SWK message failed!")
		return err
	}

	if wrappedSWKMsg.Type != common.MsgTypePubkeyWrappedSWK {
		err = errors.New("Incorrect message type!")
		log.Error("Incorrect message type!")
		return err
	}

	log.Info("Wrapped SWK Received length : ", len(wrappedSWKMsg.PubkeyWrappedSWK.WrappedSWK))

	pSize := C.ulong(len(wrappedSWKMsg.PubkeyWrappedSWK.WrappedSWK))
	log.Info("Size of Wrapped SWK : ", pSize)

	pStr := C.CBytes(wrappedSWKMsg.PubkeyWrappedSWK.WrappedSWK)
	p := (*C.uint8_t)(unsafe.Pointer(pStr))

	// Unwrap inside the enclave.
	status := C.unwrap_SWK(p, pSize)
	if status != 0 {
		err = errors.New("SWK unwrapping failed!")
	}

	return err
}

func (a *App) receiveSWKWrappedSecret(connection net.Conn) error {
	log.Info("Receiving SWK wrapped Secret message...")
	gobWrappedSecretDecoder := gob.NewDecoder(connection)
	wrappedSecretMsg := new(common.Message)

	err := gobWrappedSecretDecoder.Decode(wrappedSecretMsg)
	if err != nil {
		log.Error("Decoding wrapped secret message failed!")
		return err
	}

	if wrappedSecretMsg.Type != common.MsgTypeSWKWrappedSecret {
		err = errors.New("Incorrect message type!")
		log.Error("Incorrect message type!")
		return err
	}

	if len(wrappedSecretMsg.SWKWrappedSecret.WrappedSecret) == 0 {
		log.Error("Wrapped secret Size can't be zero")
		err = errors.New("Wrapped secret Size can't be zero!")
		return err
	}

	pSecretSize := C.ulong(len(wrappedSecretMsg.SWKWrappedSecret.WrappedSecret))
	pSecret := C.CBytes(wrappedSecretMsg.SWKWrappedSecret.WrappedSecret)
	pSecretPtr := (*C.uint8_t)(unsafe.Pointer(pSecret))

	//Unwrap the secret inside the Enclave
	status := C.unwrap_secret(pSecretPtr, pSecretSize)
	if status != 0 {
		err = errors.New("Unwrapping of secret failed!")
	}

	return err
}

func (a *App) handleConnection(connection net.Conn) error {
	defer connection.Close()

	// Step 1 - Receive a connect request
	err, authenticated := a.receiveConnectRequest(connection)
	if err != nil {
		log.Error("server:handleConnection : ", err)
		return err
	}

	if !authenticated {
		err = errors.New("Connection authentication failed!")
		log.Error("server:handleConnection : ", err)
		return err
	}

	// Step 2 - Get the quote from enclave and send it to
	// the attesting app.
	err = a.sendPubkeySGXQuote(connection)
	if err != nil {
		log.Error("server:handleConnection : ", err)
		return err
	}

	// Step 3 - Wait and receive public key wrapped SWK.
	err = a.receivePubkeyWrappedSWK(connection)
	if err != nil {
		log.Error("server:handleConnection : ", err)
		return err
	}

	// Step 4 - Receive SWK wrapped secret
	a.receiveSWKWrappedSecret(connection)
	if err != nil {
		log.Error("server:handleConnection : ", err)
		return err
	}

	return nil
}

// EnclaveInit initializes the enclave.
func (a *App) EnclaveInit() error {
	log.Trace("EnclaveInit Entering")
	defer log.Trace("EnclaveInit Leaving")

	var enclaveInitStatus C.int

	// Initialize enclave
	log.Info("Initializing enclave...")
	enclaveInitStatus = C.init()

	if enclaveInitStatus != 0 {
		return errors.Errorf("EnclaveInit Failed to initialize enclave. Error code: %d", enclaveInitStatus)
	}

	log.Info("Enclave initialized.")

	return nil
}

// EnclaveDestroy cleans up the enclave on exit
func (a *App) EnclaveDestroy() error {
	log.Trace("EnclaveDestroy Entering")
	defer log.Trace("EnclaveDestroy Leaving")

	// Destroy enclave
	enclaveDestroyStatus := C.destroy_Enclave()

	if enclaveDestroyStatus != 0 {
		return errors.Errorf("Failed to destroy enclave. Error code: %d", enclaveDestroyStatus)
	}

	log.Info("controller/socket_handler:EnclaveInit Destroyed enclave")

	return nil
}

func (a *App) startServer() error {
	log.Trace("app:startServer() Entering")
	defer log.Trace("app:startServer() Leaving")

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}

	log.Info("Starting Attested App ...")

	// AttestedApp would always bind to localhost. Port can be configured.
	listenAddr := common.DefaultAttestedAppHost + ":" + strconv.Itoa(c.AttestedAppServicePort)
	log.Infof("Attested App socket binding to %s", listenAddr)
	listener, err := net.Listen(common.ProtocolTcp, listenAddr)
	if err != nil {
		log.Error(errors.Wrapf(err, "app:startServer() Error binding to socket %s", listenAddr))
		return err
	}
	defer listener.Close()

	err = a.EnclaveInit()
	if err != nil {
		log.WithError(err).Error("app:startServer() Error initializing enclave!")
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
			go a.handleConnection(conn)

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
	err = a.EnclaveDestroy()

	if err != nil {
		log.WithError(err).Info("app:startServer() Error destroying enclave")
	}

	return nil

}
