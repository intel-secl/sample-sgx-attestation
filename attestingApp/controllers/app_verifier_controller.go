/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

// #cgo CFLAGS: -I /opt/intel/sgxsdk/include -I /usr/lib/
// #cgo LDFLAGS: -L/usr/lib64/ -lencrypt -lssl -lcrypto
// #include "../lib/encrypt.h"
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/common"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"unsafe"
)

type resourceError struct {
	StatusCode int
	Message    string
}

type QuoteVerifyAttributes struct {
	Message                        string `json:"Message"`
	ReportData                     string `json:"reportData"`
	UserDataMatch                  string `json:"userDataMatch"`
	EnclaveIssuer                  string `json:"EnclaveIssuer"`
	EnclaveIssuerProductID         string `json:"EnclaveIssuerProdID"`
	EnclaveIssuerExtendedProductID string `json:"EnclaveIssuerExtProdID"`
	EnclaveMeasurement             string `json:"EnclaveMeasurement"`
	ConfigSvn                      string `json:"ConfigSvn"`
	IsvSvn                         string `json:"IsvSvn"`
	ConfigID                       string `json:"ConfigId"`
	TCBLevel                       string `json:"TcbLevel"`
}

func (e resourceError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type AppVerifierController struct {
	Config             *common.Configuration
	ExtVerifier        ExternalVerifier
	SgxQuotePolicyPath string
}

func wrapSWKByPublicKey(swk []byte, key []byte) ([]byte, error) {

	// SWK
	pSWK := C.CString(string(swk))
	pSwkPtr := (*C.uint8_t)(unsafe.Pointer(pSWK))
	swkLen := C.int(len(swk))

	// KEY
	pKey := C.CBytes(key)
	pKeyPtr := (*C.uint8_t)(unsafe.Pointer(pKey))

	var wrappedSWKLen C.int
	var qPtr *C.u_int8_t

	// NOTE : Golang crypto/rsa uses SHA256 for both padding and MGf1.
	// This needs a corresponding change inside the enclave
	// cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pubKey, swk, nil)
	// if err != nil {
	// 	return nil, errors.Wrap(err, "Failed to create cipher text")
	// }

	// Use lib/encrypt.c to wrap SWK.
	qPtr = C.sc_encrypt_swk(pKeyPtr, pSwkPtr, swkLen, &wrappedSWKLen)
	wrappedSWK := C.GoBytes(unsafe.Pointer(qPtr), wrappedSWKLen)

	return wrappedSWK, nil
}

func (ca AppVerifierController) GenerateSWK() ([]byte, error) {
	//Key for AES 128 bit
	keyBytes := make([]byte, common.SWKSize)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "session/session_management:SessionCreateSwk() Failed to read the key bytes")
	}

	return keyBytes, nil
}

func (ca AppVerifierController) SharePubkeyWrappedSWK(conn net.Conn, key []byte, swk []byte) error {
	cipherText, err := wrapSWKByPublicKey(swk, key)
	if err != nil {
		log.Info("Cipher Text generation Failed.", err)
		return err
	}

	log.Info("Wrapped SWK Cipher Text Length : ", len(cipherText))

	var msg common.Message
	msg.Type = common.MsgTypePubkeyWrappedSWK
	msg.PubkeyWrappedSWK.WrappedSWK = cipherText

	log.Info("Sending Public key wrapped SWK message...")
	gobEncoder := gob.NewEncoder(conn)
	err = gobEncoder.Encode(msg)
	if err != nil {
		log.Error("Sending Public key wrapped SWK message failed!")
		return err
	}

	return nil
}

func (ca AppVerifierController) ShareSWKWrappedSecret(conn net.Conn, key []byte, secret []byte) error {

	log.Info("Secret : ", string(secret))

	if len(key) != 16 {
		log.Error("Key length has to be 16 bytes.")
		return errors.New("Key length has to be 16 bytes")
	}
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		log.Error("Error initialising cipher block", err)
		return err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		log.Error("Error creating GCM", err)
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		log.Error("Error generating nonce for GCM.")
		return err
	}

	wrappedSecret := gcm.Seal(nonce, nonce, secret, nil)

	// Send
	var msg common.Message
	msg.Type = common.MsgTypeSWKWrappedSecret
	msg.SWKWrappedSecret.WrappedSecret = wrappedSecret

	log.Info("Sending SWK Wrapped Secret message ...")
	gobEncoder := gob.NewEncoder(conn)
	err = gobEncoder.Encode(msg)
	if err != nil {
		log.Error("Error sending SWK Wrapped Secret message!")
		return err
	}

	return nil
}

func (ca AppVerifierController) ConnectAndReceiveQuote(conn net.Conn) (bool, *common.Message) {
	var msg common.Message
	msg.Type = common.MsgTypeConnect
	msg.ConnectRequest.Username = common.AppUsername
	msg.ConnectRequest.Password = common.AppPassword

	// Write to socket
	gobEncoder := gob.NewEncoder(conn)
	err := gobEncoder.Encode(msg)
	if err != nil {
		log.Error("Error sending connect message!")
		return false, nil
	}

	// Receive from socket
	respMsg := &common.Message{}
	gobDecoder := gob.NewDecoder(conn)
	err = gobDecoder.Decode(respMsg)
	if err != nil {
		log.Error("Error receiving SGX Quote + Pubkey message!")
		return false, nil
	}

	return true, respMsg
}

func (ca AppVerifierController) VerifySGXQuote(sgxQuote []byte, enclavePublicKey []byte) bool {
	err := ca.verifySgxQuote(sgxQuote, enclavePublicKey)
	if err != nil {
		log.WithError(err).Errorf("Error while verifying SGX quote")
		return false
	}
	log.Info("Verified SGX quote successfully.")
	return true
}

// verifySgxQuote verifies the quote
func (ca AppVerifierController) verifySgxQuote(quote []byte, publicKey []byte) error {
	var err error

	// Convert byte array to string.
	qData := base64.StdEncoding.EncodeToString(quote)
	key := base64.StdEncoding.EncodeToString(publicKey)

	var responseAttributes QuoteVerifyAttributes
	responseAttributes, err = ca.ExtVerifier.VerifyQuote(qData, key)

	if err != nil {
		return errors.Wrap(err, "Error in quote verification!")
	}

	log.Printf(" Verifying against quote policy stored at %s", ca.SgxQuotePolicyPath)

	// Load quote policy from path
	qpRaw, err := ioutil.ReadFile(ca.SgxQuotePolicyPath)
	if err != nil {
		return errors.Wrap(err, "Error reading quote policy file!")
	}

	// split by newline
	lines := strings.Split(string(qpRaw), common.EndLine)
	var mreValue, mrSignerValue, cpusvnValue string
	for _, line := range lines {
		// split by :
		lv := strings.Split(strings.TrimSpace(line), common.PolicyFileDelim)
		if len(lv) != 2 {
			continue
		}
		// switch by field name
		switch lv[0] {
		case common.MREnclaveField:
			mreValue = lv[1]
		case common.MRSignerField:
			mrSignerValue = lv[1]
		case common.CpuSvnField:
			cpusvnValue = lv[1]
		}
	}

	log.Infof("Quote policy has values \n\tMREnclaveField = %s \n\tMRSignerField = %s \n\tCpuSvnField = %s",
		mreValue, mrSignerValue, cpusvnValue)

	if responseAttributes.EnclaveIssuer != mrSignerValue {
		err = errors.Errorf("controllers/app_verifier_controller:verifySgxQuote() Quote policy mismatch in %s", common.MRSignerField)
		return err
	}

	if responseAttributes.ConfigSvn != cpusvnValue {
		err = errors.Errorf("controllers/app_verifier_controller:verifySgxQuote() Quote policy mismatch in %s", common.CpuSvnField)
		return err
	}

	if responseAttributes.EnclaveMeasurement != mreValue {
		err = errors.Errorf("controllers/app_verifier_controller:verifySgxQuote() Quote policy mismatch in %s", common.MREnclaveField)
		return err
	}

	if responseAttributes.UserDataMatch != "true" {
		err = errors.Errorf("controllers/app_verifier_controller:verifySgxQuote() Public key hash value does not match!")
		return err
	}
	return nil
}
