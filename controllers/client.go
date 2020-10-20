/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/binary"
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/constants"
	"github.com/intel-secl/sample-sgx-attestation/v3/domain"
	"github.com/spf13/cast"
	"log"
	"net"
)

type TenantAppClient struct {
	address string
}

func NewSgxSocketClient(address string) *TenantAppClient {
	return &TenantAppClient{address: address}
}


func (client *TenantAppClient) socketRequest(msg []byte) ([]byte, error) {
	// connect to server
	conn, err := net.Dial(constants.ProtocolTcp, client.address)
	if err != nil {
		return nil, err
	}

	// send to server
	conn.Write(msg)
	conn.Write([]byte(constants.StopCharacter))
	log.Printf("Send: %s", msg)

	// read from server
	buff := make([]byte, 1024)
	n, err := conn.Read(buff)
	log.Printf("Receive: %s", buff[:n])
	return buff, err
}

//Requests from the Tenant App Verifier shall use the following format:
//<Request_Type><Total_Length_of_request_parameters>[parameter]*
//Request_Type: uint8: one of connect (1), PubkeyWrappedSWK (2) and SWKWrappedSecret (3)
//Total_Length_of_request_parameters: uint16
//parameter: one or more concatenated parameters. The number of parameters depends on the request type. Each parameter is encoded as follows:
//<parameter_type><parameter_length><parameter>
//parameter_type: uint8: one of username (1), password (2), pubkeywrappedswk (3), and swkrappedSecret (4)
//parameter_length: uint16
//Note: the format version has been omitted for simplicity.
func marshalRequest(requestType uint8, params map[uint8][]byte) []byte {
	var connectRequest []byte
	connectRequest = append(connectRequest, requestType)
	connectRequest = append(connectRequest, getLengthInBytes(len(params))...)
	for paramType, paramValue := range params {
		connectRequest = append(connectRequest, paramType)
		connectRequest = append(connectRequest, getLengthInBytes(len(paramValue))...)
		connectRequest = append(connectRequest, paramValue...)
	}
	return connectRequest
}

//Responses from the Tenant App shall use the following format:
//<Request_Type><Response_Code><Total_Length_of_response>[response_element]*
//Request_Type: uint8, should be the same as the request (see 6.3.1).
//Response_Code: uint8, one of success (1), failure (2)
//Total_Length_of_request_parameters: uint16
//Response_element: one or more concatenated response elements. The number of response elements depends on the request type. Each response element is encoded as follows:
//<response_element_type>< response_element_length>< response_element >
//response_element _type: uint8: one of sgxquote (1), enclavepubkey (2)
//response_element _length: uint16
//Note: the format version has been omitted for simplicity.
func unmarshalResponse(msg []byte) (*domain.TenantAppResponse, error) {
	var connectResponse domain.TenantAppResponse

	// read Request RequestType
	connectResponse.RequestType = cast.ToUint8(msg[0])
	// response code
	connectResponse.RespCode = cast.ToUint8(msg[1])
	if connectResponse.RespCode != constants.ResponseCodeSuccess && connectResponse.RespCode != constants.ResponseCodeFailure {
		return &connectResponse, fmt.Errorf("client/unmarshalResponse: invalid response type: %d", connectResponse.RespCode)
	}
	if connectResponse.RespCode == constants.ResponseCodeFailure {
		return &connectResponse, fmt.Errorf("client/unmarshalResponse: Request failed")
	}
	if connectResponse.RequestType == constants.ReqTypeConnect {
		// length of request params
		lengthOfParams := binary.BigEndian.Uint16(msg[2:4])

		currentPosition := 4 // 0 - RequestType | 1 - ResponseCode | 2,3 - LengthOfParams
		var reList []domain.TenantAppResponseElement
		var i uint16
		// for each of the response elements
		for i = 0; i < lengthOfParams; i++ {
			var responseElement domain.TenantAppResponseElement
			// read the RE type
			responseElement.Type = msg[currentPosition]
			// validate
			if responseElement.Type != constants.ResponseElementTypeSGXQuote &&
				responseElement.Type != constants.ResponseElementTypeEnclavePubKey {
				return nil, fmt.Errorf("client/unmarshalResponse: invalid response element type: %d", responseElement.Type)
			}
			currentPosition += 1 //ElementType
			// read the RE Length
			responseElement.Length = binary.BigEndian.Uint16(msg[(currentPosition):(currentPosition + 2)])
			// get the Element type
			currentPosition += 2 //ElementLength
			// get payload
			responseElement.Payload = msg[currentPosition:(uint16(currentPosition) + responseElement.Length)]
			currentPosition += cast.ToInt(responseElement.Length) //Element
			// add the list
			reList = append(reList, responseElement)
		}

		// set elements
		connectResponse.Elements = reList
	} else if connectResponse.RequestType != constants.ReqTypePubkeyWrappedSWK && connectResponse.RequestType != constants.ReqTypeSWKWrappedSecret  {
		return &connectResponse, fmt.Errorf("client/unmarshalResponse: Invalid request-response type")
	}
	return &connectResponse, nil
}

