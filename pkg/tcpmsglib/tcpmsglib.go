/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tcpmsglib

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/intel-secl/sample-sgx-attestation/v3/pkg/domain"
	"github.com/spf13/cast"
	"intel/isecl/lib/common/v3/log"
	"io"
	"net"
)

var defaultLog = log.GetDefaultLogger()

// SendMessageAndGetResponse sends the base64-encoded message on the address provided
// reads response and returns the base64-decoded response from TenantAppService
func SendMessageAndGetResponse(address string, msg []byte) ([]byte, error) {
	defaultLog.Trace("tcpmsglib:SendMessageAndGetResponse() Entering")
	defer defaultLog.Trace("tcpmsglib:SendMessageAndGetResponse() Leaving")

	// connect to server
	conn, err := net.Dial(ProtocolTcp, address)
	if err != nil {
		return nil, err
	}

	// encode to base64 prior to transmission
	_msg := base64.StdEncoding.EncodeToString(msg)

	// send to server
	conn.Write([]byte(_msg + EndLine))
	defaultLog.Debugf("Write to socket: %s", _msg)

	// read from server
	var buf bytes.Buffer
	io.Copy(&buf, conn)
	defaultLog.Debugf("total response size: %d", buf.Len())
	encResponse := string(buf.Bytes())
	response, err := base64.StdEncoding.DecodeString(encResponse)
	if err != nil {
		return nil, err
	}
	defaultLog.Debugf("Receive response: %s", encResponse)
	return response, err
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
// MarshalRequest converts a VerifierAppRequest into a byte-array prior to transmission
func MarshalRequest(requestType uint8, params map[uint8][]byte) []byte {
	defaultLog.Trace("tcpmsglib:MarshalRequest() Entering")
	defer defaultLog.Trace("tcpmsglib:MarshalRequest() Leaving")

	var connectRequest []byte
	connectRequest = append(connectRequest, requestType)
	defaultLog.Debugf("MarshalRequest: requestType - %d", requestType)
	connectRequest = append(connectRequest, GetLengthInBytes(len(params))...)
	defaultLog.Debugf("MarshalRequest: Number of parameters - %d", len(params))
	for paramType, paramValue := range params {
		connectRequest = append(connectRequest, paramType)
		defaultLog.Debugf("MarshalRequest: paramType - %d", len(params))
		connectRequest = append(connectRequest, GetLengthInBytes(len(paramValue))...)
		defaultLog.Debugf("MarshalRequest: ParamLength - %d", len(paramValue))
		connectRequest = append(connectRequest, paramValue...)
		defaultLog.Debugf("MarshalRequest: Payload value base64 - %s", base64.StdEncoding.EncodeToString(paramValue))
	}
	return connectRequest
}

// MarshalResponse converts a TenantAppResponse into a byte-array prior to transmission
func MarshalResponse(resp domain.TenantAppResponse) []byte {
	defaultLog.Trace("tcpmsglib:MarshalResponse() Entering")
	defer defaultLog.Trace("tcpmsglib:MarshalResponse() Leaving")

	var respBytes []byte
	respBytes = append(respBytes, resp.RequestType)
	defaultLog.Debugf("MarshalResponse: requestType - %d", resp.RequestType)
	respBytes = append(respBytes, resp.RespCode)
	defaultLog.Debugf("MarshalResponse: Response Code - %d", resp.RespCode)
	respBytes = append(respBytes, GetLengthInBytes(int(resp.ParamLength))...)
	defaultLog.Debugf("MarshalResponse: Number of parameters - %d", resp.ParamLength)
	for _, paramValue := range resp.Elements {
		respBytes = append(respBytes, paramValue.Type)
		defaultLog.Debugf("MarshalResponse: paramType - %d", paramValue.Type)
		respBytes = append(respBytes, GetLengthInBytes(int(paramValue.Length))...)
		defaultLog.Debugf("MarshalResponse: ParamLength - %d", int(paramValue.Length))
		respBytes = append(respBytes, paramValue.Payload...)
		defaultLog.Debugf("MarshalResponse: Payload value base64 - %s", base64.StdEncoding.EncodeToString(paramValue.Payload))
	}

	return respBytes
}

// UnmarshalRequest extracts VerifierAppRequest from a byte-array
func UnmarshalRequest(req []byte) domain.VerifierAppRequest {
	defaultLog.Trace("tcpmsglib:UnmarshalRequest() Entering")
	defer defaultLog.Trace("tcpmsglib:UnmarshalRequest() Leaving")

	var tar domain.VerifierAppRequest
	// get Request Type
	tar.RequestType = req[0]
	defaultLog.Debugf("UnmarshalRequest: RequestType - %d", tar.RequestType)

	// get Param Length
	tar.ParamLength = binary.BigEndian.Uint16(req[1:3])
	defaultLog.Debugf("UnmarshalRequest: ParamLength - %d", tar.ParamLength)

	var elements []domain.TenantAppMessageElement

	var curByte uint16 = 3
	for i := 0; i < int(tar.ParamLength); i++ {
		var te domain.TenantAppMessageElement
		te.Type = req[curByte]
		defaultLog.Debugf("UnmarshalRequest: Element %d | Type - %d", i, te.Type)
		curByte += 1
		te.Length = binary.BigEndian.Uint16(req[curByte : curByte+2])
		defaultLog.Debugf("UnmarshalRequest: Element %d | ParamLength - %d", i, te.Length)
		curByte += 2
		te.Payload = req[curByte : curByte+te.Length]
		curByte += te.Length
		defaultLog.Debugf("UnmarshalRequest: Element %d | Payload - %s", i, te.Payload)
		elements = append(elements, te)
	}

	tar.Elements = elements

	defaultLog.Debugf("UnmarshalRequest: Request return %v", tar)

	return tar
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
// UnmarshalResponse extracts TenantAppResponse from a byte-array
func UnmarshalResponse(msg []byte) (*domain.TenantAppResponse, error) {
	defaultLog.Trace("tcpmsglib:UnmarshalResponse() Entering")
	defer defaultLog.Trace("tcpmsglib:UnmarshalResponse() Leaving")

	var connectResponse domain.TenantAppResponse

	const minNumberOfBytes = 4
	// check for malformed/empty response body - all responses should contain these fields:
	// 1. Request Type  - 1 byte
	// 2. Response Code - 1 byte
	// 3. Number of Response Elements - 2 bytes
	// Any response less than 4 bytes will be dropped
	if len(msg) < minNumberOfBytes {
		if len(msg) < minNumberOfBytes {
			return nil, fmt.Errorf("tcpmsglib/UnmarshalResponse: malformed response body of insufficient length: %d", len(msg))
		}
	}

	// read Request RequestType
	connectResponse.RequestType = cast.ToUint8(msg[0])
	// response code
	connectResponse.RespCode = cast.ToUint8(msg[1])
	if connectResponse.RespCode != ResponseCodeSuccess && connectResponse.RespCode != ResponseCodeFailure {
		return &connectResponse, fmt.Errorf("tcpmsglib/UnmarshalResponse: invalid response type: %d", connectResponse.RespCode)
	}
	if connectResponse.RespCode == ResponseCodeFailure {
		return &connectResponse, fmt.Errorf("tcpmsglib/UnmarshalResponse: Request failed")
	}
	if connectResponse.RequestType == ReqTypeConnect {
		// length of request params
		lengthOfParams := binary.BigEndian.Uint16(msg[2:4])

		currentPosition := 4 // 0 - RequestType | 1 - ResponseCode | 2,3 - LengthOfParams
		var reList []domain.TenantAppMessageElement
		var i uint16
		// for each of the response elements
		for i = 0; i < lengthOfParams; i++ {
			var responseElement domain.TenantAppMessageElement
			// read the RE type
			responseElement.Type = msg[currentPosition]
			// validate
			if responseElement.Type != ResponseElementTypeSGXQuote &&
				responseElement.Type != ResponseElementTypeEnclavePubKey {
				return nil, fmt.Errorf("tcpmsglib/UnmarshalResponse: invalid response element type: %d", responseElement.Type)
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
	} else if connectResponse.RequestType != ReqTypePubkeyWrappedSWK && connectResponse.RequestType != ReqTypeSWKWrappedSecret {
		return &connectResponse, fmt.Errorf("tcpmsglib/UnmarshalResponse: Invalid request-response type")
	}

	defaultLog.Debugf("UnmarshalResponse: %v", connectResponse)
	return &connectResponse, nil
}

// GetLengthInBytes returns the binary version of an integer
func GetLengthInBytes(length int) []byte {
	defaultLog.Trace("tcpmsglib:GetLengthInBytes() Entering")
	defer defaultLog.Trace("tcpmsglib:GetLengthInBytes() Leaving")

	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, cast.ToUint16(length))
	return lengthBytes
}