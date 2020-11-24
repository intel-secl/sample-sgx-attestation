/*
 * Copyright (C) 2020-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define __STDC_WANT_LIB_EXT1__ 1

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include<iostream>
#include<fstream>
#include<user_types.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "sgx_report.h"
#include "sgx_error.h"
#include "sgx_quote_3.h"

#include "App_Func.h"
#include "Enclave_u.h"
#include "sgx_pce.h"
#include "sgx_dcap_ql_wrapper.h"
#include <sgx_tcrypto.h>

using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_status_t status = SGX_SUCCESS;
bool mode = true;

u_int32_t major_no = 1;
u_int32_t minor_no = 0;

static ref_rsa_params_t g_rsa_key;

typedef struct CK_RSA_PUBLIC_KEY_PARAMS {
	long ulExponentLen;
	long ulModulusLen;
} CK_RSA_PUBLIC_KEY_PARAMS;


typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char *msg;
	const char *sug; /* Suggestion */
} sgx_errlist_t;

typedef struct ecdsa_quote_verify_data
{
	u_int32_t  pckCert_size;
}ecdsa_quote_verify_data;

typedef struct sw_quote_verify_data{
	u_int32_t dummy;
}sw_quote_verify_data;

typedef union qdetails {
	ecdsa_quote_verify_data ecdsa_quote_details;
	sw_quote_verify_data sw_quto_details;
}apimodule_quote_details;


struct keyagent_sgx_quote_info {
	u_int32_t major_num;
	u_int32_t minor_num;
	u_int32_t quote_size;
	u_int32_t quote_type;
	u_int32_t keytype;
	union {
		struct {
			u_int32_t exponent_len;
			u_int32_t modulus_len;
		}rsa;
		struct {
			u_int32_t dummy;
		}ec;
	}keydetails;
	apimodule_quote_details quote_details;
};

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
	{
		SGX_ERROR_UNEXPECTED,
		"Unexpected error occurred.",
		NULL
	},
	{
		SGX_ERROR_INVALID_PARAMETER,
		"Invalid parameter.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_MEMORY,
		"Out of memory.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_LOST,
		"Power transition occurred.",
		"Please refer to the sample \"PowerTransition\" for details."
	},
	{
		SGX_ERROR_INVALID_ENCLAVE,
		"Invalid enclave image.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ENCLAVE_ID,
		"Invalid enclave identification.",
		NULL
	},
	{
		SGX_ERROR_INVALID_SIGNATURE,
		"Invalid enclave signature.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_EPC,
		"Out of EPC memory.",
		NULL
	},
	{
		SGX_ERROR_NO_DEVICE,
		"Invalid SGX device.",
		"Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
	},
	{
		SGX_ERROR_MEMORY_MAP_CONFLICT,
		"Memory map conflicted.",
		NULL
	},
	{
		SGX_ERROR_INVALID_METADATA,
		"Invalid enclave metadata.",
		NULL
	},
	{
		SGX_ERROR_DEVICE_BUSY,
		"SGX device was busy.",
		NULL
	},
	{
		SGX_ERROR_INVALID_VERSION,
		"Enclave version was invalid.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ATTRIBUTE,
		"Enclave was not authorized.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_FILE_ACCESS,
		"Can't open enclave file.",
		NULL
	},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
	cout << "initializing enclave" << endl;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
	/* Call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	cout << "ENCLAVE_FILENAME: " << ENCLAVE_FILENAME << "\t" << SGX_DEBUG_FLAG << "\t" << &global_eid << endl;
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
	cout << "return code: " << "\t" << ret <<endl;

	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
		return -1;
	}
	return 0;
}

int destroy_Enclave() {
	cout << "destroying enclave" <<endl;

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    // return 0 on successful destroy
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s\n", str);
}

void ocall_print_string1(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s\n", str);
}

int get_Key()
{
	if (mode ==true) {
		printf("Current mode is standalone mode.\n");
		return 0;
	}

	int count;
	enclave_pubkey(global_eid, &status, &g_rsa_key, &count);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		return -1;
	}
	return 0;
}

uint8_t* get_SGX_Quote(int* x) {
	if (mode ==true) {
		printf("Getting quote in standalone mode\n");
		FILE *fptr = NULL;
		fptr = fopen("/tmp/quote.dat","rb");
		if (fptr==NULL) {cout << "cant open quote.dat file\n"<< endl; return 0; }

		// obtain file size:
		fseek (fptr, 0 , SEEK_END);
		int lSize = ftell (fptr);
		*x = lSize;
		cout << "quote size: " << lSize << endl;
		rewind (fptr);

		// allocate memory to contain the whole file:
		uint8_t* buffer = (uint8_t*) malloc(lSize);
		if (buffer == NULL) {cout << "error in creating buffer for quote." << endl; return 0;}

		// copy the file into the buffer:
		size_t result = fread (buffer,1,lSize,fptr);
		if (result != lSize) {cout << "error in  reading quote." << endl; return 0;}
		return buffer;
	} else {
					/*
					 * Following code is use din Non StandAlone Mode. This mode will
					 * be used in future releases.
					 */
					cout << "generating quote in non stand alone mode" << endl;
					int ret = 0;
					uint32_t retval = 0;
					quote3_error_t qe3_ret = SGX_QL_SUCCESS;
					uint32_t quote_size = 0;
					uint8_t* p_quote_buffer = NULL;
					sgx_target_info_t qe_target_info;
					sgx_report_t app_report;
					sgx_report_data_t reportData{};
					sgx_quote3_t *p_quote;
					sgx_ql_auth_data_t *p_auth_data;
					sgx_ql_ecdsa_sig_data_t *p_sig_data;
					sgx_ql_certification_data_t *p_cert_data;
					FILE *fptr = NULL;

					CK_RSA_PUBLIC_KEY_PARAMS rsaPublicKeyParams{};

					qe3_ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
					if(SGX_QL_SUCCESS != qe3_ret) {
									printf("Error in set enclave load policy: 0x%04x\n", qe3_ret);
									ret = -1;
					}
					printf("successful in setting load policy!\n");
					qe3_ret = sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib64/libsgx_pce.signed.so");
					if(SGX_QL_SUCCESS != qe3_ret) {
									printf("Error in set PCE directory: 0x%04x.\n", qe3_ret);
									ret = -1;
					}
					qe3_ret = sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib64/libsgx_qe3.signed.so");
					if(SGX_QL_SUCCESS != qe3_ret) {
									printf("Error in set QE3 directory: 0x%04x.\n", qe3_ret);
									ret = -1;
					}
					qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib64/libdcap_quoteprov.so.1");
					if(SGX_QL_SUCCESS != qe3_ret) {
									printf("Info: /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1 not found.\n");
					}
					printf("\nStep1: Call sgx_qe_get_target_info:");
					qe3_ret = sgx_qe_get_target_info(&qe_target_info);
					if (SGX_QL_SUCCESS != qe3_ret) {
									printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
									ret = -1;
					}
					printf("succeed!");

					printf("\nStep3: Call sgx_qe_get_quote_size:");
					qe3_ret = sgx_qe_get_quote_size(&quote_size);
					if (SGX_QL_SUCCESS != qe3_ret) {
									printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
									ret = -1;
					}
					printf("succeed quote_size: %d\n", quote_size);

					p_quote_buffer = (uint8_t*)malloc(REF_E_SIZE_IN_BYTES+ REF_N_SIZE_IN_BYTES + sizeof(rsaPublicKeyParams) + quote_size);
					if (NULL == p_quote_buffer) {
									printf("Couldn't allocate quote_buffer\n");
									ret = -1;
					}
					memset(p_quote_buffer, 0, quote_size);

					rsaPublicKeyParams.ulExponentLen = REF_E_SIZE_IN_BYTES;
					rsaPublicKeyParams.ulModulusLen = REF_N_SIZE_IN_BYTES;
					const char* exponent = (const char *)g_rsa_key.e;
					const char* modulus = (const char *)g_rsa_key.n;

					memcpy(p_quote_buffer, &rsaPublicKeyParams, sizeof(rsaPublicKeyParams));
					memcpy(p_quote_buffer+sizeof(CK_RSA_PUBLIC_KEY_PARAMS), exponent, REF_N_SIZE_IN_BYTES);
					memcpy(p_quote_buffer+sizeof(CK_RSA_PUBLIC_KEY_PARAMS) + REF_N_SIZE_IN_BYTES, modulus, REF_E_SIZE_IN_BYTES);

					int offset = sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
					const uint32_t publicKeyBufferSize = REF_N_SIZE_IN_BYTES+ REF_E_SIZE_IN_BYTES+ sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
					const uint32_t publicKeyBufferSize1 = REF_N_SIZE_IN_BYTES+ REF_E_SIZE_IN_BYTES ;

					uint8_t msg_hash[64] = {0};
					status = sgx_sha256_msg(p_quote_buffer+offset, publicKeyBufferSize1, (sgx_sha256_hash_t *)msg_hash);
					memcpy(reportData.d, msg_hash, sizeof(msg_hash));

					printf("\nStep2: Call create_app_report:");
					status = enclave_create_report(global_eid,
													&retval,
													&qe_target_info,&reportData,
													&app_report);
					if ((SGX_SUCCESS != status) || (0 != retval)) {
									printf("\nCall to get_app_enclave_report() failed\n");
									ret = false;
					}

					// Get the Quote
					printf("\nStep4: Call sgx_qe_get_quote\n");
					qe3_ret = sgx_qe_get_quote(&app_report,
													quote_size,
													p_quote_buffer+publicKeyBufferSize);
					if (SGX_QL_SUCCESS != qe3_ret) {
									printf( "Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
									ret = -1;
					}

					CK_RSA_PUBLIC_KEY_PARAMS* rsaPublicKeyParam_ = (CK_RSA_PUBLIC_KEY_PARAMS*)(p_quote_buffer);

					p_quote = (_sgx_quote3_t*)(p_quote_buffer+publicKeyBufferSize);
					p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
					p_auth_data = (sgx_ql_auth_data_t*)p_sig_data->auth_certification_data;
					p_cert_data = (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);


					printf("cert_key_type = 0x%x\n", p_cert_data->cert_key_type);
					printf("cert_key_type = %d\n", p_cert_data->cert_key_type);

					uint32_t certSize = p_cert_data->size;
					uint32_t* cert_information = NULL;
					cert_information = (uint32_t*)malloc(certSize);
					if (NULL == cert_information) {
									printf("Couldn't allocate cert_information buffer\n");
									ret = -1;
					}
					memset(cert_information, 0, certSize);
					memcpy(cert_information, (unsigned char*)( p_cert_data->certification_data), certSize);

					// Fetch PCK Certificate from PCK Cert chain. PCK is the 1st certificate in the chain.
					// Hence we will fetch it by getting the position of the ending of PCK and copying it.
					std::string pckCert;
					std::size_t pckPos1, pckPos2;
					const char* certificate_pattern = "-----BEGIN CERTIFICATE-----";
					// Whole PCK chain in quote from which PCK cert will be fetched.
					std::string certificate_str((const char*)(cert_information));
					pckPos1 = certificate_str.find(certificate_pattern);
					if(pckPos1 != std::string::npos) {
									pckPos2 = certificate_str.find(certificate_pattern, pckPos1 + 1);
									if(pckPos2 != std::string::npos) {
													pckCert = certificate_str.substr(pckPos1, pckPos2);
									}
					} else {
									printf("pck certificate could not be fetched");
					}
					const std::size_t pckCertSize = pckPos2;

					struct keyagent_sgx_quote_info quote_info = {
									.major_num = major_no,
									.minor_num = minor_no,
									.quote_size = quote_size +REF_N_SIZE_IN_BYTES+REF_E_SIZE_IN_BYTES,
									.quote_type = 1,
									.keytype = 1,
									.keydetails = {
													.rsa = {
																	.exponent_len = (u_int32_t)rsaPublicKeyParam_->ulExponentLen,
																	.modulus_len = (u_int32_t)rsaPublicKeyParam_->ulModulusLen
													},
									},
									.quote_details = {
													.ecdsa_quote_details = {
																	.pckCert_size =  (u_int32_t)pckCertSize,
													},
									}
					};

					uint8_t* challenge_final = NULL;
					challenge_final = (uint8_t*)malloc((sizeof(quote_info)+pckCertSize+quote_size+REF_N_SIZE_IN_BYTES+REF_E_SIZE_IN_BYTES));

					memcpy(challenge_final,(uint8_t*)&quote_info, sizeof(quote_info));
					memcpy(challenge_final+sizeof(quote_info), (char *)(pckCert.c_str()), pckCertSize);
					memcpy(challenge_final+sizeof(quote_info)+pckCertSize, p_quote_buffer+sizeof(CK_RSA_PUBLIC_KEY_PARAMS), quote_size+REF_N_SIZE_IN_BYTES+REF_E_SIZE_IN_BYTES);
					uint8_t* publicKey = NULL;
					publicKey = (uint8_t*)malloc(REF_N_SIZE_IN_BYTES+REF_E_SIZE_IN_BYTES);
					memcpy(publicKey, challenge_final+sizeof(quote_info)+pckCertSize+sizeof(CK_RSA_PUBLIC_KEY_PARAMS), 388);

					fptr = fopen("quote.dat","wb");
					if( fptr )
					{
									fwrite(challenge_final, sizeof(quote_info)+pckCertSize+quote_size+REF_E_SIZE_IN_BYTES+REF_N_SIZE_IN_BYTES, 1, fptr);
									fclose(fptr);
					}

					printf("sgx_qe_cleanup_by_policy is valid in in-proc mode only.\n");
					printf("\n Clean up the enclave load policy:");
					qe3_ret = sgx_qe_cleanup_by_policy();
					if(SGX_QL_SUCCESS != qe3_ret) {
									printf("Error in cleanup enclave load policy: 0x%04x\n", qe3_ret);
									ret = -1;
					}
					printf("succeed!\n");
					*x = sizeof(quote_info)+pckCertSize+quote_size+REF_E_SIZE_IN_BYTES+REF_N_SIZE_IN_BYTES;
					return challenge_final;
	}
}

void unwrap_SWK(){
	if (mode == true) {
		printf("Passing wrapped SWK to enclave. SWK is unwrapped inside enclave.\n");
	}
}

void unwrap_Secret(){
	if (mode == true) {
		printf("Passing wrapped secret to enclave. Secret is unwrapped inside enclave.\n");
	}
}

/* Application entry */
int SGX_CDECL init(bool argc)
{
    printf("init called\n");
    mode = argc;

    printf("mode is: %d\n", mode);

    /* Following code is for Non StandAlone mode that will be used in 3.3 release.
     * Initialize the enclave 
     * */
    if(initialize_enclave() < 0){
        return -1; 
    }
    cout << "enclave id: " << global_eid <<endl;
 
    printf("Info: SampleEnclave successfully returned.\n");

    return 0;
}
