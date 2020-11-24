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

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <sgx_tcrypto.h>
#include <user_types.h>

///Following is needed for report generation.
#include "sgx_trts.h"
#include "sgx_error.h"
#include "sgx_report.h"
#include "sgx_utils.h"

#include <iostream>
using namespace std;



/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

sgx_status_t enclave_pubkey(ref_rsa_params_t* g_rsa_key, int* count) {

	g_rsa_key->e[0] = 0x10001;
	sgx_status_t ret_code = sgx_create_rsa_key_pair(REF_N_SIZE_IN_BYTES,
            REF_E_SIZE_IN_BYTES,
	    (unsigned char*)g_rsa_key->n,
	    (unsigned char*)g_rsa_key->d,
	    (unsigned char*)g_rsa_key->e,
	    (unsigned char*)g_rsa_key->p,
	    (unsigned char*)g_rsa_key->q,
	    (unsigned char*)g_rsa_key->dmp1,
	    (unsigned char*)g_rsa_key->dmq1,
	    (unsigned char*)g_rsa_key->iqmp);

        if (ret_code != SGX_SUCCESS) {
		return ret_code;
        }

	return SGX_SUCCESS;
}

uint32_t enclave_create_report(const sgx_target_info_t* p_qe3_target, const sgx_report_data_t* reportData, sgx_report_t* p_report) {

    // Generate the report for the app_enclave
    sgx_status_t  sgx_error = sgx_create_report(p_qe3_target, reportData, p_report);

    return sgx_error;

}
