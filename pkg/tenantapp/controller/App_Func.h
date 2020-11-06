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


#ifndef _APP_FUN_H_
#define _APP_FUN_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_defs.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

/*#define REF_N_SIZE_IN_BYTES    384
#define REF_E_SIZE_IN_BYTES    4
#define REF_D_SIZE_IN_BYTES    384
#define REF_P_SIZE_IN_BYTES    192
#define REF_Q_SIZE_IN_BYTES    192
#define REF_DMP1_SIZE_IN_BYTES 192
#define REF_DMQ1_SIZE_IN_BYTES 192
#define REF_IQMP_SIZE_IN_BYTES 192

#define REF_N_SIZE_IN_UINT     REF_N_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_E_SIZE_IN_UINT     REF_E_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_D_SIZE_IN_UINT     REF_D_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_P_SIZE_IN_UINT     REF_P_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_Q_SIZE_IN_UINT     REF_Q_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_DMP1_SIZE_IN_UINT  REF_DMP1_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_DMQ1_SIZE_IN_UINT  REF_DMQ1_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_IQMP_SIZE_IN_UINT  REF_IQMP_SIZE_IN_BYTES/sizeof(unsigned int)


typedef struct _ref_rsa_params_t {
    unsigned int n[REF_N_SIZE_IN_UINT];
    unsigned int e[REF_E_SIZE_IN_UINT];
    unsigned int d[REF_D_SIZE_IN_UINT];
    unsigned int p[REF_P_SIZE_IN_UINT];
    unsigned int q[REF_Q_SIZE_IN_UINT];
    unsigned int dmp1[REF_DMP1_SIZE_IN_UINT];
    unsigned int dmq1[REF_DMQ1_SIZE_IN_UINT];
    unsigned int iqmp[REF_IQMP_SIZE_IN_UINT];
}ref_rsa_params_t;*/

extern sgx_enclave_id_t global_eid;    /* global enclave id */

void print_error_message(sgx_status_t ret);
int initialize_enclave(void);


int get_Key();
uint8_t* get_SGX_Quote(int* x);
void unwrap_SWK();
void unwrap_Secret();

int SGX_CDECL init(bool argc);

#if defined(__cplusplus)
extern "C" {
#endif

//void ocall_print_string(const char *str);
//void ocall_print_string1(const char *str);

/*void edger8r_array_attributes(void);
void edger8r_type_attributes(void);
void edger8r_pointer_attributes(void);
void edger8r_function_attributes(void);

void ecall_libc_functions(void);
void ecall_libcxx_functions(void);
void ecall_thread_functions(void);*/

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_FUN_H_ */

