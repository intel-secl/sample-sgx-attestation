/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
*/
#ifndef _APP_FUN_H_
#define _APP_FUN_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

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

extern sgx_enclave_id_t global_eid;    /* global enclave id */

void print_error_message(sgx_status_t ret);
int initialize_enclave(void);


int get_Key();
uint8_t* get_SGX_Quote(int* x);
void unwrap_SWK();
void unwrap_Secret();

int SGX_CDECL init(bool argc, char *argv[]);

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
