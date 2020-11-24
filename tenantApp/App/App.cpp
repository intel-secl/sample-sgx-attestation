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

# include <unistd.h>
# include <pwd.h>
# include <sgx_defs.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_error.h"
#include "App_Func.h"
#include "sgx_urts.h"

using namespace std;

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
	cout << "App starting" << endl;

    (void)(argc);
    (void)(argv);

    int status = 0;
    status = init(false);
		
if (status != 0) {
	cout << "failed to initialize enclave" << endl;
	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}

    ///Ecalls will come here. Call here and defins in enclave.cpp
    status = get_Key();
    int size = 0;
    uint8_t* quote = get_SGX_Quote(&size);
    printf("size of quote is: %d\n", size);
    uint8_t* p_quote = (uint8_t*)malloc(size);
    memcpy(p_quote, quote, size);

    unwrap_SWK();
    unwrap_Secret();

    destroy_Enclave();

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

