/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <sgx_tcrypto.h>
#include <user_types.h>

// Needed for report generation.
#include "sgx_trts.h"
#include "sgx_error.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_tcrypto.h"

#include <iostream>
using namespace std;

#define SWK_KEY_SIZE 16

/*Global copy of RSA key pair */
static ref_rsa_params_t g_rsa_key;

/*Global copy of SWK */
static uint8_t *enclave_swk = NULL;
static size_t enclave_swk_size = 0;

/* Have we generated RSA key pair already? */
static bool key_pair_created = false;

/* Have we received SWK already? */
static bool swk_received = false;

int formatted_info_print(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);

    ocall_print_info_string(buf);

    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

sgx_status_t enclave_pubkey(ref_rsa_params_t* key) {
    sgx_status_t ret_code;
    key->e[0] = 0x10001;
    g_rsa_key.e[0] = 0x10001;
    
    if (!key_pair_created) {

        ret_code = sgx_create_rsa_key_pair(REF_N_SIZE_IN_BYTES,
                                           REF_E_SIZE_IN_BYTES,
                                           (unsigned char*)g_rsa_key.n,
                                           (unsigned char*)g_rsa_key.d,
                                           (unsigned char*)g_rsa_key.e,
                                           (unsigned char*)g_rsa_key.p,
                                           (unsigned char*)g_rsa_key.q,
                                           (unsigned char*)g_rsa_key.dmp1,
                                           (unsigned char*)g_rsa_key.dmq1,
                                           (unsigned char*)g_rsa_key.iqmp);

        if (ret_code != SGX_SUCCESS) {
            ocall_print_error_string("RSA key pair creation failed.");
            return ret_code;
        }
        key_pair_created = true;
    }
    
    for(int i=0; i<REF_N_SIZE_IN_BYTES; i++) {
        key->n[i] = g_rsa_key.n[i];
    }
    for(int i=0; i<REF_E_SIZE_IN_BYTES; i++) {
        key->e[i] = g_rsa_key.e[i];
    }

    return SGX_SUCCESS;
}

uint32_t enclave_create_report(const sgx_target_info_t* p_qe3_target, sgx_report_data_t* reportData, sgx_report_t* p_report) {

    const uint32_t size = REF_N_SIZE_IN_BYTES + REF_E_SIZE_IN_BYTES;

    uint8_t buffer[REF_N_SIZE_IN_BYTES + REF_E_SIZE_IN_BYTES];
    uint8_t* pdata = &buffer[0];
    ref_rsa_params_t key;
    key.e[0] = 0x10001;

    for(int i=0; i<REF_N_SIZE_IN_BYTES; i++) {
        key.n[i] = g_rsa_key.n[i];
    }
    for(int i=0; i<REF_E_SIZE_IN_BYTES; i++) {
        key.e[i] = g_rsa_key.e[i];
    }
    unsigned char* e1 = ((unsigned char *)key.e);
    unsigned char* m1 = ((unsigned char *)key.n);

    memcpy(pdata, e1, REF_E_SIZE_IN_BYTES);
    memcpy(pdata+REF_E_SIZE_IN_BYTES, m1, REF_N_SIZE_IN_BYTES);

    uint8_t msg_hash[64] = {0};
    sgx_status_t status = sgx_sha256_msg(pdata, size, (sgx_sha256_hash_t *)msg_hash);
    memcpy(reportData->d, msg_hash, sizeof(msg_hash));

    // Generate the report for the app_enclave
    sgx_status_t  sgx_error = sgx_create_report(p_qe3_target, reportData, p_report);

    return sgx_error;
}

sgx_status_t provision_swk_wrapped_secret(uint8_t* wrappedSecret, uint32_t wrappedSecretSize)
{
    /*
      wrappedSecret format :
      <IV:SGX_AESGCM_IV_SIZE><CipherText:n><MAC:SGX_AESGCM_MAC_SIZE>
    */

    sgx_status_t ret_code= SGX_SUCCESS;

    formatted_info_print ("Received wrappedSecret of size : %d", wrappedSecretSize);

    // We don't have the SWK yet!
    if (!swk_received) {
        ocall_print_error_string("We don't have the SWK yet!");
        return SGX_ERROR_UNEXPECTED;
    }

    // Plaintext Output Buffer.
    int plaintext_len = wrappedSecretSize - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
    uint8_t *plaintext = (uint8_t *) malloc (plaintext_len);
    
    // Cipher text 
    uint32_t cipher_text_len = wrappedSecretSize - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
    formatted_info_print ("Cipher Text Length : %d", cipher_text_len);

    // Copy of SWK
    sgx_aes_gcm_128bit_key_t *sk_key = (sgx_aes_gcm_128bit_key_t *)malloc (sizeof(sgx_aes_gcm_128bit_key_t));
    memcpy (sk_key, enclave_swk, SWK_KEY_SIZE);

    // Extract the MAC from the transmitted cipher text
    sgx_aes_gcm_128bit_tag_t mac;
    memcpy (mac, wrappedSecret + SGX_AESGCM_IV_SIZE+ plaintext_len, SGX_AESGCM_MAC_SIZE);
    
    // IV initialisation
    uint8_t iv_length = SGX_AESGCM_IV_SIZE;
    unsigned char iv[SGX_AESGCM_IV_SIZE];
    memcpy (iv, wrappedSecret, SGX_AESGCM_IV_SIZE);

    sgx_status_t dec_ret_code = sgx_rijndael128GCM_decrypt(sk_key, // Key
                                                           wrappedSecret + SGX_AESGCM_IV_SIZE, // Cipher text
                                                           cipher_text_len, //Cipher len
                                                           plaintext, // Plaintext 
                                                           iv, // Initialisation vector
                                                           iv_length, // IV Length
                                                           NULL, // AAD Buffer
                                                           0, // AAD Length
                                                           &mac); // MAC 

    if (SGX_SUCCESS != ret_code) {
        ocall_print_error_string("Secret decryption failed!");
        return ret_code;
    }

    uint8_t *plaintext_printable = (uint8_t *)malloc (plaintext_len);
    memcpy (plaintext_printable, plaintext, plaintext_len);
    plaintext_printable[plaintext_len] = '\0';

    formatted_info_print ("Secret in plain text : |%s|", plaintext_printable);

    ocall_print_info_string("Secret unwrapped successfully...");

    return SGX_SUCCESS;
}


sgx_status_t provision_pubkey_wrapped_swk(uint8_t* wrappedSWK, uint32_t wrappedSWKSize) 
{
    sgx_status_t ret_code= SGX_SUCCESS;
    size_t swk_size;
    
    // Build the private key.
    void *rsa_key = NULL;
    ret_code = sgx_create_rsa_priv2_key(REF_N_SIZE_IN_BYTES,
                                        REF_E_SIZE_IN_BYTES,
                                        (const unsigned char*)g_rsa_key.e,
                                        (const unsigned char*)g_rsa_key.p,
                                        (const unsigned char*)g_rsa_key.q,
                                        (const unsigned char*)g_rsa_key.dmp1,
                                        (const unsigned char*)g_rsa_key.dmq1,
                                        (const unsigned char*)g_rsa_key.iqmp,
                                        &rsa_key);

    if (SGX_SUCCESS != ret_code) {
        ocall_print_error_string("sgx_create_rsa_priv2_key - Unable to create private key");
        return ret_code;
    }

    // Unwrap using Private Key
    // Pass NULL to calculate the length of the output buffer.
    ret_code != sgx_rsa_priv_decrypt_sha256(rsa_key,
                                            NULL, ///Pointer to the output decrypted data buffer.
                                            &swk_size,///Length of the output decrypted data buffer.
                                            wrappedSWK,///Pointer to the input data buffer to be decrypted.
                                            wrappedSWKSize);

    if (SGX_SUCCESS != ret_code) {
        ocall_print_error_string("sgx_rsa_priv_decrypt_sha256 unable to calculate buffer size.");
        return ret_code;
    } 

    // Note : Somehow swk_size defaults to len (n) + len (p). We'll
    // snip the buffer when we get the right length. Bug ?
    unsigned char *decryptedBuffer = (unsigned char*)malloc(swk_size);

    if (decryptedBuffer == NULL) {
        ocall_print_error_string("malloc of decryptedBuffer failed!");
        return SGX_ERROR_UNEXPECTED;        
    }

    ret_code = sgx_rsa_priv_decrypt_sha256(rsa_key,
                                           decryptedBuffer,//Pointer to the output decrypted data buffer.
                                           &swk_size, //Length of the output decrypted data buffer.
                                           wrappedSWK, //Pointer to the input data buffer to be decrypted.
                                           wrappedSWKSize); //size of input data buffer.

    if (ret_code != SGX_SUCCESS) {
        ocall_print_error_string("Decrypt failed. Check error code.");
        return ret_code;
    }

    // Global copy.
    enclave_swk = (uint8_t*) malloc (swk_size);
    memcpy(enclave_swk, decryptedBuffer, swk_size);
    enclave_swk_size = swk_size;

    swk_received = true;

    ocall_print_info_string("Sucessfully decrypted SWK.");
    
    return SGX_SUCCESS;
}
