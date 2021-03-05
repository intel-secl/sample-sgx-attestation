/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

// Standard RSA key component sizes.
#define EXP_SIZE_IN_BYTES 4
#define MOD_SIZE_IN_BYTES 384

int pub_encrypt_sha256(EVP_PKEY *rsa_key, unsigned char* pout_data,
                       size_t* pout_len, const unsigned char* pin_data,
                       const size_t pin_len)
{

    if (rsa_key == NULL || pout_len == NULL || pin_data == NULL || pin_len < 1 || pin_len >= INT_MAX)
    {
        return -1;
    }

    EVP_PKEY_CTX *ctx = NULL;
    size_t data_len = 0;
    int ret_code = -1;

    do
    {
        // Allocate and init PKEY_CTX
        ctx = EVP_PKEY_CTX_new((EVP_PKEY*)rsa_key, NULL);
        if ((ctx == NULL) || (EVP_PKEY_encrypt_init(ctx) < 1))
        {
            break;
        }

        // Set the RSA padding mode. Init it to use SHA256
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

        if (EVP_PKEY_encrypt(ctx, NULL, &data_len, pin_data, pin_len) <= 0)
        {
            break;
        }

        if(pout_data == NULL)
        {
            *pout_len = data_len;
            ret_code = 0;
            break;
        }

        else if(*pout_len < data_len)
        {
            ret_code = -1;
            break;
        }

        if (EVP_PKEY_encrypt(ctx, pout_data, pout_len, pin_data, pin_len) <= 0)
        {
            break;
        }

        ret_code = 0;
    }
    while (0);

    EVP_PKEY_CTX_free(ctx);

    return ret_code;
}

uint8_t* sc_encrypt_swk (uint8_t *raw_key, uint8_t *swk, int swkSize, int *encrypted_len) 
{
    int status = 0;

    unsigned char *raw_exponent = malloc (EXP_SIZE_IN_BYTES);
    memcpy (raw_exponent, raw_key, EXP_SIZE_IN_BYTES);
    unsigned char *raw_modulus = malloc (MOD_SIZE_IN_BYTES);
    memcpy (raw_modulus, raw_key + EXP_SIZE_IN_BYTES, MOD_SIZE_IN_BYTES);

    //BIGNUM for mod and exp 
    BIGNUM *modulus = BN_new();
    BN_lebin2bn((const unsigned char*)raw_modulus, MOD_SIZE_IN_BYTES, modulus);        

    BIGNUM *exponent = BN_new();
    BN_lebin2bn((const unsigned char*)raw_exponent, EXP_SIZE_IN_BYTES, exponent);        

    //Create a OPENSSL key
    EVP_PKEY *evp_pub_key = EVP_PKEY_new();
    RSA *evp_rsa_key = RSA_new();
    RSA_set0_key (evp_rsa_key, modulus, exponent, NULL);
    EVP_PKEY_assign_RSA(evp_pub_key, evp_rsa_key);

    printf ("libencrypt(C) : Size of unencrypted SWK : %d\n", swkSize);

    size_t encrypted_swk_len;
    // Run it once with out output buffer to calculate its length
    status = pub_encrypt_sha256(evp_pub_key, NULL, &encrypted_swk_len, swk, (size_t)swkSize);
    if ( status != 0) {
      printf("libencrypt(C) : Output buffer calculation failed : %d\n", status);
      return NULL;
    }
    
    uint8_t *encrypted_swk = (uint8_t *)malloc (encrypted_swk_len);

    status = pub_encrypt_sha256(evp_pub_key, encrypted_swk, &encrypted_swk_len, swk, (size_t)swkSize);
    if ( status != 0) {
      printf("libencrypt(C) : Encryption failed : %d\n", status);
      return NULL;
    }

    *encrypted_len = encrypted_swk_len;
    printf("libencrypt(C) : Encryption successful.\n");

    return encrypted_swk;
}
