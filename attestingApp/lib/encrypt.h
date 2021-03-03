#ifndef __ENCRYPT_H_
#define __ENCRYPT_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_defs.h"     /* sgx_enclave_id_t */

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if defined(__cplusplus)
extern "C" {
#endif
  uint8_t* sc_encrypt_swk (uint8_t *raw_key, uint8_t *swk,
			   int swkSize, int *encrypted_len);

  int pub_encrypt_sha256(const void* rsa_key, unsigned char* pout_data,
			 size_t* pout_len, const unsigned char* pin_data,
			 const size_t pin_len);

  #if defined(__cplusplus)
}
#endif

#endif /* _ENCRYPT_H__ */
