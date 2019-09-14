#ifndef CRYPTO_ENGINE_T_H__
#define CRYPTO_ENGINE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void generateRSAKeyPair(char* RSAPublicKey, char* RSAPrivateKey, size_t RSAKeysLength);
void SGXEncryptRSA(const char* public_key, size_t public_key_length, const char* plaintext, size_t plaintext_length, char* ciphertext, size_t ciphertext_length, int* cipherTextLength);
void SGXDecryptRSA(const char* private_key_ciphered, size_t private_key_ciphered_length, const char* ciphertext, size_t ciphertext_length, char* plaintext, size_t plaintext_length, int* plainTextLength);

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
