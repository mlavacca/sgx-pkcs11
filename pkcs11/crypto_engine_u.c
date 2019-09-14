#include "crypto_engine_u.h"
#include <errno.h>

typedef struct ms_generateRSAKeyPair_t {
	char* ms_RSAPublicKey;
	char* ms_RSAPrivateKey;
	size_t ms_RSAKeysLength;
} ms_generateRSAKeyPair_t;

typedef struct ms_SGXEncryptRSA_t {
	const char* ms_public_key;
	size_t ms_public_key_length;
	const char* ms_plaintext;
	size_t ms_plaintext_length;
	char* ms_ciphertext;
	size_t ms_ciphertext_length;
	int* ms_cipherTextLength;
} ms_SGXEncryptRSA_t;

typedef struct ms_SGXDecryptRSA_t {
	const char* ms_private_key_ciphered;
	size_t ms_private_key_ciphered_length;
	const char* ms_ciphertext;
	size_t ms_ciphertext_length;
	char* ms_plaintext;
	size_t ms_plaintext_length;
	int* ms_plainTextLength;
} ms_SGXDecryptRSA_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL crypto_engine_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL crypto_engine_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL crypto_engine_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL crypto_engine_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL crypto_engine_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL crypto_engine_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[6];
} ocall_table_crypto_engine = {
	6,
	{
		(void*)crypto_engine_u_sgxssl_ftime,
		(void*)crypto_engine_sgx_oc_cpuidex,
		(void*)crypto_engine_sgx_thread_wait_untrusted_event_ocall,
		(void*)crypto_engine_sgx_thread_set_untrusted_event_ocall,
		(void*)crypto_engine_sgx_thread_setwait_untrusted_events_ocall,
		(void*)crypto_engine_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t generateRSAKeyPair(sgx_enclave_id_t eid, char* RSAPublicKey, char* RSAPrivateKey, size_t RSAKeysLength)
{
	sgx_status_t status;
	ms_generateRSAKeyPair_t ms;
	ms.ms_RSAPublicKey = RSAPublicKey;
	ms.ms_RSAPrivateKey = RSAPrivateKey;
	ms.ms_RSAKeysLength = RSAKeysLength;
	status = sgx_ecall(eid, 0, &ocall_table_crypto_engine, &ms);
	return status;
}

sgx_status_t SGXEncryptRSA(sgx_enclave_id_t eid, const char* public_key, size_t public_key_length, const char* plaintext, size_t plaintext_length, char* ciphertext, size_t ciphertext_length, int* cipherTextLength)
{
	sgx_status_t status;
	ms_SGXEncryptRSA_t ms;
	ms.ms_public_key = public_key;
	ms.ms_public_key_length = public_key_length;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_length = plaintext_length;
	ms.ms_ciphertext = ciphertext;
	ms.ms_ciphertext_length = ciphertext_length;
	ms.ms_cipherTextLength = cipherTextLength;
	status = sgx_ecall(eid, 1, &ocall_table_crypto_engine, &ms);
	return status;
}

sgx_status_t SGXDecryptRSA(sgx_enclave_id_t eid, const char* private_key_ciphered, size_t private_key_ciphered_length, const char* ciphertext, size_t ciphertext_length, char* plaintext, size_t plaintext_length, int* plainTextLength)
{
	sgx_status_t status;
	ms_SGXDecryptRSA_t ms;
	ms.ms_private_key_ciphered = private_key_ciphered;
	ms.ms_private_key_ciphered_length = private_key_ciphered_length;
	ms.ms_ciphertext = ciphertext;
	ms.ms_ciphertext_length = ciphertext_length;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_length = plaintext_length;
	ms.ms_plainTextLength = plainTextLength;
	status = sgx_ecall(eid, 2, &ocall_table_crypto_engine, &ms);
	return status;
}

