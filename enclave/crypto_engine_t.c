#include "crypto_engine_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_generateRSAKeyPair(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generateRSAKeyPair_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generateRSAKeyPair_t* ms = SGX_CAST(ms_generateRSAKeyPair_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_RSAPublicKey = ms->ms_RSAPublicKey;
	size_t _tmp_RSAKeysLength = ms->ms_RSAKeysLength;
	size_t _len_RSAPublicKey = _tmp_RSAKeysLength * sizeof(char);
	char* _in_RSAPublicKey = NULL;
	char* _tmp_RSAPrivateKey = ms->ms_RSAPrivateKey;
	size_t _len_RSAPrivateKey = _tmp_RSAKeysLength * sizeof(char);
	char* _in_RSAPrivateKey = NULL;

	if (sizeof(*_tmp_RSAPublicKey) != 0 &&
		(size_t)_tmp_RSAKeysLength > (SIZE_MAX / sizeof(*_tmp_RSAPublicKey))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_RSAPrivateKey) != 0 &&
		(size_t)_tmp_RSAKeysLength > (SIZE_MAX / sizeof(*_tmp_RSAPrivateKey))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_RSAPublicKey, _len_RSAPublicKey);
	CHECK_UNIQUE_POINTER(_tmp_RSAPrivateKey, _len_RSAPrivateKey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_RSAPublicKey != NULL && _len_RSAPublicKey != 0) {
		if ( _len_RSAPublicKey % sizeof(*_tmp_RSAPublicKey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_RSAPublicKey = (char*)malloc(_len_RSAPublicKey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_RSAPublicKey, 0, _len_RSAPublicKey);
	}
	if (_tmp_RSAPrivateKey != NULL && _len_RSAPrivateKey != 0) {
		if ( _len_RSAPrivateKey % sizeof(*_tmp_RSAPrivateKey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_RSAPrivateKey = (char*)malloc(_len_RSAPrivateKey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_RSAPrivateKey, 0, _len_RSAPrivateKey);
	}

	generateRSAKeyPair(_in_RSAPublicKey, _in_RSAPrivateKey, _tmp_RSAKeysLength);
	if (_in_RSAPublicKey) {
		if (memcpy_s(_tmp_RSAPublicKey, _len_RSAPublicKey, _in_RSAPublicKey, _len_RSAPublicKey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_RSAPrivateKey) {
		if (memcpy_s(_tmp_RSAPrivateKey, _len_RSAPrivateKey, _in_RSAPrivateKey, _len_RSAPrivateKey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_RSAPublicKey) free(_in_RSAPublicKey);
	if (_in_RSAPrivateKey) free(_in_RSAPrivateKey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_SGXEncryptRSA(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_SGXEncryptRSA_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_SGXEncryptRSA_t* ms = SGX_CAST(ms_SGXEncryptRSA_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_public_key = ms->ms_public_key;
	size_t _tmp_public_key_length = ms->ms_public_key_length;
	size_t _len_public_key = _tmp_public_key_length * sizeof(char);
	char* _in_public_key = NULL;
	const char* _tmp_plaintext = ms->ms_plaintext;
	size_t _tmp_plaintext_length = ms->ms_plaintext_length;
	size_t _len_plaintext = _tmp_plaintext_length * sizeof(char);
	char* _in_plaintext = NULL;
	char* _tmp_ciphertext = ms->ms_ciphertext;
	size_t _tmp_ciphertext_length = ms->ms_ciphertext_length;
	size_t _len_ciphertext = _tmp_ciphertext_length * sizeof(char);
	char* _in_ciphertext = NULL;
	int* _tmp_cipherTextLength = ms->ms_cipherTextLength;
	size_t _len_cipherTextLength = 1 * sizeof(int);
	int* _in_cipherTextLength = NULL;

	if (sizeof(*_tmp_public_key) != 0 &&
		(size_t)_tmp_public_key_length > (SIZE_MAX / sizeof(*_tmp_public_key))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_plaintext) != 0 &&
		(size_t)_tmp_plaintext_length > (SIZE_MAX / sizeof(*_tmp_plaintext))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_ciphertext) != 0 &&
		(size_t)_tmp_ciphertext_length > (SIZE_MAX / sizeof(*_tmp_ciphertext))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_cipherTextLength) != 0 &&
		1 > (SIZE_MAX / sizeof(*_tmp_cipherTextLength))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_public_key, _len_public_key);
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_ciphertext, _len_ciphertext);
	CHECK_UNIQUE_POINTER(_tmp_cipherTextLength, _len_cipherTextLength);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_public_key != NULL && _len_public_key != 0) {
		if ( _len_public_key % sizeof(*_tmp_public_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_public_key = (char*)malloc(_len_public_key);
		if (_in_public_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_public_key, _len_public_key, _tmp_public_key, _len_public_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_plaintext = (char*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plaintext, _len_plaintext, _tmp_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ciphertext != NULL && _len_ciphertext != 0) {
		if ( _len_ciphertext % sizeof(*_tmp_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ciphertext = (char*)malloc(_len_ciphertext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ciphertext, 0, _len_ciphertext);
	}
	if (_tmp_cipherTextLength != NULL && _len_cipherTextLength != 0) {
		if ( _len_cipherTextLength % sizeof(*_tmp_cipherTextLength) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_cipherTextLength = (int*)malloc(_len_cipherTextLength)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cipherTextLength, 0, _len_cipherTextLength);
	}

	SGXEncryptRSA((const char*)_in_public_key, _tmp_public_key_length, (const char*)_in_plaintext, _tmp_plaintext_length, _in_ciphertext, _tmp_ciphertext_length, _in_cipherTextLength);
	if (_in_ciphertext) {
		if (memcpy_s(_tmp_ciphertext, _len_ciphertext, _in_ciphertext, _len_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_cipherTextLength) {
		if (memcpy_s(_tmp_cipherTextLength, _len_cipherTextLength, _in_cipherTextLength, _len_cipherTextLength)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_public_key) free(_in_public_key);
	if (_in_plaintext) free(_in_plaintext);
	if (_in_ciphertext) free(_in_ciphertext);
	if (_in_cipherTextLength) free(_in_cipherTextLength);
	return status;
}

static sgx_status_t SGX_CDECL sgx_SGXDecryptRSA(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_SGXDecryptRSA_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_SGXDecryptRSA_t* ms = SGX_CAST(ms_SGXDecryptRSA_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_private_key_ciphered = ms->ms_private_key_ciphered;
	size_t _tmp_private_key_ciphered_length = ms->ms_private_key_ciphered_length;
	size_t _len_private_key_ciphered = _tmp_private_key_ciphered_length * sizeof(char);
	char* _in_private_key_ciphered = NULL;
	const char* _tmp_ciphertext = ms->ms_ciphertext;
	size_t _tmp_ciphertext_length = ms->ms_ciphertext_length;
	size_t _len_ciphertext = _tmp_ciphertext_length * sizeof(char);
	char* _in_ciphertext = NULL;
	char* _tmp_plaintext = ms->ms_plaintext;
	size_t _tmp_plaintext_length = ms->ms_plaintext_length;
	size_t _len_plaintext = _tmp_plaintext_length * sizeof(char);
	char* _in_plaintext = NULL;
	int* _tmp_plainTextLength = ms->ms_plainTextLength;

	if (sizeof(*_tmp_private_key_ciphered) != 0 &&
		(size_t)_tmp_private_key_ciphered_length > (SIZE_MAX / sizeof(*_tmp_private_key_ciphered))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_ciphertext) != 0 &&
		(size_t)_tmp_ciphertext_length > (SIZE_MAX / sizeof(*_tmp_ciphertext))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_plaintext) != 0 &&
		(size_t)_tmp_plaintext_length > (SIZE_MAX / sizeof(*_tmp_plaintext))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_private_key_ciphered, _len_private_key_ciphered);
	CHECK_UNIQUE_POINTER(_tmp_ciphertext, _len_ciphertext);
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_private_key_ciphered != NULL && _len_private_key_ciphered != 0) {
		if ( _len_private_key_ciphered % sizeof(*_tmp_private_key_ciphered) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_private_key_ciphered = (char*)malloc(_len_private_key_ciphered);
		if (_in_private_key_ciphered == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_private_key_ciphered, _len_private_key_ciphered, _tmp_private_key_ciphered, _len_private_key_ciphered)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ciphertext != NULL && _len_ciphertext != 0) {
		if ( _len_ciphertext % sizeof(*_tmp_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ciphertext = (char*)malloc(_len_ciphertext);
		if (_in_ciphertext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ciphertext, _len_ciphertext, _tmp_ciphertext, _len_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_plaintext = (char*)malloc(_len_plaintext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plaintext, 0, _len_plaintext);
	}

	SGXDecryptRSA((const char*)_in_private_key_ciphered, _tmp_private_key_ciphered_length, (const char*)_in_ciphertext, _tmp_ciphertext_length, _in_plaintext, _tmp_plaintext_length, _tmp_plainTextLength);
	if (_in_plaintext) {
		if (memcpy_s(_tmp_plaintext, _len_plaintext, _in_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_private_key_ciphered) free(_in_private_key_ciphered);
	if (_in_ciphertext) free(_in_ciphertext);
	if (_in_plaintext) free(_in_plaintext);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_generateRSAKeyPair, 0},
		{(void*)(uintptr_t)sgx_SGXEncryptRSA, 0},
		{(void*)(uintptr_t)sgx_SGXDecryptRSA, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][3];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp_timeptr = __tmp;
		memset(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}
	
	ms->ms_timeb_len = timeb_len;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

