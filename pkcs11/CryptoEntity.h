#pragma once
#ifndef POLITO_CSS_ESIGNER_H_
#define POLITO_CSS_ESIGNER_H_

#include <sgx_urts.h>
#include <string>
#include "crypto_engine_u.h"
#include "shared_values.h"

class CryptoEntity {
private:
#ifdef _WIN32
	const char* kEnclaveFile = "PKCS11_crypto_engine.signed.dll";
#else
	const char* kEnclaveFile = "PKCS11_crypto_engine.signed.so";
#endif
	const char* kTokenFile = "token";
	sgx_enclave_id_t enclave_id_;
	char* initializedKey;
public:
	CryptoEntity();
	void RSAKeyGeneration(char* publickey, char* privateKey);
	void RSAInitEncrypt(char* key);
	char* RSAEncrypt(char* plainData, int* cipherLength);
	void RSAInitDecrypt(char* key);
	char* RSADecrypt(char* cipherData, int* plainLength);
	~CryptoEntity();
};

#endif  // POLITO_CSS_ESIGNER_H_