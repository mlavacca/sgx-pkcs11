#include <exception>
#include <stdexcept>
#include "CryptoEntity.h"

CryptoEntity::CryptoEntity() {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	sgx_launch_token_t launch_token = { 0 };
	int updated = 0;

	// Step 1: try to retrieve the launch token saved by last transaction
	//         if there is no token, then create a new one.
	auto fp = fopen(this->kTokenFile, "rb");
	if (fp == nullptr) {
		if ((fp = fopen(this->kTokenFile, "wb")) == nullptr) {
			throw std::runtime_error("Failed to create the launch token file.");
		}
	}
	else {
		// read the token from saved file
		const size_t read_num = fread(launch_token, 1,
			sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			// if token is invalid, clear the buffer
			memset(&launch_token, 0, sizeof(sgx_launch_token_t));
		}
	}

	// Step 2: call sgx_create_enclave to initialize an enclave instance
	ret = sgx_create_enclave(this->kEnclaveFile, SGX_DEBUG_FLAG, &launch_token, &updated, &this->enclave_id_, NULL);
	if (ret != SGX_SUCCESS) {
		throw std::runtime_error("Failed to create enclave.");
	}

	// Step 3: save the launch token if it is updated
	if (updated) {
		fp = freopen(this->kTokenFile, "wb", fp);
		if (fp == nullptr) {
			throw std::runtime_error("Failed to save launch token.");
		}
		const std::size_t write_num = fwrite(launch_token, 1, sizeof(sgx_launch_token_t), fp);
		if (write_num != sizeof(sgx_launch_token_t)) {
			throw std::runtime_error("Failed to save launch token.");
		}
	}
	fclose(fp);
}

void CryptoEntity::RSAKeyGeneration(char* publicKey, char* privateKey) {
	sgx_status_t ret;

	ret = generateRSAKeyPair(this->enclave_id_, publicKey, privateKey, KEY_SIZE);
	if (ret != SGX_SUCCESS)
		throw new std::exception;
}

void CryptoEntity::RSAInitEncrypt(char* key) {
	this->initializedKey = key;
}

char* CryptoEntity::RSAEncrypt(char* plainData, int* cipherLength) {
	sgx_status_t ret;
	char* cipherData = (char*)malloc(CIPHER_BUFFER_LENGTH * sizeof(char));

	ret = SGXEncryptRSA(this->enclave_id_, this->initializedKey, strlen(this->initializedKey),
		plainData, strlen(plainData), cipherData, CIPHER_BUFFER_LENGTH, cipherLength);
	if (ret != SGX_SUCCESS)
		throw std::runtime_error("Encryption failed\n");
	
	if(*cipherLength < 1){
		throw std::runtime_error("Encryption failed\n");
	}

	return cipherData;
}

void CryptoEntity::RSAInitDecrypt(char* key) {
	this->initializedKey = key;
}

char* CryptoEntity::RSADecrypt(char* cipherData, int* plainLength) {
	sgx_status_t ret;
	char* plainData = (char*)malloc(PLAIN_BUFFER_LENGTH * sizeof(char));
	ret = SGXDecryptRSA(this->enclave_id_,
			this->initializedKey, KEY_SIZE,
			cipherData, CIPHER_BUFFER_LENGTH,
			plainData, PLAIN_BUFFER_LENGTH, plainLength);
	if (ret != SGX_SUCCESS)
		throw std::runtime_error("Decryption failed\n");

	if(*plainLength < 1){
		throw std::runtime_error("Decryption failed\n");
	}

	return plainData;
}

CryptoEntity::~CryptoEntity() {
	sgx_destroy_enclave(this->enclave_id_);
}