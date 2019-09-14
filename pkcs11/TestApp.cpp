#include <iostream>
#include <fstream>
#include "pkcs11-interface.h"
#include "keyTemplates.h"
#include "shared_values.h"

using namespace std;

void safeClose(CK_OBJECT_HANDLE pubKey, CK_OBJECT_HANDLE priKey,
	char* cipherBuffer, char* plainBuffer, char* buffer);

int main(int argc, const char** argv) {
	CK_FLAGS flags = 0b10 | 0b100;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanismGen = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
	};
	CK_MECHANISM mechanismRSA = {
				CKM_RSA_PKCS, NULL_PTR, 0
	};

	CK_RV ret_value;
	CK_OBJECT_HANDLE hPublicKey = (CK_OBJECT_HANDLE)NULL;
	CK_OBJECT_HANDLE hPrivateKey = (CK_OBJECT_HANDLE)NULL;
	char *cipherBuffer = NULL;
	char *plainBuffer = NULL;
	char *buffer = NULL;

	if(argc != 2){
		printf("App inFile\n");
		exit(EXIT_FAILURE);
	}

	ret_value = C_Initialize(nullptr);
	if (ret_value != CKR_OK) {
		printf("Error in C_initialize, error number: %ld\n", ret_value);
		safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
		exit(EXIT_FAILURE);
	}

	printf("PKCS11 interface Initialization done\n");

	ret_value = C_OpenSession(1, flags, nullptr, nullptr, &session);
	if (ret_value != CKR_OK) {
		printf("Error in C_OpenSession, error number: %ld\n", ret_value);
		safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
		exit(EXIT_FAILURE);
	}

	printf("PKCS11 session opened and Intel SGX initialized\n\n");

	ret_value = C_GenerateKeyPair(session, &mechanismGen,
		publicRSAKeyTemplate, publicRSAKeyTemplateLength,
		privateRSAKeyTemplate, privateRSAKeyTemplateLength,
		&hPublicKey, &hPrivateKey);
	if (ret_value != CKR_OK) {
		printf("Error in C_GenerateKeyPair, error number: %ld\n", ret_value);
		safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
		exit(EXIT_FAILURE);
	}

	printf("Intel SGX created and returned a pair of RSA keys:\n");
	printf("1-clear RSA public key\n");
	printf("2-private RSA key encrypted with AES-256-cbc\n\n");

	string bufferStr;
	size_t cipherBufferLength = CIPHER_BUFFER_LENGTH;
	size_t plainBufferLength = PLAIN_BUFFER_LENGTH;

	ifstream input_file;
	input_file.open(argv[1], ifstream::in);
	if(input_file.fail()){
		printf("Invalid input file\n");
		exit(EXIT_FAILURE);
	}

	getline(input_file, bufferStr);
	input_file.close();
	buffer = (char*)malloc(PLAIN_BUFFER_LENGTH * sizeof(char));
	memset(buffer, '\0', bufferStr.size() + 1);
	strncpy(buffer, bufferStr.c_str(), bufferStr.size());

	if(strlen(buffer) > MAX_RSA_SIZE){
		printf("ERROR: Input message too long\n");
		safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
		exit(EXIT_FAILURE);
	}

	printf("Message to encrypt:\n%s\n", buffer);
	printf("\nEncryption initialization...\n");

	ret_value = C_EncryptInit(session, &mechanismRSA, hPublicKey);
	if (ret_value != CKR_OK) {
		printf("Error in C_EncryptInit, error number: %ld\n", ret_value);
		safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
		exit(EXIT_FAILURE);
	}

	ret_value = C_Encrypt(session, (CK_BYTE_PTR)buffer, strlen(buffer),
		(CK_BYTE_PTR)&cipherBuffer, (CK_ULONG_PTR)&cipherBufferLength);
	if (ret_value != CKR_OK) {
		printf("Error in C_Encrypt, error number: %ld\n", ret_value);
		safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
		exit(EXIT_FAILURE);
	}

	printf("Intel SGX has encrypted the message by using the public RSA key\n");

	printf("\nDecryption initialization...\n");

	ret_value = C_DecryptInit(session, &mechanismRSA, hPrivateKey);
	if (ret_value != CKR_OK) {
		printf("Error in C_DecryptInit, error number: %ld\n", ret_value);
		safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
		exit(EXIT_FAILURE);
	}

	ret_value = C_Decrypt(session, (CK_BYTE_PTR)cipherBuffer, cipherBufferLength,
		(CK_BYTE_PTR)&plainBuffer, (CK_ULONG_PTR)&plainBufferLength);
	if (ret_value != CKR_OK) {
		printf("Error in C_Decrypt, error number: %ld\n", ret_value);
		safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
		exit(EXIT_FAILURE);
	}

	printf("Intel SGX has decrypted the message by using the private encrypted RSA key\n");
	printf("Decrypted message:\n%s\n\n", plainBuffer);

	ret_value = C_CloseSession(session);
	if (ret_value != CKR_OK) {
		printf("Error in C_CloseSession, error number: %ld\n", ret_value);
		safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
		exit(EXIT_FAILURE);
	}

	printf("PKCS11 session closed and Intel SGX closed\n");

	ret_value = C_Finalize(NULL);
	if (ret_value != CKR_OK) {
		printf("Error in C_Finalize, error number: %ld\n", ret_value);
		safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
		exit(EXIT_FAILURE);
	}

	printf("PKCS11 interface closed\n");

	safeClose(hPublicKey, hPrivateKey, cipherBuffer, plainBuffer, buffer);
	exit(EXIT_SUCCESS);
}

void safeClose(CK_OBJECT_HANDLE pubKey, CK_OBJECT_HANDLE priKey,
	char* cipherBuffer, char* plainBuffer, char* buffer) {

	delete(cipherBuffer);
	delete(plainBuffer);
	delete(buffer);

	printf("Exit...\n");
}


