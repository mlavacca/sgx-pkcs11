#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "crypto_engine_t.h"
#include "tSgxSSL_api.h"
#include "sgx_trts.h"

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/rsa.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/rand.h"

#define KEY_SIZE 1680
#define RSA_PUBLIC 437
#define BUFFER_SIZE 300

char phrase[64];
unsigned char* digest;
unsigned int digest_len;

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,
	EVP_CIPHER_CTX *d_ctx) {
	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) {
		return -1;
	}

	if (e_ctx != NULL) {
		EVP_CIPHER_CTX_init(e_ctx);
		EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	}

	if (d_ctx != NULL) {
		EVP_CIPHER_CTX_init(d_ctx);
		EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	}

	return 0;
}


unsigned char* aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int ilen, int *olen)
{
	int c_len, f_len = 0;
	unsigned char *ciphertext = (unsigned char*)malloc(KEY_SIZE);
	memset(ciphertext, '\0', KEY_SIZE);

	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, ilen);
	EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);

	*olen = c_len + f_len;
	return ciphertext;
}

unsigned char* aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int ilen, int *olen)
{
	int p_len = ilen, f_len = 0;
	unsigned char *plaintext = (unsigned char*)malloc(p_len);

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, ilen);
	EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

	*olen = p_len + f_len;
	return plaintext;
}

int key_digest(unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if ((mdctx = EVP_MD_CTX_create()) == NULL) {
		EVP_MD_CTX_destroy(mdctx);
		return -1;
	}

	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
		EVP_MD_CTX_destroy(mdctx);
		return -1;
	}

	if (1 != EVP_DigestUpdate(mdctx, message, message_len)) {
		EVP_MD_CTX_destroy(mdctx);
		return -1;
	}

	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL) {
		EVP_MD_CTX_destroy(mdctx);
		return -1;
	}

	if (1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		return -1;

	EVP_MD_CTX_destroy(mdctx);

	return 0;
}

void generateRSA(char* public_key, char* private_key) {
	int ret = 0;
	RSA *r = NULL;
	BIGNUM *bne = NULL;
	BIO *bp_public = NULL, *bp_private = NULL;

	int bits = 2048;
	unsigned long e = RSA_F4;

	bne = BN_new();
	ret = BN_set_word(bne, e);
	if (ret != 1) {
		BN_free(bne);
		return;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if (ret != 1) {
		RSA_free(r);
		BN_free(bne);
	}

	bp_public = BIO_new(BIO_s_mem());
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
	BIO_read(bp_public, public_key, KEY_SIZE);

	bp_private = BIO_new(BIO_s_mem());
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
	BIO_read(bp_private, private_key, KEY_SIZE);

	RSA_free(r);
	BN_free(bne);
}


void generateRSAKeyPair(char* RSAPublicKey, char* RSAPrivateKey, size_t RSAKeysLength) {

	char public_key[RSA_PUBLIC];
	char private_key[KEY_SIZE];

	RAND_bytes((unsigned char*)phrase, sizeof(phrase));

	unsigned char *cipherKey = NULL;
	EVP_CIPHER_CTX* e_ctx = EVP_CIPHER_CTX_new();

	aes_init((unsigned char*)phrase, sizeof(phrase), NULL, e_ctx, NULL);

	generateRSA(public_key, private_key);

	int ilen = strlen(private_key);

	key_digest((unsigned char*)private_key, ilen, &digest, &digest_len);

	int olen;
	cipherKey = aes_encrypt(e_ctx, (unsigned char*)private_key, ilen ,&olen);

	strncpy(RSAPublicKey, public_key, RSA_PUBLIC);
	memcpy((void*)RSAPrivateKey, (void*)cipherKey, olen);

	EVP_CIPHER_CTX_cleanup(e_ctx);
	free(e_ctx);
}

void SGXEncryptRSA(const char* public_key, size_t public_key_length,
	const char* plaintext, size_t plaintext_length,
	char* ciphertext, size_t ciphertext_length,
	int* cipherTextLength) {

	int padding = RSA_PKCS1_PADDING;
	BIO *bp_public = NULL;
	RSA *rsa = RSA_new();

	bp_public = BIO_new(BIO_s_mem());
	BIO_write(bp_public, public_key, public_key_length);
	PEM_read_bio_RSAPublicKey(bp_public, &rsa, NULL, NULL);

	int len = RSA_public_encrypt(plaintext_length, (unsigned char*)plaintext, (unsigned char*)ciphertext, rsa, padding);
	
	*cipherTextLength = len;
	RSA_free(rsa);
	BIO_free(bp_public);
}

void SGXDecryptRSA(const char* private_key_ciphered, size_t private_key_ciphered_length,
	const char* ciphertext, size_t ciphertext_length,
	char* plaintext, size_t plaintext_length, int* plainTextLength) {

	EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();

	aes_init((unsigned char*)phrase, sizeof(phrase), NULL, NULL, d_ctx);

	int len;
	unsigned char* decipheredKey = aes_decrypt(d_ctx, (unsigned char *)private_key_ciphered, KEY_SIZE, &len);

	unsigned int digest_len;
	unsigned char* new_digest;

	key_digest((unsigned char*)decipheredKey, len, &new_digest, &digest_len);

	for (uint i = 0; i < digest_len; i++) {
		if (digest[i] != new_digest[i]) {
			plaintext = (char*)"\0";
			*plainTextLength = 0;
			return;
		}	
	}

	EVP_CIPHER_CTX_cleanup(d_ctx);
	free(d_ctx);

	int padding = RSA_PKCS1_PADDING;
	BIO *bp_private = NULL;
	RSA *rsa = RSA_new();

	bp_private = BIO_new(BIO_s_mem());
	BIO_write(bp_private, decipheredKey, KEY_SIZE-1);
	PEM_read_bio_RSAPrivateKey(bp_private, &rsa, NULL, NULL);

	char buffer[BUFFER_SIZE];
	memset(buffer, '\0', BUFFER_SIZE);

	RSA_private_decrypt(*plainTextLength, (unsigned char*)ciphertext, (unsigned char*)buffer, rsa, padding);

	strncpy(plaintext, buffer, strlen(buffer));
}