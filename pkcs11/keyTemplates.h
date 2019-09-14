#pragma once
#include "pkcs11-interface.h"

CK_ULONG modulusBits = 768;
CK_BYTE publicExponent[] = { 3 };
CK_BBOOL tr = CK_TRUE;
CK_BYTE subject[] = { "Ciphered private RSA key" };
CK_BYTE id[] = { 123 };
CK_OBJECT_CLASS cl = CKO_DATA;
CK_BYTE dat[] = "";

CK_ATTRIBUTE publicRSAKeyTemplate[] = {
	{CKA_CLASS, &cl, sizeof(cl)},
	{CKA_ENCRYPT, &tr, sizeof(tr)},
	{CKA_VALUE, dat, sizeof(dat)}
};
CK_ULONG publicRSAKeyTemplateLength = 3;

CK_ATTRIBUTE privateRSAKeyTemplate[] = {
	{CKA_CLASS, &cl, sizeof(cl)},
	{CKA_TOKEN, &tr, sizeof(tr)},
	{CKA_PRIVATE, &tr, sizeof(tr)},
	{CKA_SUBJECT, subject, sizeof(subject)},
	{CKA_ID, id, sizeof(id)},
	{CKA_SENSITIVE, &tr, sizeof(true)},
	{CKA_DECRYPT, &tr, sizeof(true)},
	{CKA_VALUE, dat, sizeof(dat)}
};
CK_ULONG privateRSAKeyTemplateLength = 7;