#ifndef __SSL_HELPER_H__
#define __SSL_HELPER_H__

#include "cryptoki.h"
#include <openssl/rsa.h>

int crypto_import_key_pair(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE hSession, char* filePath, char* filePIN, char* label, char* objID, size_t objIDLen, int noPublicKey);
EVP_PKEY* crypto_read_file(char* filePath, char* filePIN);

// RSA
typedef struct rsa_key_material_t {
	CK_ULONG sizeE;
	CK_ULONG sizeN;
	CK_ULONG sizeD;
	CK_ULONG sizeP;
	CK_ULONG sizeQ;
	CK_ULONG sizeDMP1;
	CK_ULONG sizeDMQ1;
	CK_ULONG sizeIQMP;
	CK_VOID_PTR bigE;
	CK_VOID_PTR bigN;
	CK_VOID_PTR bigD;
	CK_VOID_PTR bigP;
	CK_VOID_PTR bigQ;
	CK_VOID_PTR bigDMP1;
	CK_VOID_PTR bigDMQ1;
	CK_VOID_PTR bigIQMP;
	rsa_key_material_t() {
		sizeE = 0;
		sizeN = 0;
		sizeD = 0;
		sizeP = 0;
		sizeQ = 0;
		sizeDMP1 = 0;
		sizeDMQ1 = 0;
		sizeIQMP = 0;
		bigE = NULL_PTR;
		bigN = NULL_PTR;
		bigD = NULL_PTR;
		bigP = NULL_PTR;
		bigQ = NULL_PTR;
		bigDMP1 = NULL_PTR;
		bigDMQ1 = NULL_PTR;
		bigIQMP = NULL_PTR;
	}
} rsa_key_material_t;
int crypto_save_rsa(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, RSA* rsa);
rsa_key_material_t* crypto_malloc_rsa(RSA* rsa);
void crypto_free_rsa(rsa_key_material_t* keyMat);

#endif