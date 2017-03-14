#ifndef __SSL_HELPER_H__
#define __SSL_HELPER_H__

#include "cryptoki.h"
#include <openssl/rsa.h>
#include "win32\config.h"

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

// DSA
typedef struct dsa_key_material_t {
	CK_ULONG sizeP;
	CK_ULONG sizeQ;
	CK_ULONG sizeG;
	CK_ULONG sizeX;
	CK_ULONG sizeY;
	CK_VOID_PTR bigP;
	CK_VOID_PTR bigQ;
	CK_VOID_PTR bigG;
	CK_VOID_PTR bigX;
	CK_VOID_PTR bigY;
	dsa_key_material_t() {
		sizeP = 0;
		sizeQ = 0;
		sizeG = 0;
		sizeX = 0;
		sizeY = 0;
		bigP = NULL_PTR;
		bigQ = NULL_PTR;
		bigG = NULL_PTR;
		bigX = NULL_PTR;
		bigY = NULL_PTR;
	}
} dsa_key_material_t;
int crypto_save_dsa(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, DSA* dsa);
dsa_key_material_t* crypto_malloc_dsa(DSA* dsa);
void crypto_free_dsa(dsa_key_material_t* keyMat);

#ifdef WITH_ECC
// ECDSA
typedef struct ecdsa_key_material_t {
	CK_ULONG sizeParams;
	CK_ULONG sizeD;
	CK_ULONG sizeQ;
	CK_VOID_PTR derParams;
	CK_VOID_PTR bigD;
	CK_VOID_PTR derQ;
	ecdsa_key_material_t() {
		sizeParams = 0;
		sizeD = 0;
		sizeQ = 0;
		derParams = NULL_PTR;
		bigD = NULL_PTR;
		derQ = NULL_PTR;
	}
} ecdsa_key_material_t;
int crypto_save_ecdsa(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE hSession, char* label, char* objID, size_t objIDLen, int noPublicKey, EC_KEY* ecdsa);
ecdsa_key_material_t* crypto_malloc_ecdsa(EC_KEY* ecdsa);
void crypto_free_ecdsa(ecdsa_key_material_t* keyMat);
#endif

#endif