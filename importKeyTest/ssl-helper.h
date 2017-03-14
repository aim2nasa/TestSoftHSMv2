#ifndef __SSL_HELPER_H__
#define __SSL_HELPER_H__

#include "cryptoki.h"
#include <openssl/rsa.h>

int crypto_import_key_pair(CK_SESSION_HANDLE hSession, char* filePath, char* filePIN, char* label, char* objID, size_t objIDLen, int noPublicKey);
EVP_PKEY* crypto_read_file(char* filePath, char* filePIN);

#endif