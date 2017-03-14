#ifndef __SSL_HELPER_H__
#define __SSL_HELPER_H__

#include "cryptoki.h"

#include <openssl/rsa.h>
//#include <openssl/x509.h>
//#include <openssl/pem.h>
//#include <openssl/pkcs12.h>
//#include "win32\config.h"

int crypto_import_key_pair(CK_SESSION_HANDLE hSession, char* filePath, char* filePIN, char* label, char* objID, size_t objIDLen, int noPublicKey);
EVP_PKEY* crypto_read_file(char* filePath, char* filePIN);

#endif