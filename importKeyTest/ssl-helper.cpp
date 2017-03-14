#include "ssl-helper.h"

#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include "win32\config.h"
#include <string.h>

int crypto_import_key_pair(CK_SESSION_HANDLE hSession, char* filePath, char* filePIN, char* label, char* objID, size_t objIDLen, int noPublicKey)
{
	EVP_PKEY* pkey = crypto_read_file(filePath, filePIN);
	if (pkey == NULL)
	{
		return 1;
	}

	RSA* rsa = NULL;
	DSA* dsa = NULL;
#ifdef WITH_ECC
	EC_KEY* ecdsa = NULL;
#endif

	switch (EVP_PKEY_type(EVP_PKEY_id(pkey)))
	{
	case EVP_PKEY_RSA:
		rsa = EVP_PKEY_get1_RSA(pkey);
		break;
	case EVP_PKEY_DSA:
		dsa = EVP_PKEY_get1_DSA(pkey);
		break;
#ifdef WITH_ECC
	case EVP_PKEY_EC:
		ecdsa = EVP_PKEY_get1_EC_KEY(pkey);
		break;
#endif
	default:
		fprintf(stderr, "ERROR: Cannot handle this algorithm.\n");
		EVP_PKEY_free(pkey);
		return 1;
		break;
	}
	EVP_PKEY_free(pkey);

	//softhsm2-util로 부터 포팅중

	return 0;
}

// Read the key from file
EVP_PKEY* crypto_read_file(char* filePath, char* filePIN)
{
	BIO* in = NULL;
	PKCS8_PRIV_KEY_INFO* p8inf = NULL;
	EVP_PKEY* pkey = NULL;
	X509_SIG* p8 = NULL;

	if (!(in = BIO_new_file(filePath, "rb")))
	{
		fprintf(stderr, "ERROR: Could open the PKCS#8 file: %s\n", filePath);
		return NULL;
	}

	// The PKCS#8 file is encrypted
	if (filePIN)
	{
		p8 = PEM_read_bio_PKCS8(in, NULL, NULL, NULL);
		BIO_free(in);

		if (!p8)
		{
			fprintf(stderr, "ERROR: Could not read the PKCS#8 file. "
				"Maybe the file is not encrypted.\n");
			return NULL;
		}

		p8inf = PKCS8_decrypt(p8, filePIN, (int)strlen(filePIN));
		X509_SIG_free(p8);

		if (!p8inf)
		{
			fprintf(stderr, "ERROR: Could not decrypt the PKCS#8 file. "
				"Maybe wrong PIN to file (--file-pin <PIN>)\n");
			return NULL;
		}
	}
	else
	{
		p8inf = PEM_read_bio_PKCS8_PRIV_KEY_INFO(in, NULL, NULL, NULL);
		BIO_free(in);

		if (!p8inf)
		{
			fprintf(stderr, "ERROR: Could not read the PKCS#8 file. "
				"Maybe it is encypted (--file-pin <PIN>)\n");
			return NULL;
		}
	}

	// Convert the PKCS#8 to OpenSSL
	pkey = EVP_PKCS82PKEY(p8inf);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (!pkey)
	{
		fprintf(stderr, "ERROR: Could not convert the key.\n");
		return NULL;
	}

	return pkey;
}