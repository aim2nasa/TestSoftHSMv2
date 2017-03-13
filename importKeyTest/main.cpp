#include <iostream>
#include "library.h"
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

using namespace std;

int openSession(CK_FUNCTION_LIST_PTR p11, unsigned long slotID, CK_SESSION_HANDLE *pSession);
int login(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE *pSession, char* soPin);
char* hexStrToBin(char* objectID, int idLength, size_t* newLen);
int hexdigit_to_int(char ch);
CK_OBJECT_HANDLE searchObject(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE hSession, char* objID, size_t objIDLen);
int crypto_import_key_pair(CK_SESSION_HANDLE hSession, char* filePath, char* filePIN, char* label, char* objID, size_t objIDLen, int noPublicKey);
EVP_PKEY* crypto_read_file(char* filePath, char* filePIN);

int main(int argc, char* argv[])
{
	if (argc < 8) {
		cout << "usage: importKeyTest <slot id> <userPin> <obj id> <label> <file> <filePin> <noPublicKey>" << endl;
		return -1;
	}

	void* module;
	CK_FUNCTION_LIST_PTR p11 = NULL;
	if (loadLib(&module, &p11) == -1) {
		cout << "ERROR: loadLib" << endl;
		return -1;
	}
	cout << "loadLib ok" << endl;

	CK_SESSION_HANDLE hSession;
	if (openSession(p11, atoi(argv[1]), &hSession) == 0) {
		cout << "openSession OK" << endl;

		if (login(p11, &hSession, argv[2]) == 0) {
			cout << "login OK" << endl;

			size_t objIDLen = 0;
			char* objectID = hexStrToBin(argv[3], (int)strlen(argv[3]), &objIDLen);
			CK_OBJECT_HANDLE oHandle = searchObject(p11,hSession, objectID,objIDLen);
			if (oHandle != CK_INVALID_HANDLE) {
				cout << "Object found, obj id(" << argv[3] << ")" << endl;

				char* filePin = NULL;
				if (strlen(argv[6]) > 0) filePin = argv[6];
				crypto_import_key_pair(hSession, argv[5], filePin, argv[4], objectID, objIDLen, atoi(argv[7]));
			}
			else{
				cout << "ERROR: Object not found, obj id(" << argv[3] << ")" << endl;
				free(objectID);
				unloadLib(module);
				return -1;
			}
			free(objectID);
		}
		else{
			unloadLib(module);
			return -1;
		}
	}
	else{
		unloadLib(module);
		return -1;
	}

	unloadLib(module);
	cout << "import key test end" << endl;
	return 0;
}

int openSession(CK_FUNCTION_LIST_PTR p11, unsigned long slotID, CK_SESSION_HANDLE *pSession)
{
	CK_RV rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, pSession);
	if (rv != CKR_OK) {
		cout << "ERROR: Could not open a session with the library." << endl;
		return -1;
	}
	return 0;
}

int login(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE *pSession, char* soPin)
{
	CK_RV rv = p11->C_Login(*pSession, CKU_SO, (CK_UTF8CHAR_PTR)soPin, (CK_ULONG)strlen(soPin));
	if (rv != CKR_OK) {
		cout << "ERROR: Could not log in on the token. (0x" << hex << rv << ")" << endl;
		return -1;
	}
	return 0;
}

// Convert a char array of hexadecimal characters into a binary representation
char* hexStrToBin(char* objectID, int idLength, size_t* newLen)
{
	char* bytes = NULL;

	if (idLength < 2 || idLength % 2 != 0)
	{
		fprintf(stderr, "ERROR: Invalid length on hex string.\n");
		return NULL;
	}

	for (int i = 0; i < idLength; i++)
	{
		if (hexdigit_to_int(objectID[i]) == -1)
		{
			fprintf(stderr, "ERROR: Invalid character in hex string.\n");
			return NULL;
		}
	}

	*newLen = idLength / 2;
	bytes = (char*)malloc(*newLen);
	if (bytes == NULL)
	{
		fprintf(stderr, "ERROR: Could not allocate memory.\n");
		return NULL;
	}

	for (size_t i = 0; i < *newLen; i++)
	{
		bytes[i] = hexdigit_to_int(objectID[2 * i]) * 16 +
			hexdigit_to_int(objectID[2 * i + 1]);
	}

	return bytes;
}

// Return the integer value of a hexadecimal character
int hexdigit_to_int(char ch)
{
	switch (ch)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'a':
	case 'A':
		return 10;
	case 'b':
	case 'B':
		return 11;
	case 'c':
	case 'C':
		return 12;
	case 'd':
	case 'D':
		return 13;
	case 'e':
	case 'E':
		return 14;
	case 'f':
	case 'F':
		return 15;
	default:
		return -1;
	}
}

CK_OBJECT_HANDLE searchObject(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE hSession, char* objID, size_t objIDLen)
{
	if (objID == NULL)
	{
		return CK_INVALID_HANDLE;
	}

	CK_OBJECT_CLASS oClass = CKO_PRIVATE_KEY;
	CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;
	CK_ULONG objectCount = 0;

	CK_ATTRIBUTE objTemplate[] = {
		{ CKA_CLASS, &oClass, (CK_ULONG)sizeof(oClass) },
		{ CKA_ID, objID, (CK_ULONG)objIDLen }
	};

	CK_RV rv = p11->C_FindObjectsInit(hSession, objTemplate, 2);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not prepare the object search.\n");
		return CK_INVALID_HANDLE;
	}

	rv = p11->C_FindObjects(hSession, &hObject, 1, &objectCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the search results.\n");
		return CK_INVALID_HANDLE;
	}

	rv = p11->C_FindObjectsFinal(hSession);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not finalize the search.\n");
		return CK_INVALID_HANDLE;
	}

	if (objectCount == 0)
	{
		return CK_INVALID_HANDLE;
	}

	return hObject;
}

int crypto_import_key_pair(CK_SESSION_HANDLE hSession,char* filePath,char* filePIN,char* label,char* objID,size_t objIDLen,int noPublicKey)
{
	EVP_PKEY* pkey = crypto_read_file(filePath, filePIN);
	if (pkey == NULL)
	{
		return 1;
	}

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