#include "rsaEncryptDecrypt.h"
#include <assert.h>
#include <memory.h>

int rsaEncryptDecrypt(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, 1, NULL_PTR, 0 };
	CK_BYTE plainText[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F };
	CK_BYTE cipherText[256];
	CK_ULONG ulCipherTextLen;
	CK_BYTE recoveredText[256];
	CK_ULONG ulRecoveredTextLen;
	CK_RV rv;

	if (mechanismType == CKM_RSA_PKCS_OAEP)
	{
		mechanism.pParameter = &oaepParams;
		mechanism.ulParameterLen = sizeof(oaepParams);
	}

	rv = C_EncryptInit(hSession, &mechanism, hPublicKey);
	if (rv != CKR_OK) return (int)rv;

	ulCipherTextLen = sizeof(cipherText);
	rv = C_Encrypt(hSession, plainText, sizeof(plainText), cipherText, &ulCipherTextLen);
	if (rv != CKR_OK) return (int)rv;

	rv = C_DecryptInit(hSession, &mechanism, hPrivateKey);
	if (rv != CKR_OK) return (int)rv;

	ulRecoveredTextLen = sizeof(recoveredText);
	rv = C_Decrypt(hSession, cipherText, ulCipherTextLen, recoveredText, &ulRecoveredTextLen);
	if (rv != CKR_OK) return (int)rv;

	if (memcmp(plainText, &recoveredText[ulRecoveredTextLen - sizeof(plainText)], sizeof(plainText)) !=0) return -1;

	return 0;
}