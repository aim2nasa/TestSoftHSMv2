#include "signVerify.h"
#include <iostream>

using namespace std;

int signVerifySingle(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param, CK_ULONG paramLen)
{
	CK_RV rv;
	CK_MECHANISM mechanism = { mechanismType, param, paramLen };
	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F };
	CK_BYTE signature[256];
	CK_ULONG ulSignatureLen = 0;

	rv = C_SignInit(hSession, &mechanism, hPrivateKey);
	if (rv != CKR_OK) {
		cout << "ERROR: C_SignInit: 0x" << hex << rv << endl;
		return -1;
	}

	ulSignatureLen = sizeof(signature);
	rv = C_Sign(hSession, data, sizeof(data), signature, &ulSignatureLen);
	if (rv != CKR_OK) {
		cout << "ERROR: C_Sign: 0x" << hex << rv << endl;
		return -2;
	}

	rv = C_VerifyInit(hSession, &mechanism, hPublicKey);
	if (rv != CKR_OK) {
		cout << "ERROR: C_VerifyInit: 0x" << hex << rv << endl;
		return -3;
	}

	rv = C_Verify(hSession, data, sizeof(data), signature, ulSignatureLen);
	if (rv != CKR_OK) {
		cout << "ERROR: C_Verify: 0x" << hex << rv << endl;
		return -4;
	}

	// verify again, but now change the input that is being signed.
	rv = C_VerifyInit(hSession, &mechanism, hPublicKey);
	if (rv != CKR_OK) {
		cout << "ERROR: C_VerifyInit: 0x" << hex << rv << endl;
		return -5;
	}

	data[0] = 0xff;
	rv = C_Verify(hSession, data, sizeof(data), signature, ulSignatureLen);
	if (rv != CKR_SIGNATURE_INVALID) {
		cout << "ERROR: C_Verify: 0x" << hex << rv << endl;
		return -6;
	}
	return 0;
}

int signVerifyMulti(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param, CK_ULONG paramLen)
{
	CK_RV rv;
	CK_MECHANISM mechanism = { mechanismType, param, paramLen };
	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F };
	CK_BYTE signature[256];
	CK_ULONG ulSignatureLen = 0;

	rv = C_SignInit(hSession, &mechanism, hPrivateKey);
	if (rv != CKR_OK) {
		cout << "ERROR: C_SignInit: 0x" << hex << rv << endl;
		return -1;
	}

	rv = C_SignUpdate(hSession, data, sizeof(data));
	if (rv != CKR_OK) {
		cout << "ERROR: C_SignUpdate: 0x" << hex << rv << endl;
		return -2;
	}

	ulSignatureLen = sizeof(signature);
	rv = C_SignFinal(hSession, signature, &ulSignatureLen);
	if (rv != CKR_OK) {
		cout << "ERROR: C_SignFinal: 0x" << hex << rv << endl;
		return -3;
	}

	rv = C_VerifyInit(hSession, &mechanism, hPublicKey);
	if (rv != CKR_OK) {
		cout << "ERROR: C_VerifyInit: 0x" << hex << rv << endl;
		return -4;
	}

	rv = C_VerifyUpdate(hSession, data, sizeof(data));
	if (rv != CKR_OK) {
		cout << "ERROR: C_VerifyUpdate: 0x" << hex << rv << endl;
		return -5;
	}

	rv = C_VerifyFinal(hSession, signature, ulSignatureLen);
	if (rv != CKR_OK) {
		cout << "ERROR: C_VerifyFinal: 0x" << hex << rv << endl;
		return -6;
	}

	// verify again, but now change the input that is being signed.
	rv = C_VerifyInit(hSession, &mechanism, hPublicKey);
	if (rv != CKR_OK) {
		cout << "ERROR: C_VerifyInit: 0x" << hex << rv << endl;
		return -7;
	}

	data[0] = 0xff;
	rv = C_VerifyUpdate(hSession, data, sizeof(data));
	if (rv != CKR_OK) {
		cout << "ERROR: C_VerifyUpdate: 0x" << hex << rv << endl;
		return -8;
	}

	rv = C_VerifyFinal(hSession, signature, ulSignatureLen);
	if (rv != CKR_SIGNATURE_INVALID) {
		cout << "ERROR: C_VerifyFinal: 0x" << hex << rv << endl;
		return -9;
	}
	return 0;
}

int signVerifyAll(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
	int nRtn = 0;
	if ((nRtn = signVerifySingle(CKM_RSA_PKCS , hSession, hPublicKey, hPrivateKey)) != 0) return nRtn;
	if ((nRtn = signVerifySingle(CKM_RSA_X_509, hSession, hPublicKey, hPrivateKey)) != 0) return nRtn;

	if ((nRtn = signVerifySingle(CKM_SHA1_RSA_PKCS  , hSession, hPublicKey, hPrivateKey)) != 0) return nRtn;
	if ((nRtn = signVerifySingle(CKM_SHA224_RSA_PKCS, hSession, hPublicKey, hPrivateKey)) != 0) return nRtn;
	if ((nRtn = signVerifySingle(CKM_SHA256_RSA_PKCS, hSession, hPublicKey, hPrivateKey)) != 0) return nRtn;
	if ((nRtn = signVerifySingle(CKM_SHA384_RSA_PKCS, hSession, hPublicKey, hPrivateKey)) != 0) return nRtn;
	if ((nRtn = signVerifySingle(CKM_SHA512_RSA_PKCS, hSession, hPublicKey, hPrivateKey)) != 0) return nRtn;

	CK_RSA_PKCS_PSS_PARAMS params[] = {
		{ CKM_SHA_1, CKG_MGF1_SHA1, 0 },
		{ CKM_SHA224, CKG_MGF1_SHA224, 28 },
		{ CKM_SHA256, CKG_MGF1_SHA256, 32 },
		{ CKM_SHA384, CKG_MGF1_SHA384, 0 },
		{ CKM_SHA512, CKG_MGF1_SHA512, 0 }
	};

	if ((nRtn = signVerifySingle(CKM_SHA1_RSA_PKCS_PSS  , hSession, hPublicKey, hPrivateKey, &params[0], sizeof(params[0]))) != 0) return nRtn;
	if ((nRtn = signVerifySingle(CKM_SHA224_RSA_PKCS_PSS, hSession, hPublicKey, hPrivateKey, &params[1], sizeof(params[1]))) != 0) return nRtn;
	if ((nRtn = signVerifySingle(CKM_SHA256_RSA_PKCS_PSS, hSession, hPublicKey, hPrivateKey, &params[2], sizeof(params[2]))) != 0) return nRtn;
	if ((nRtn = signVerifySingle(CKM_SHA384_RSA_PKCS_PSS, hSession, hPublicKey, hPrivateKey, &params[3], sizeof(params[3]))) != 0) return nRtn;
	if ((nRtn = signVerifySingle(CKM_SHA512_RSA_PKCS_PSS, hSession, hPublicKey, hPrivateKey, &params[4], sizeof(params[4]))) != 0) return nRtn;

	return 0;
}