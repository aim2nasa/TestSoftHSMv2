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