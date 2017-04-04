#include <iostream>
#include "library.h"
#include "createToken.h"
#include "generateRSA.h"
#include "signVerify.h"
#include "rsaEncryptDecrypt.h"
#include "deleteToken.h"

using namespace std;

int main(int argc, char* argv[]) {
	if (argc < 4) {
		cout << "usage: testpkcs11 <soPin> <label> <userPin>" << endl;
		return -1;
	}

	void* module;
	CK_FUNCTION_LIST_PTR p11 = NULL;
	if (loadLib(&module, &p11) == -1) {
		cout << "ERROR: loadLib" << endl;
		return -1;
	}
	cout << "loadLib ok" << endl;

	char *soPin = argv[1];
	char *label = argv[2];
	char *userPin = argv[3];

	//��ū�� �����Ѵ� (���� ���� ����)
	CK_SESSION_HANDLE hSession;
	int nRtn = 0;;
	if ((nRtn = createToken(p11, &hSession, soPin, label, userPin)) != 0) {
		cout << "ERROR: createToken(" <<soPin<<","<<label<<","<<userPin<<")="<<nRtn<< endl;
		return -1;
	}
	cout << "token("<<label<<") created" << endl;

	//RSA Key pair�� �����Ѵ�
	cout << "generating RSA key pair..." << endl;
	CK_OBJECT_HANDLE hPuk,hPrk;
	if ((nRtn = generateRsaKeyPair(hSession, ON_TOKEN, IS_PUBLIC, ON_TOKEN, IS_PUBLIC, &hPuk, &hPrk)) != 0) {
		cout << "ERROR: generateRSA=" << nRtn << endl;
		return -1;
	}
	cout << "RSA key pair generated" << endl;

	//Sign�ϰ� Sign�� ���ؼ� verify
	if ((nRtn = signVerifyAll(hSession, hPuk, hPrk)) != 0) {
		cout << "ERROR: signVerifyAll=" << nRtn << endl;
		return -1;
	}
	cout << "sign and verified" << endl;

	//Encrypt(RSA PubŰ)�ϰ� Decrypt(RSA PrivŰ)�Ͽ� ����� ���������� �����ϴ� �׽�Ʈ
	if ((nRtn=rsaEncryptDecrypt(CKM_RSA_PKCS, hSession, hPuk, hPrk)) != 0) {
		cout << "ERROR: rsaEncryptDecrypt(CKM_RSA_PKCS)=" << nRtn << endl;
		return -1;
	}

	if ((nRtn = rsaEncryptDecrypt(CKM_RSA_X_509, hSession, hPuk, hPrk)) != 0) {
		cout << "ERROR: rsaEncryptDecrypt(CKM_RSA_X_509)=" << nRtn << endl;
		return -1;
	}

	if ((nRtn = rsaEncryptDecrypt(CKM_RSA_PKCS_OAEP, hSession, hPuk, hPrk)) != 0) {
		cout << "ERROR: rsaEncryptDecrypt(CKM_RSA_PKCS_OAEP)=" << nRtn << endl;
		return -1;
	}
	cout << "RSA Encrypt/Decrypt tested ok" << endl;

	//������ ��ū�� �����Ѵ�
	if ( (nRtn=deleteToken(NULL_PTR, label)) != 0) {
		cout << "ERROR: deleteToken(," << label << ")=" << nRtn << endl;
		return -1;
	}
	cout << "token(" << label << ") deleted" << endl;

	unloadLib(module);
	cout << "end of testpkcs11" << endl;
	return 0;
}