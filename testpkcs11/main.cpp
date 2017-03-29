#include <iostream>
#include "library.h"
#include "createToken.h"
#include "generateRSA.h"
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

	//토큰을 생성한다 (세션 오픈 포함)
	CK_SESSION_HANDLE hSession;
	int nRtn = 0;;
	if ((nRtn = createToken(p11, &hSession, soPin, label, userPin)) != 0) {
		cout << "ERROR: createToken(" <<soPin<<","<<label<<","<<userPin<<")="<<nRtn<< endl;
		return -1;
	}
	cout << "token("<<label<<") created" << endl;

	//RSA Key pair를 생성한다
	CK_OBJECT_HANDLE hPuk,hPrk;
	if ((nRtn = generateRsaKeyPair(hSession, ON_TOKEN, IS_PUBLIC, ON_TOKEN, IS_PUBLIC, &hPuk, &hPrk)) != 0) {
		cout << "ERROR: generateRSA=" << nRtn << endl;
		return -1;
	}

	//생성된 토큰을 삭제한다
	if ( (nRtn=deleteToken(NULL_PTR, label)) != 0) {
		cout << "ERROR: deleteToken(," << label << ")=" << nRtn << endl;
		return -1;
	}
	cout << "token(" << label << ") deleted" << endl;

	unloadLib(module);
	cout << "end of testpkcs11" << endl;
	return 0;
}