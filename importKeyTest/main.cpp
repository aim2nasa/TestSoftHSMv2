#include <iostream>
#include "library.h"

using namespace std;

int openSession(CK_FUNCTION_LIST_PTR p11, unsigned long slotID, CK_SESSION_HANDLE *pSession);
int login(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE *pSession, char* soPin);

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