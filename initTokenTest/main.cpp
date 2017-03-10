#include <iostream>
#include "library.h"

using namespace std;

int initToken(CK_FUNCTION_LIST_PTR p11, unsigned long slotID, char* soPin, char *label);
int openSession(CK_FUNCTION_LIST_PTR p11, unsigned long slotID, CK_SESSION_HANDLE *pSession);
int login(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE *pSession, char* soPin);
int initPin(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE *pSession, char* userPin);

int main(int argc, char* argv[])
{
	if (argc < 5) {
		cout << "usage: initTokenTest <slot id> <soPin> <label> <userPin>" << endl;
		return -1;
	}

	void* module;
	CK_FUNCTION_LIST_PTR p11 = NULL;
	if (loadLib(&module, &p11) == -1) {
		cout << "ERROR: loadLib" << endl;
		return -1;
	}
	cout << "loadLib ok" << endl;

	if (initToken(p11, atoi(argv[1]), argv[2], argv[3]) == 0) {
		cout << "InitToken OK" << endl;

		CK_SESSION_HANDLE hSession;
		if (openSession(p11, atoi(argv[1]), &hSession) == 0) {
			cout << "openSession OK" << endl;

			if (login(p11, &hSession, argv[2]) == 0) {
				cout << "login OK" << endl;
				
				if (initPin(p11, &hSession, argv[4]) == 0) {
					cout << "initPin OK" << endl;
				}else{
					unloadLib(module);
					return -1;
				}
			}else{
				unloadLib(module);
				return -1;
			}
		}else{
			unloadLib(module);
			return -1;
		}
	}else{
		unloadLib(module);
		return -1;
	}

	unloadLib(module);
	cout << "initToken test end" << endl;
	return 0;
}

int initToken(CK_FUNCTION_LIST_PTR p11, unsigned long slotID, char* soPin, char *label)
{
	CK_RV rv = p11->C_InitToken(slotID, (CK_UTF8CHAR_PTR)soPin, (CK_ULONG)strlen(soPin), (CK_UTF8CHAR_PTR)label);
	switch (rv)
	{
	case CKR_OK:
		break;
	case CKR_SLOT_ID_INVALID:
		cout << "ERROR: CKR_SLOT_ID_INVALID: Slot " << slotID << " does not exist." << endl;
		return -1;
	case CKR_PIN_INCORRECT:
		cout << "ERROR: CKR_PIN_INCORRECT: The given SO PIN does not match the one in the token. Needed when reinitializing the token." << endl;
		return -1;
	case CKR_TOKEN_NOT_PRESENT:
		cout << "ERROR: CKR_TOKEN_NOT_PRESENT: The token is not present. Please read the HSM manual for further assistance." << endl;
		return -1;
	default:
		cout << "ERROR: Could not initialize the token. (" <<hex<< rv << ")" << endl;
		return -1;
	}
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
		cout << "ERROR: Could not log in on the token. (0x" <<hex<<rv<< ")" << endl;
		return -1;
	}
	return 0;
}

int initPin(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE *pSession, char* userPin)
{
	CK_RV rv = p11->C_InitPIN(*pSession, (CK_UTF8CHAR_PTR)userPin, (CK_ULONG)strlen(userPin));
	if (rv != CKR_OK) {
		cout << "ERROR: Could not initialize the user PIN. (0x" << hex << rv << ")" << endl;
		return -1;
	}
	return 0;
}