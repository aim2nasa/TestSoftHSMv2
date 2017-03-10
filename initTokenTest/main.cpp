#include <iostream>
#include "library.h"

using namespace std;

int initToken(CK_FUNCTION_LIST_PTR p11, unsigned long slotID, char *label, char* soPin);

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

	initToken(p11, atoi(argv[1]), argv[2], argv[3]);

	unloadLib(module);
	cout << "initToken test end" << endl;
	return 0;
}

int initToken(CK_FUNCTION_LIST_PTR p11, unsigned long slotID, char *label, char* soPin)
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
	cout << "InitToken OK" << endl;

	return 0;
}