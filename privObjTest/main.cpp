#include <iostream>
#include <assert.h>
#include "library.h"

using namespace std;

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;

CK_RV createDataObjectMinimal(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject, CK_UTF8CHAR_PTR label);

int main(int argc, char* argv[]) {
	if (argc < 3) {
		cout << "usage: privObjTest <slot id> <userPin>" << endl;
		return -1;
	}

	void* module;
	CK_FUNCTION_LIST_PTR p11 = NULL;
	int nRtn = loadLib(&module, &p11);
	assert(nRtn != -1);
	cout << "loadLib ok" << endl;

	unsigned long slotID = atoi(argv[1]);

	CK_SESSION_HANDLE hSession;
	CK_RV rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	assert(rv ==CKR_OK);
	cout << hex << "openSession OK: 0x" << (unsigned long)rv << endl;

	char *userPin = argv[2];
	rv = p11->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)userPin, (CK_ULONG)strlen(userPin));
	assert(rv == CKR_OK);
	cout << hex << "user login OK: 0x" << (unsigned long)rv << endl;

	const char  *pLabel = "VeraCrypt secret1";
	CK_OBJECT_HANDLE hObjectTokenPrivate;
	rv = createDataObjectMinimal(hSession, ON_TOKEN, IS_PRIVATE, hObjectTokenPrivate, (CK_UTF8CHAR_PTR)pLabel);
	assert(rv == CKR_OK);

	CK_ATTRIBUTE attribs[] = {
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)pLabel, (CK_ULONG)strlen(pLabel) }
	};

	rv = p11->C_FindObjectsInit(hSession, &attribs[0], 1);	//1이면 attribute에 지정된 속성을 검색하고 0이면 이에 상관없이 모든 object를 찾는다
	assert(rv == CKR_OK);
	cout << hex << "FindObject Init OK: 0x" << (unsigned long)rv << endl;

	CK_OBJECT_HANDLE hObjects[16];
	CK_ULONG ulObjectCount = 0;
	rv = p11->C_FindObjects(hSession, &hObjects[0], 16, &ulObjectCount);
	assert(rv == CKR_OK);
	cout << hex << "FindObject OK: 0x" << (unsigned long)rv << dec << ",objectCount=" << ulObjectCount << endl;

	rv = p11->C_FindObjectsFinal(hSession);
	assert(rv == CKR_OK);
	cout << hex << "FindObjectsFinal OK: 0x" << (unsigned long)rv << endl;

	unloadLib(module);
	cout << "private object test end" << endl;
	return 0;
}

CK_RV createDataObjectMinimal(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hObject, CK_UTF8CHAR_PTR label)
{
	CK_OBJECT_CLASS cClass = CKO_DATA;
	CK_ATTRIBUTE objTemplate[] = {
		// Common
		{ CKA_CLASS, &cClass, sizeof(cClass) },

		// Storage
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		//CKA_MODIFIABLE
		{ CKA_LABEL, label, (CK_ULONG)strlen((char*)label) },
		//CKA_COPYABLE

		// Data
	};

	hObject = CK_INVALID_HANDLE;
	return C_CreateObject(hSession, objTemplate, sizeof(objTemplate) / sizeof(CK_ATTRIBUTE), &hObject);
}