#include <iostream>
#include <windows.h>
#include "cryptoki.h"

#define DEFAULT_PKCS11_LIB "softhsm2.dll"

using namespace std;

int showSlots(CK_FUNCTION_LIST_PTR p11);

int main(int argc, char* argv[]) {
	HINSTANCE hDLL = LoadLibraryA(DEFAULT_PKCS11_LIB);
	if (hDLL == NULL) {
		cout << "LoadLibraryA failed : " << GetLastError() << endl;
		return -1;
	}
	cout << DEFAULT_PKCS11_LIB<<" loaded" << endl;

	CK_C_GetFunctionList pGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hDLL, "C_GetFunctionList");
	if (pGetFunctionList == NULL) {
		cout << "getProcAddress failed : " << GetLastError() << endl;
		FreeLibrary(hDLL);
		return -1;
	}
	cout <<"0x"<<hex<< pGetFunctionList << " C_GetFunctionList retrived" << endl;

	// Load the function list
	CK_FUNCTION_LIST_PTR p11 = NULL;
	(*pGetFunctionList)(&p11);

	// Initialize the library
	if (p11->C_Initialize(NULL_PTR) != CKR_OK) {
		cout << "ERROR: Could not initialize the library" << endl;
		FreeLibrary(hDLL);
		return -1;
	}
	cout << "library initialized" << endl;

	showSlots(p11);

	FreeLibrary(hDLL);
	cout << "end of list slot" << endl;
	return 0;
}

int showSlots(CK_FUNCTION_LIST_PTR p11)
{
	CK_ULONG ulSlotCount;
	CK_RV rv = p11->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
	if (rv != CKR_OK) {
		cout << "Couldn't get the number of slots" << endl;
		return -1;
	}
	cout << "number of slots:" << ulSlotCount << endl;

	CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount*sizeof(CK_SLOT_ID));
	if (!pSlotList) {
		cout << "Couldn't allocate memory" << endl;
		return -1;
	}

	if (p11->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount) != CKR_OK) {
		cout << "Couldn't get the slot list" << endl;
		free(pSlotList);
		return -1;
	}

	for (CK_ULONG i = 0; i < ulSlotCount; i++) {

		CK_SLOT_INFO slotInfo;
		if (p11->C_GetSlotInfo(pSlotList[i], &slotInfo) != CKR_OK) {
			cout << "Couldn't get info about slot : 0x" << hex << pSlotList[i] << dec << " (" << pSlotList[i] << ")" << endl;
			continue;
		}
		cout << "Slot : 0x" << hex << pSlotList[i] << dec << " (" << pSlotList[i] << ")" << endl;
	}

	free(pSlotList);
	return 0;
}