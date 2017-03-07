#include <iostream>
#include <windows.h>
#include "cryptoki.h"

#define DEFAULT_PKCS11_LIB "softhsm2.dll"

using namespace std;

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
		return NULL;
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

	FreeLibrary(hDLL);
	cout << "end of list slot" << endl;
	return 0;
}