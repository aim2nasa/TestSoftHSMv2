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

	CK_C_GetFunctionList pGetFunctionList = NULL;

	FreeLibrary(hDLL);
	cout << "end of list slot" << endl;
	return 0;
}