#include <iostream>
#include <windows.h>

#define DEFAULT_PKCS11_LIB "softhsm2.dll"

using namespace std;

int main(int argc, char* argv[]) {
	HINSTANCE hDLL = LoadLibraryA(DEFAULT_PKCS11_LIB);
	if (hDLL == NULL) {
		// Failed to load the PKCS #11 library
		DWORD dw = GetLastError();
		cout << "LoadLibraryA failed : " << GetLastError() << endl;
		return -1;
	}
	cout << DEFAULT_PKCS11_LIB<<" loaded" << endl;

	FreeLibrary(hDLL);
	cout << "end of list slot" << endl;
	return 0;
}