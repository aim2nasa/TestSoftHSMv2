#include <iostream>
#include "library.h"

using namespace std;

int main(int argc, char* argv[]) {
	void* module;
	CK_FUNCTION_LIST_PTR p11 = NULL;
	if (loadLib(&module, &p11) == -1) {
		cout << "ERROR: loadLib" << endl;
		return -1;
	}
	cout << "loadLib ok" << endl;

	unsigned long slotID = 1868647305;	//하드코딩 변수임: softhsm2-util.exe --show-slots로 조회된 슬롯 아이디를 입력해야 함

	CK_SESSION_HANDLE hSession;
	CK_RV rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv == CKR_OK) {
		cout <<hex<< "openSession OK: 0x" << (unsigned long)rv << endl;

		char userPin[] = "1234";	//하드코딩 변수임: user PIN을 1234로 입력했다고 가정함

		rv = p11->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)userPin, (CK_ULONG)strlen(userPin));
		if (rv == CKR_OK) {
			cout << hex << "user login OK: 0x" << (unsigned long)rv << endl;

			const char  *pLabel = "MyToken 1";
			CK_ATTRIBUTE attribs[] = {
				{ CKA_LABEL, (CK_UTF8CHAR_PTR)pLabel, (CK_ULONG)strlen(pLabel) }
			};

			rv = p11->C_FindObjectsInit(hSession, &attribs[0], 0);
			if (rv == CKR_OK) {
				cout << hex << "FindObject Init OK: 0x" << (unsigned long)rv << endl;

				CK_OBJECT_HANDLE hObjects[16];
				CK_ULONG ulObjectCount = 0;
				rv = p11->C_FindObjects(hSession, &hObjects[0], 16, &ulObjectCount);
				if (rv == CKR_OK) {
					cout << hex << "FindObject OK: 0x" << (unsigned long)rv <<dec<<",objectCount="<<ulObjectCount<< endl;

					rv = p11->C_FindObjectsFinal(hSession);
					if (rv == CKR_OK) {
						cout << hex << "FindObjectsFinal OK: 0x" << (unsigned long)rv << endl;
					}
					else{
						cout << hex << "FindObjectsFinal failed: 0x" << (unsigned long)rv << endl;
						unloadLib(module);
						return -1;
					}
				}
				else{
					cout << hex << "FindObject failed: 0x" << (unsigned long)rv << endl;
					unloadLib(module);
					return -1;
				}
			}
			else{
				cout << hex << "FindObject Init failed: 0x" << (unsigned long)rv << endl;
				unloadLib(module);
				return -1;
			}

		}else{
			cout << hex << "user login failed: 0x" << (unsigned long)rv << endl;
			unloadLib(module);
			return -1;
		}
	}
	else{
		cout <<hex<< "openSession failed: 0x" << (unsigned long)rv << endl;
		unloadLib(module);
		return -1;
	}

	unloadLib(module);
	cout << "private object test end" << endl;
	return 0;
}