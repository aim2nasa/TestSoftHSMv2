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

	unsigned long slotID = 1868647305;	//�ϵ��ڵ� ������: softhsm2-util.exe --show-slots�� ��ȸ�� ���� ���̵� �Է��ؾ� ��

	CK_SESSION_HANDLE hSession;
	CK_RV rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv == CKR_OK) {
		cout <<hex<< "openSession OK: 0x" << (unsigned long)rv << endl;
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