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

	CK_ULONG ulSlotCount;
	CK_RV rv = p11->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
	if (rv != CKR_OK) {
		cout << "ERROR: Couldn't get the number of slots: 0x" << hex << rv << endl;
		return -1;
	}
	cout << "number of slots:" << ulSlotCount << endl;

	CK_SLOT_ID slotID = ulSlotCount - 1; //����Ʈ�� ���� �Ѱ��� ī��Ʈ�� �����Ѵ�. ������ �ϳ��� �������� ī��Ʈ�� 1�� �����Ƿ�
	cout << "SlotID : 0x" << hex << slotID << dec << " (" << slotID << ")" << endl;

	unloadLib(module);
	cout << "end of testpkcs11" << endl;
	return 0;
}