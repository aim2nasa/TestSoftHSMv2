#include <iostream>
#include <windows.h>
#include "cryptoki.h"

#define DEFAULT_PKCS11_LIB "softhsm2.dll"

using namespace std;

int showSlots(CK_FUNCTION_LIST_PTR p11);

int main(int argc, char* argv[]) {
	HINSTANCE hDLL = LoadLibraryA(DEFAULT_PKCS11_LIB);
	if (hDLL == NULL) {
		cout << "ERROR: LoadLibraryA failed : " << GetLastError() << endl;
		return -1;
	}
	cout << DEFAULT_PKCS11_LIB<<" loaded" << endl;

	CK_C_GetFunctionList pGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hDLL, "C_GetFunctionList");
	if (pGetFunctionList == NULL) {
		cout << "ERROR: getProcAddress failed : " << GetLastError() << endl;
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
	cout << "end of show slots" << endl;
	return 0;
}

int showSlots(CK_FUNCTION_LIST_PTR p11)
{
	CK_ULONG ulSlotCount;
	CK_RV rv = p11->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
	if (rv != CKR_OK) {
		cout << "ERROR: Couldn't get the number of slots" << endl;
		return -1;
	}
	cout << "number of slots:" << ulSlotCount << endl;

	CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount*sizeof(CK_SLOT_ID));
	if (!pSlotList) {
		cout << "ERROR: Couldn't allocate memory" << endl;
		return -1;
	}

	if (p11->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount) != CKR_OK) {
		cout << "ERROR: Couldn't get the slot list" << endl;
		free(pSlotList);
		return -1;
	}

	for (CK_ULONG i = 0; i < ulSlotCount; i++) {

		CK_SLOT_INFO slotInfo;
		if (p11->C_GetSlotInfo(pSlotList[i], &slotInfo) != CKR_OK) {
			cout << "ERROR: Couldn't get info about slot : 0x" << hex << pSlotList[i] << dec << " (" << pSlotList[i] << ")" << endl;
			continue;
		}
		cout << "Slot : 0x" << hex << pSlotList[i] << dec << " (" << pSlotList[i] << ")" << endl;

		cout << "\tSlot info :" << endl;
		string str;

		str.assign((char*)&slotInfo.slotDescription, sizeof(slotInfo.slotDescription));
		cout << "\t\tDescription :" << str.c_str() << endl;
		str.assign((char*)&slotInfo.manufacturerID, sizeof(slotInfo.manufacturerID));
		cout << "\t\tManufacturer ID :" << str.c_str() << endl;
		cout << "\t\tHardware version :" << (int)slotInfo.hardwareVersion.major << "." << (int)slotInfo.hardwareVersion.minor << endl;
		cout << "\t\tFirmware version :" << (int)slotInfo.firmwareVersion.major << "." << (int)slotInfo.firmwareVersion.minor << endl;
		cout << "\t\tToken present :";
		if ((slotInfo.flags & CKF_TOKEN_PRESENT) == 0) {
			cout << "no" << endl;
			continue;
		}
		cout << "yes" << endl;

		CK_TOKEN_INFO tokenInfo;
		if (p11->C_GetTokenInfo(pSlotList[i], &tokenInfo) != CKR_OK) {
			cout << "Couldn't get token info in slot : 0x" << hex << pSlotList[i] << dec << " (" << pSlotList[i] << ")" << endl;
			continue;
		}
		cout << "\tGet token info in slot : 0x" << hex << pSlotList[i] << dec << " (" << pSlotList[i] << ")" << endl;

		cout << "\tToken info :" << endl;

		str.assign((char*)&tokenInfo.manufacturerID, sizeof(tokenInfo.manufacturerID));
		cout << "\t\tManufacturer ID :" << str.c_str() << endl;
		str.assign((char*)&tokenInfo.model, sizeof(tokenInfo.model));
		cout << "\t\tModel :" << str.c_str() << endl;
		cout << "\t\tHardware version :" << (int)tokenInfo.hardwareVersion.major << "." << (int)tokenInfo.hardwareVersion.minor << endl;
		cout << "\t\tFirmware version :" << (int)tokenInfo.firmwareVersion.major << "." << (int)tokenInfo.firmwareVersion.minor << endl;
		str.assign((char*)&tokenInfo.serialNumber, sizeof(tokenInfo.serialNumber));
		cout << "\t\tSerial number :" << str.c_str() << endl;
		cout << "\t\tInitialized :";
		if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == 0)
			cout << "no" << endl;
		else
			cout << "yes" << endl;

		cout << "\t\tUser PIN init :";
		if ((tokenInfo.flags & CKF_USER_PIN_INITIALIZED) == 0)
			cout << "no" << endl;
		else
			cout << "yes" << endl;

		str.assign((char*)&tokenInfo.label, sizeof(tokenInfo.label));
		cout << "\t\tLabel :" << str.c_str() << endl;
	}

	free(pSlotList);
	return 0;
}