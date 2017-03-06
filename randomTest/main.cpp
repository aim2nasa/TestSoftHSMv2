#include <iostream>
#include <assert.h>
#include "cryptoki.h"

using namespace std;

int main(int argc, char* argv[])
{
	CK_RV rv;
	CK_SLOT_ID initializedTokenSlotID = 0; //잘못된 의미없는 Slot ID 부여
	CK_SESSION_HANDLE hSession;

	rv = C_Finalize(NULL_PTR);
	assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	assert(rv == CKR_OK);

	rv = C_OpenSession(initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	assert(rv == CKR_SLOT_ID_INVALID);

	cout << "end of main" << endl;
	return 0;
}