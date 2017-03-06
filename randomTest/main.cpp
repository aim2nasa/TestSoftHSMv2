#include <iostream>
#include <assert.h>
#include "cryptoki.h"

using namespace std;

int main(int argc, char* argv[])
{
	CK_RV rv;

	rv = C_Finalize(NULL_PTR);
	assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	assert(rv == CKR_OK);

	cout << "end of main" << endl;
	return 0;
}