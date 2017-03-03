#include <iostream>
#include "cryptoki.h"

using namespace std;

int main(int argc, char* argv[])
{
	CK_RV rv;

	C_Finalize(NULL_PTR);

	cout << "end of main" << endl;
	return 0;
}