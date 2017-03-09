#include <iostream>
#include "library.h"

using namespace std;

int initToken(CK_FUNCTION_LIST_PTR p11);

int main(int argc, char* argv[])
{
	void* module;
	CK_FUNCTION_LIST_PTR p11 = NULL;
	if (loadLib(&module, &p11) == -1) {
		cout << "ERROR: loadLib" << endl;
		return -1;
	}
	cout << "loadLib ok" << endl;

	initToken(p11);

	unloadLib(module);
	cout << "initToken test end" << endl;
	return 0;
}

int initToken(CK_FUNCTION_LIST_PTR p11)
{
	return 0;
}