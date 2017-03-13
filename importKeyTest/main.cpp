#include <iostream>
#include "library.h"

using namespace std;

int main(int argc, char* argv[])
{
	if (argc < 8) {
		cout << "usage: importKeyTest <slot id> <userPin> <obj id> <label> <file> <filePin> <noPublicKey>" << endl;
		return -1;
	}

	void* module;
	CK_FUNCTION_LIST_PTR p11 = NULL;
	if (loadLib(&module, &p11) == -1) {
		cout << "ERROR: loadLib" << endl;
		return -1;
	}
	cout << "loadLib ok" << endl;

	unloadLib(module);
	cout << "import key test end" << endl;
	return 0;
}