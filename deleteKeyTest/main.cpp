#include <iostream>
#include "helper.h"
#include "Configuration.h"

using namespace std;

int main(int argc, char* argv[])
{
	if (argc < 3) {
		cout << "usage: deleteKeyTest <serial> <label>" << endl;
		return -1;
	}

	char* serial = argv[1];
	char* token = argv[2];

	if (serial == NULL && token == NULL) {
		fprintf(stderr, "ERROR: A token must be supplied. "
			"Use --serial <serial> or --token <label>\n");
		return -1;
	}

	// Initialize the SoftHSM internal functions
	if (!initSoftHSM()) {
		finalizeSoftHSM();
		return -1;
	}

	std::string basedir = Configuration::i()->getString("directories.tokendir", DEFAULT_TOKENDIR);
	std::string tokendir;

	cout << "delete key test end" << endl;
	return 0;
}