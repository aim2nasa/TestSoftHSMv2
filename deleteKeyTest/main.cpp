#include <iostream>
#include "helper.h"
#include "Configuration.h"
#include "OSPathSep.h"

using namespace std;

int main(int argc, char* argv[])
{
	if (argc < 3) {
		cout << "usage: deleteKeyTest <serial> <label>" << endl;
		return -1;
	}

	char* serial = NULL;
	if (strlen(argv[1]) > 0) serial = argv[1];

	char* token = NULL;
	if (strlen(argv[2]) > 0) token = argv[2];

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

	if (findTokenDirectory(basedir, tokendir, serial, token))
	{
		std::string fulldir = basedir;
		if (fulldir.find_last_of(OS_PATHSEP) != (fulldir.size() - 1))
		{
			fulldir += OS_PATHSEP + tokendir;
		}
		else
		{
			fulldir += tokendir;
		}

		if (rmdir(fulldir))
		{
			printf("The token (%s) has been deleted.\n", fulldir.c_str());
		}
	}

	finalizeSoftHSM();
	cout << "delete key test end" << endl;
	return 0;
}