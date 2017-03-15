#include <iostream>

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

	cout << "delete key test end" << endl;
	return 0;
}