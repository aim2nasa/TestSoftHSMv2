#include <iostream>

using namespace std;

int main(int argc, char* argv[])
{
	if (argc < 3) {
		cout << "usage: deleteKeyTest <serial> <label>" << endl;
		return -1;
	}

	cout << "delete key test end" << endl;
	return 0;
}