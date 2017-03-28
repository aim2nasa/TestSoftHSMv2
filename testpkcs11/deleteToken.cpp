#include "deleteToken.h"

class CSoftHsm{
public:
	CSoftHsm(){ initSoftHSM(); }
	~CSoftHsm(){ finalizeSoftHSM(); }
};

int deleteToken(char *serial, char* token)
{
	CSoftHsm sHsm;	//���ÿ� �ξ� �ڵ����� �����ڿ� �Ҹ��ڰ� ȣ��ǵ���

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
			return 0;
		}
		else{
			return -2;
		}
	}
	return -1;
}