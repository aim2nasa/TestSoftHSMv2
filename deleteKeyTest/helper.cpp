#include "helper.h"
#include "MutexFactory.h"
#include "SecureMemoryRegistry.h"
#include "CryptoFactory.h"
#include "Configuration.h"
#include "SimpleConfigLoader.h"
#include "ObjectStoreToken.h"
#include "Directory.h"

#if defined(WITH_OPENSSL)
#include "OSSLCryptoFactory.h"
#else
#include "BotanCryptoFactory.h"
#endif

#ifdef HAVE_CXX11

std::unique_ptr<MutexFactory> MutexFactory::instance(nullptr);
std::unique_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(nullptr);
#if defined(WITH_OPENSSL)
std::unique_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(nullptr);
#else
std::unique_ptr<BotanCryptoFactory> BotanCryptoFactory::instance(nullptr);
#endif

#else

std::auto_ptr<MutexFactory> MutexFactory::instance(NULL);
std::auto_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(NULL);
#if defined(WITH_OPENSSL)
std::auto_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(NULL);
#else
std::auto_ptr<BotanCryptoFactory> BotanCryptoFactory::instance(NULL);
#endif

#endif

bool initSoftHSM()
{
	// Not using threading
	MutexFactory::i()->disable();

	// Initiate SecureMemoryRegistry
	if (SecureMemoryRegistry::i() == NULL)
	{
		fprintf(stderr, "ERROR: Could not initiate SecureMemoryRegistry.\n");
		return false;
	}

	// Build the CryptoFactory
	if (CryptoFactory::i() == NULL)
	{
		fprintf(stderr, "ERROR: Could not initiate CryptoFactory.\n");
		return false;
	}

#ifdef WITH_FIPS
	// Check the FIPS status
	if (!CryptoFactory::i()->getFipsSelfTestStatus())
	{
		fprintf(stderr, "ERROR: FIPS self test failed.\n");
		return false;
	}
#endif

	// Load the configuration
	if (!Configuration::i()->reload(SimpleConfigLoader::i()))
	{
		fprintf(stderr, "ERROR: Could not load the SoftHSM configuration.\n");
		return false;
	}

	// Configure the log level
	if (!setLogLevel(Configuration::i()->getString("log.level", DEFAULT_LOG_LEVEL)))
	{
		fprintf(stderr, "ERROR: Could not configure the log level.\n");
		return false;
	}

	// Configure object store storage backend used by all tokens.
	if (!ObjectStoreToken::selectBackend(Configuration::i()->getString("objectstore.backend", DEFAULT_OBJECTSTORE_BACKEND)))
	{
		fprintf(stderr, "ERROR: Could not select token backend.\n");
		return false;
	}

	return true;
}

void finalizeSoftHSM()
{
	CryptoFactory::reset();
	SecureMemoryRegistry::reset();
}

// Find the token directory
bool findTokenDirectory(std::string basedir, std::string& tokendir, char* serial, char* label)
{
	if (serial == NULL && label == NULL)
	{
		return false;
	}

	// Load the variables
	CK_UTF8CHAR paddedSerial[16];
	CK_UTF8CHAR paddedLabel[32];
	if (serial != NULL)
	{
		size_t inSize = strlen(serial);
		size_t outSize = sizeof(paddedSerial);
		if (inSize > outSize)
		{
			fprintf(stderr, "ERROR: --serial is too long.\n");
			return false;
		}
		memset(paddedSerial, ' ', outSize);
		memcpy(paddedSerial, serial, inSize);
	}
	if (label != NULL)
	{
		size_t inSize = strlen(label);
		size_t outSize = sizeof(paddedLabel);
		if (inSize > outSize)
		{
			fprintf(stderr, "ERROR: --token is too long.\n");
			return false;
		}
		memset(paddedLabel, ' ', outSize);
		memcpy(paddedLabel, label, inSize);
	}

	// Find all tokens in the specified path
	Directory storeDir(basedir);

	if (!storeDir.isValid())
	{
		fprintf(stderr, "Failed to enumerate object store in %s", basedir.c_str());

		return false;
	}

	// Assume that all subdirectories are tokens
	std::vector<std::string> dirs = storeDir.getSubDirs();

	ByteString tokenLabel;
	ByteString tokenSerial;
	CK_UTF8CHAR paddedTokenSerial[16];
	CK_UTF8CHAR paddedTokenLabel[32];
	size_t counter = 0;
	for (std::vector<std::string>::iterator i = dirs.begin(); i != dirs.end(); i++)
	{
		memset(paddedTokenSerial, ' ', sizeof(paddedTokenSerial));
		memset(paddedTokenLabel, ' ', sizeof(paddedTokenLabel));

		// Create a token instance
		ObjectStoreToken* token = ObjectStoreToken::accessToken(basedir, *i);

		if (!token->isValid())
		{
			delete token;
			continue;
		}

		if (token->getTokenLabel(tokenLabel) && tokenLabel.size() <= sizeof(paddedTokenLabel))
		{
			strncpy((char*)paddedTokenLabel, (char*)tokenLabel.byte_str(), tokenLabel.size());
		}
		if (token->getTokenSerial(tokenSerial) && tokenSerial.size() <= sizeof(paddedTokenSerial))
		{
			strncpy((char*)paddedTokenSerial, (char*)tokenSerial.byte_str(), tokenSerial.size());
		}

		if (serial != NULL && label == NULL &&
			memcmp(paddedTokenSerial, paddedSerial, sizeof(paddedSerial)) == 0)
		{
			printf("Found token (%s) with matching serial.\n", i->c_str());
			tokendir = i->c_str();
			counter++;
		}
		if (serial == NULL && label != NULL &&
			memcmp(paddedTokenLabel, paddedLabel, sizeof(paddedLabel)) == 0)
		{
			printf("Found token (%s) with matching token label.\n", i->c_str());
			tokendir = i->c_str();
			counter++;
		}
		if (serial != NULL && label != NULL &&
			memcmp(paddedTokenSerial, paddedSerial, sizeof(paddedSerial)) == 0 &&
			memcmp(paddedTokenLabel, paddedLabel, sizeof(paddedLabel)) == 0)
		{
			printf("Found token (%s) with matching serial and token label.\n", i->c_str());
			tokendir = i->c_str();
			counter++;
		}

		delete token;
	}

	if (counter == 1) return true;
	if (counter > 1)
	{
		fprintf(stderr, "ERROR: Found multiple matching tokens.\n");
		return false;
	}

	fprintf(stderr, "ERROR: Could not find a token using --serial or --token.\n");
	return false;
}