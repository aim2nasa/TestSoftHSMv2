#include "helper.h"
#include "MutexFactory.h"
#include "SecureMemoryRegistry.h"
#include "CryptoFactory.h"
#include "Configuration.h"
#include "SimpleConfigLoader.h"
#include "ObjectStoreToken.h"

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

}