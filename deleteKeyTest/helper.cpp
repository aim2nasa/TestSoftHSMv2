#include "helper.h"
#include "MutexFactory.h"
#include "SecureMemoryRegistry.h"

#ifdef HAVE_CXX11

std::unique_ptr<MutexFactory> MutexFactory::instance(nullptr);
std::unique_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(nullptr);

#else

std::auto_ptr<MutexFactory> MutexFactory::instance(NULL);
std::auto_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(NULL);

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

	return true;
}

void finalizeSoftHSM()
{

}