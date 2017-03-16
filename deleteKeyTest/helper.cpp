#include "helper.h"
#include "MutexFactory.h"

#ifdef HAVE_CXX11

std::unique_ptr<MutexFactory> MutexFactory::instance(nullptr);

#else

std::auto_ptr<MutexFactory> MutexFactory::instance(NULL);

#endif

bool initSoftHSM()
{
	// Not using threading
	MutexFactory::i()->disable();
	return true;
}

void finalizeSoftHSM()
{

}