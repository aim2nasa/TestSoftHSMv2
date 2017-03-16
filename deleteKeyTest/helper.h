#ifndef __HELPER_H__
#define __HELPER_H__

#include <string>

bool initSoftHSM();
void finalizeSoftHSM();
bool findTokenDirectory(std::string basedir, std::string& tokendir, char* serial, char* label);

#endif