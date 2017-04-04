#include <pkcs11.h>

int signVerifySingle(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param = NULL_PTR, CK_ULONG paramLen = 0);
int signVerifyMulti(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_VOID_PTR param = NULL_PTR, CK_ULONG paramLen = 0);