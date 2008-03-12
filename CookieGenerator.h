
/*
#include <windows.h>
#include <bcrypt.h>
#include "fbase64.h"
*/

class CookieGenerator {

public:
	CookieGenerator();
	~CookieGenerator();
	DWORD MakeCookie( char* cookie, int length );

private:
	BCRYPT_ALG_HANDLE algorithm;
};