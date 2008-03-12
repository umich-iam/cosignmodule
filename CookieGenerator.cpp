
#include <windows.h>
#include <bcrypt.h>
#include "fbase64.h"
#include "CookieGenerator.h"


CookieGenerator::CookieGenerator() {
	NTSTATUS status = BCryptOpenAlgorithmProvider( &algorithm, BCRYPT_RNG_ALGORITHM, NULL, 0 );
	if ( status < 0 ) {
		algorithm = NULL;
	}
}

CookieGenerator::~CookieGenerator() {
	if ( algorithm != NULL ) {
		BCryptCloseAlgorithmProvider( algorithm, 0 );	
	}
}
DWORD CookieGenerator::MakeCookie( char* cookie, int length ) {

	/// XXX Need sanity checking to make sure buffers are large enough!

	OutputDebugString( L"Making a cookie" );
	if ( algorithm == NULL ) {
		/// Should actually throw something
		return( -1 );
	}

	UCHAR	buf[ 1024 ];
	ULONG	bufSize = 1024;
	
	length-=3;
	bufSize = SZ_FBASE64_D( length );

	OutputDebugString( L"Randomly generating stuff" );
	/*status = */BCryptGenRandom( algorithm, buf, bufSize, 0 );

	OutputDebugString( L"Making cookie into fbase64" );
	fbase64_e( buf, bufSize, cookie );

	return( 0 );
}
