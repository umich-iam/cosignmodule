/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <windows.h>
#include <bcrypt.h>
#include "fbase64.h"
#include "CookieGenerator.h"
#include "Log.h"


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

	CosignLog( L"Making a cookie" );
	if ( algorithm == NULL ) {
		/// Should actually throw something
		return( -1 );
	}

	UCHAR	buf[ 1024 ];
	ULONG	bufSize = 1024;
	
	length-=3;
	bufSize = SZ_FBASE64_D( length );

	CosignLog( L"Randomly generating stuff" );
	/*status = */BCryptGenRandom( algorithm, buf, bufSize, 0 );

	CosignLog( L"Making cookie into fbase64" );
	fbase64_e( buf, bufSize, cookie );

	return( 0 );
}
