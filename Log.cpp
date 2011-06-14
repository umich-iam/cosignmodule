/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include "Log.h"

#define __ENABLE_LOGGING_


void
CosignLog( wchar_t* format, ... ) {
#ifdef __ENABLE_LOGGING_
	va_list	args;
	wchar_t* msg;
	size_t	msgSize;
	int		result;

	va_start(args, format);
	msgSize = _vscwprintf( format, args ) + 1;
	msg = (wchar_t*)malloc( msgSize * sizeof(wchar_t));
	if ( msg == NULL ) {
		OutputDebugStringW( L"[CosignModule] Insufficient memory for logging.");
		return;
	}
	result = vswprintf_s( msg, msgSize, format, args );
	va_end(args);

	if ( result < 0 ) {
		OutputDebugStringW( L"[CosignModule] An error occurred while logging");
		free( msg );
		return;
	}
	std::wstring	wmsg;
	wmsg = L"[CosignModule] ";
	wmsg += msg;
	OutputDebugStringW( wmsg.c_str() );
	free( msg );
#endif
}

void
CosignLog( char* format, ... ) {
#ifdef __ENABLE_LOGGING_
	va_list	args;
	char*	msg;
	size_t	msgSize;
	int		result;

	va_start(args, format);
	msgSize = _vscprintf( format, args ) + 1;
	msg = (char*)malloc( msgSize * sizeof(char)) ;
	if ( msg == NULL ) {
		OutputDebugStringW( L"[CosignModule] Insufficient memory for logging.");
		return;
	}
	result = vsprintf_s( msg, msgSize, format, args );
	va_end(args);

	if ( result < 0 ) {
		OutputDebugStringA( "[CosignModule] An error occurred while logging");
		free( msg );
		return;
	}
	std::string amsg;
	amsg = "[CosignModule] ";
	amsg += msg;
	OutputDebugStringA( amsg.c_str() );
	free( msg );
#endif
}
