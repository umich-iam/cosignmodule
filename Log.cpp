/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include "Log.h"

#define MSGCHARCOUNT 2048
//#define __ENABLE_LOGGING_


void
CosignLog( wchar_t* format, ... ) {
#ifdef __ENABLE_LOGGING_
	va_list	args;
	wchar_t	msg[ MSGCHARCOUNT ];
	size_t	msgSize = (sizeof(msg)) / (sizeof(wchar_t));
	int		result;

	va_start(args, format);
	result = vswprintf_s( msg, msgSize, format, args );
	va_end(args);

	if ( result < 0 ) {
		OutputDebugStringW( L"[CosignModule] An error occurred while logging");
		return;
	}
	std::wstring	wmsg;
	wmsg = L"[CosignModule] ";
	wmsg += msg;
	OutputDebugStringW( wmsg.c_str() );
#endif
}

void
CosignLog( char* format, ... ) {
#ifdef __ENABLE_LOGGING_
	va_list	args;
	char	msg[ MSGCHARCOUNT ];
	size_t	msgSize = (sizeof(msg)) / (sizeof(wchar_t));
	int		result;

	va_start(args, format);
	result = vsprintf_s( msg, msgSize, format, args );
	va_end(args);

	if ( result < 0 ) {
		OutputDebugStringA( "[CosignModule] An error occurred while logging");
		return;
	}
	std::string amsg;
	amsg = "[CosignModule] ";
	amsg += msg;
	OutputDebugStringA( amsg.c_str() );
#endif
}
