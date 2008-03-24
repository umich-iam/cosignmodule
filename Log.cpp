/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "Log.h"

#define MSGCHARCOUNT 2048

void
CosignLog( wchar_t* format, ... ) {
	va_list	args;
	wchar_t	msg[ MSGCHARCOUNT ];
	size_t	msgSize = (sizeof(msg)) / (sizeof(wchar_t));
	int		result;

	va_start(args, format);
	result = vswprintf( msg, msgSize, format, args );
	va_end(args);

	if ( result < 0 ) {
		OutputDebugStringW( L"An error occurred while logging");
		return;
	}
	OutputDebugStringW( msg );
}

void
CosignLog( char* format, ... ) {
	va_list	args;
	char	msg[ MSGCHARCOUNT ];
	size_t	msgSize = (sizeof(msg)) / (sizeof(wchar_t));
	int		result;

	va_start(args, format);
	result = vsprintf_s( msg, msgSize, format, args );
	va_end(args);

	if ( result < 0 ) {
		OutputDebugStringA( "An error occurred while logging");
		return;
	}
	OutputDebugStringA( msg );
}
