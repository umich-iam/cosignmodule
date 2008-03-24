/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
*/

#define COSIGNTRACE

void CosignLog( wchar_t* format, ... );
void CosignLog( char* format, ... );
#ifdef COSIGNTRACE
#define CosignTrace0( format ) CosignLog( format )
#define CosignTrace1( format, arg1 ) CosignLog( format, arg1 )
#define CosignTrace2( msg, arg1, arg2 ) CosignLog( msg, arg1, arg2 )
#define CosignTrace3( msg, arg1, arg2, arg3 ) CosignLog( msg, arg1, arg2, arg3 )
#else
#define CosignTrace0( format ) 
#define CosignTrace1( format, arg1 )
#define CosignTrace2( msg, arg1, arg2 )
#define CosignTrace2( msg, arg1, arg2, arg3 )
#endif

class CosignError {

private:
	DWORD	err;
	int		line;
	char*	fileName;
	
public:

	CosignError( DWORD err, int	line, char*	fileName) {
		this->err = err;
		this->line = line;
		this->fileName = fileName;
	};
	
	void showError() {
		LPTSTR	errs;
		
		CosignLog( "Function: %s\nLine: %d\nError: 0x%x\n", fileName, line, err );
		if ( FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			err,
			0,
			(LPTSTR)&errs,
			0,
			NULL ) == 0 ) {
			CosignLog( "Could not find message for error code 0x%x.", err );
		} else {
			CosignLog( errs );
			LocalFree( errs );
		}
	};

	DWORD getError() { return( err ); }

};
