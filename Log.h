
/*
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
*/

void CosignLog( WCHAR* format, ... );
void CosignLogA( char* format, ... );

class CosignError {

private:
	DWORD	err;
	int		line;
	char*	functionName;
	
public:

	CosignError( DWORD err, int	line, char*	functionName) {
		this->err = err;
		this->line = line;
		this->functionName = functionName;
	};
	
	void showError() {
		LPTSTR	errs;
		
		CosignLogA( "Function: %s\nLine: %d\nError: 0x%x\n", functionName, line, err );
		FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (LPTSTR)&errs, 0, NULL );
		CosignLog( errs );
		LocalFree( errs );
	};
};
