
#include <windows.h>
#include <string>
#include "Log.h"
#include "StringToWString.h"

int
StringToWString( std::string& str, std::wstring& wstr ) {

	DWORD	bufferSize = (DWORD)((str.length() + 1)*2);
	PWCHAR	buffer = new WCHAR[ bufferSize ];
	size_t	charsConverted;
	errno_t	err;

	err = mbstowcs_s( &charsConverted, buffer, bufferSize, str.c_str(), bufferSize - 1);
	if ( err != 0 ) {
		CosignLog( "mbstowcs_s( %s ) failed with %d", str.c_str(), err );
		return( -1 );
	}
	wstr = buffer;
	delete buffer;
	return( 0 );
}
