/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <iterator>
#include "Log.h"
#include "CosignServiceInfo.h"
#include "CookieDatabase.h"
#include "StringToWString.h"

CookieDatabase::CookieDatabase() {
}




void
CookieDatabase::Init( std::wstring& databasePath, ULONGLONG et, int hl, std::wstring& kerbDir, std::wstring& proxyDir  ) {

	path = databasePath;
	if ( path[ path.length() - 1 ] != '\\' &&
		path[ path.length() - 1 ] != '/' ) {
		path += L"\\";
	} 	
	expireTime = et;
	hashLength = hl;
	kerberosTicketsDirectory = kerbDir;
	proxyCookiesDirectory = proxyDir;
	/// xxx check for appropriate permissions in directory here?
	/// xxx check to make sure expireTime isn't really small?
}

CookieDatabase::~CookieDatabase() {
}

COSIGNSTATUS
CookieDatabase::CheckCookie( std::string& cookie, CosignServiceInfo* csi ) {

	std::wstring	wcookie;

	if ( StringToWString( cookie, wcookie ) == -1 ) {
		return( COSIGNERROR );
	}
	return( CheckCookie( wcookie, csi ) );
}

COSIGNSTATUS
CookieDatabase::CheckCookie( std::wstring& cookie, CosignServiceInfo* csi ) {

	HANDLE	hcf = INVALID_HANDLE_VALUE;
	std::wstring	cookiePath = L"\\\\?\\" + path + cookie;
	COSIGNSTATUS	status = COSIGNOK;

	CosignLog( L"cookiePath = %s", cookiePath.c_str() );

	try {
		hcf = CreateFile( cookiePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
		if ( hcf == INVALID_HANDLE_VALUE ) {
			/// xxx should check for a fatal error
			/// in particular, if the error is something like "file does not exist", that is ok
			CosignLog( L"Could not obtain file handle for %s: 0x%x", cookiePath.c_str(), GetLastError() );
			return( COSIGNOK );
		}
		FILETIME	fileTime;
		FILETIME	currentTime;

		if ( !GetFileTime( hcf, NULL, NULL, &fileTime ) ) {
			CosignLog( L"Could not obtain file write time for %s", cookiePath.c_str() );
			throw( CosignError( GetLastError(), __LINE__ -2, __FUNCTION__ ) );
		}
		GetSystemTimeAsFileTime( &currentTime );
		
		ULARGE_INTEGER	uliFt;
		ULARGE_INTEGER	uliCt;
		
		uliFt.HighPart = fileTime.dwHighDateTime;
		uliFt.LowPart = fileTime.dwLowDateTime;
		uliCt.HighPart = currentTime.dwHighDateTime;
		uliCt.LowPart = currentTime.dwLowDateTime;
		
		ULONGLONG diff = uliCt.QuadPart - uliFt.QuadPart;
		ULONGLONG seconds = diff / 10000000;
		ULONGLONG minutes;
		minutes = seconds / 60;
		seconds = seconds % 60;
		CosignLog( L"Local cookie cache is %u minutes and %u seconds stale", (unsigned int)minutes, (unsigned int)seconds );
		/// xxx sanity check?  Make sure currenttime is later than filetime?
		if ( diff > expireTime ) {
			CloseHandle( hcf );
			CosignLog( L"Cookie is too old." );
			return( COSIGNLOGGEDOUT );
		}

		/// xxx retrieve login info from local cookie file
		char	readBuffer[ READBUFFERSIZE ];
		DWORD	bytesRead;
		std::string	data = "";
		while( ReadFile( hcf, readBuffer, READBUFFERSIZE, &bytesRead, NULL ) ) {
			if ( bytesRead == 0 ) {
				// EOF
				break;
			}
			data.append( readBuffer, bytesRead );
		}
		CloseHandle( hcf );
		hcf = INVALID_HANDLE_VALUE;

		// extract lines from cookie file data and put them into a vector for processing.
		std::string::size_type			start = 0, end;
		std::vector<std::string>		lines;
		std::string						line;
		size_t							found;

		while (( end = data.find( '\n', start )) != data.npos ) {
			line = data.substr( start, end - start );
			found = line.find_last_not_of( "\r\n" );
			if ( found != line.npos ) {
				line.erase( found + 1 );
			}
			
			lines.push_back( line );
			start = end + 1;
		}

		// walk the vector looking for key lines.
		//
		// i: initial client IP address
		// p: user name (i.e., a user principal, in Kerberos terms)
		// r: realm (i.e., primary authenticating factor, often a Kerberos realm)
		// f: all authenticated factors, separated by whitespace.
		for ( std::vector<std::string>::iterator iter = lines.begin(); iter != lines.end(); iter++ ) {
			switch( (*iter)[ 0 ] ) {
				case 'i':
					csi->ipAddr = iter->substr( 1, iter->length() );
					break;
				case 'p':
					csi->user = iter->substr( 1, iter->length() );
					break;
				case 'r':
					csi->realm = iter->substr( 1, iter->length() );
					break;
				case 'f':
					csi->strFactors = iter->substr( 1, iter->length());
					// we split the whitespace-separated factor string into a vector below
					break;
				default:
					CosignLog( L"Cookie file contained unknown identifer %s", iter );
					break;
			}
		}

		std::stringstream	factorSplitter( csi->strFactors );
		copy( std::istream_iterator<std::string>( factorSplitter ),
				std::istream_iterator<std::string>(), std::back_inserter( csi->factors ));
		if ( csi->factors.size() < 1 ) {
			CosignLog( L"Incorrect number of arguments.  Expected at least 1, received %d",
						(int)csi->factors.size() );
			return( COSIGNERROR );
		}

		status = COSIGNLOGGEDIN;
	} catch ( CosignError ce ) {
		ce.showError();
		status = COSIGNERROR;
	}

	if ( hcf != INVALID_HANDLE_VALUE ) {
		CloseHandle( hcf );
	}
	CosignLog( L"Closed file handle!" );
	return( status );
}

COSIGNSTATUS
CookieDatabase::UpdateCookie( std::string& cookie ) {

	std::wstring	wcookie;
	
	StringToWString( cookie, wcookie );
	return( UpdateCookie( wcookie ) );
}

COSIGNSTATUS
CookieDatabase::UpdateCookie( std::wstring& cookie ) {

	FILETIME	curTime;
	HANDLE		hcf;
	DWORD		err;
	COSIGNSTATUS	status = COSIGNOK;
	std::wstring	cookiePath = L"\\\\?\\" + path + cookie;

	hcf = CreateFile( cookiePath.c_str(),
		FILE_WRITE_ATTRIBUTES,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL,
		NULL );
	if ( hcf == INVALID_HANDLE_VALUE ) {
		err = GetLastError();
		CosignLog( L"Could not update cookie time, CreateFile failed with 0x%x", err );
		//throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
		return( COSIGNERROR );
	}
	GetSystemTimeAsFileTime( &curTime );
	if ( !SetFileTime( hcf, NULL, NULL, &curTime ) ) {
		err = GetLastError();
		CosignLog( L"Could not update cookie time for %s, SetFileTime failed with 0x%x", cookiePath.c_str(), err );
		status = COSIGNERROR;
	}
	if ( !CloseHandle( hcf ) ) {
		err = GetLastError();
		CosignLog( L"Could not CloseHandle for file %s, CloseHandle failed with 0x%x", cookiePath.c_str(), err );
		status = COSIGNERROR;
	}
	return( status );
}



COSIGNSTATUS
CookieDatabase::StoreCookie( std::string& cookie, CosignServiceInfo* csi ) {
	std::wstring	wcookie;
	StringToWString( cookie, wcookie );
	return( StoreCookie( wcookie, csi ) );
}

COSIGNSTATUS
CookieDatabase::StoreCookie( std::wstring& cookie, CosignServiceInfo* csi ) {

	DWORD	err;
	WCHAR	tempFileName[ 32768 ];
	HANDLE hcf;
	COSIGNSTATUS	status = COSIGNOK;

	try {

	CosignLog( L"path = %s", path.c_str() );
	if ( GetTempFileName( path.c_str(), L"cck", 0, tempFileName ) == 0 ) {
		err = GetLastError();
		CosignLog( L"GetTempFileName failed with 0x%x", err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}
	CosignLog( L"tempFileName = %s", tempFileName );
	hcf = CreateFile( tempFileName,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_TEMPORARY,
		NULL );
	if ( hcf == INVALID_HANDLE_VALUE ) {
		err = GetLastError();
		CosignLog( L"CreateFile failed with 0x%x", err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}

	std::string out = "i" + csi->ipAddr + "\r\n";
	DWORD	bytesWritten = 0;
	if ( !WriteFile( hcf,
		out.c_str(),
		(DWORD)out.length(),
		&bytesWritten,
		NULL ) ) {

		err = GetLastError();
		CosignLog( L"WriteFile(%s) failed with 0x%x", out.c_str(), err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}

	out = "p" + csi->user + "\r\n";
	bytesWritten = 0;
	if ( !WriteFile( hcf,
		out.c_str(),
		(DWORD)out.length(),
		&bytesWritten,
		NULL ) ) {

		err = GetLastError();
		CosignLog( L"WriteFile(%s) failed with 0x%x", out.c_str(), err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}

	out = "r" + csi->realm + "\r\n";
	bytesWritten = 0;
	if ( !WriteFile( hcf,
		out.c_str(),
		(DWORD)out.length(),
		&bytesWritten,
		NULL ) ) {

		err = GetLastError();
		CosignLog( L"WriteFile(%s) failed with 0x%x", out.c_str(), err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}

	out = "f" + csi->strFactors + "\r\n";
	bytesWritten = 0;
	if ( !WriteFile( hcf,
		out.c_str(),
		(DWORD)out.length(),
		&bytesWritten,
		NULL ) ) {

		err = GetLastError();
		CosignLog( L"WriteFile(%s) failed with 0x%x", out.c_str(), err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}

	if ( hcf != INVALID_HANDLE_VALUE ) {
		CloseHandle( hcf );
	}

	std::wstring	cookiePath = path + cookie;
	if ( !CopyFileEx( tempFileName, cookiePath.c_str(), NULL, NULL, FALSE, 0 ) ) {
		err = GetLastError();
		CosignLog( L"Could not copy file %s to %s: 0x%x", tempFileName, cookiePath.c_str(), err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}
	if ( !DeleteFile( tempFileName ) ) {
		err = GetLastError();
		CosignLog( L"Could not delete temp file %s: 0x%x", tempFileName, err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}

	} catch ( CosignError ce ) {
		ce.showError();
		if ( hcf != INVALID_HANDLE_VALUE ) {
			CloseHandle( hcf );
		}
		return( COSIGNERROR );
	}
	CloseHandle( hcf );
	
	return( status );
}
