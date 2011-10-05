/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#define SECURITY_WIN32

#include <ws2tcpip.h>
#include <security.h>
#include <schnlsp.h>
#include <string>
#include <vector>
#include <sstream>
#include <iterator>
#include <windows.h>
#include "Snetpp.h"
#include "CosignServiceInfo.h"
#include "ConnectionList.h"
#include "StringToWString.h"
#include "Log.h"

bool
ConnectionList::getProxyCookies() {
		CosignLog( L"proxyCookiesDirectory is set to %s", proxyCookiesDirectory.c_str() );
		CosignLog( L"proxyCookiesDirector.empty() = %s", (proxyCookiesDirectory.empty() ? L"true" : L"false" ) );
		if ( proxyCookiesDirectory == L"\\\\?\\" || proxyCookiesDirectory.empty() ) {
			if ( proxyCookiesDirectory == L"\\\\?\\" ) {
				CosignLog( L"proxyCookiesDirectory == \\\\?\\" );
			}
			if ( proxyCookiesDirectory.empty() ) {
				CosignLog( L"proxyCookiesDirectory.empty()" );
			}
			return( false );
		}
		return( true );
	}
ConnectionList::ConnectionList() {
	numServers = 0;
	certificateContext = NULL;
	curConnection = NULL;
	port = -1;
	mutex = INVALID_HANDLE_VALUE;
}

ConnectionList::~ConnectionList() {
	/// xxx maybe shouldn't wait forever?
	CosignTrace0( L"Waiting for mutex before destructing." );
	WaitForSingleObject( mutex, INFINITE );
	CosignTrace0( L"Obtained mutex.  Deconstruction continues." );
	CloseHandle( mutex );
	Depopulate();
	CertFreeCertificateContext( certificateContext );
}

void
ConnectionList::Init( std::wstring& s, int p, PCCERT_CONTEXT ctx, std::wstring& kerbDir, std::wstring& proxyDir ) {


	server = s;
	port = p;
	certificateContext = ctx;
	mutex = CreateMutex( NULL, FALSE, NULL );
	if ( mutex == NULL ) {
		throw( CosignError( (DWORD)GetLastError(), __LINE__ - 2, __FUNCTION__ ) );
	}

	if ( kerbDir[ kerbDir.length() - 1 ] != '\\' &&
		kerbDir[ kerbDir.length() - 1 ] != '/' ) {
		kerberosTicketsDirectory = kerbDir + L"\\";
	} else {
		kerberosTicketsDirectory = kerbDir;
	}
	
	if ( proxyDir[ proxyDir.length() - 1 ] != '\\' &&
		proxyDir[ proxyDir.length() - 1 ] != '/' ) {
			proxyCookiesDirectory = proxyDir + L"\\";
	} else {
		proxyCookiesDirectory = proxyDir;
	}
}

void
ConnectionList::Depopulate() {
	for( unsigned int i = 0; i < connections.size(); i++ ) {
		delete connections[i];
	}
	numServers = 0;
	connections.clear();
}

void
ConnectionList::Populate() {

	if ( numServers > 0 ) {
		/// Probably throw some sort of error if already populated?
		/// Or, assume caller wants to "repopulate" and should destroy all current connections before making new ones?
		return;
	}

	if ( certificateContext == NULL ) {
		CosignLog( L"Certificate context is NULL." );
		throw( CosignError( -1, __LINE__ -1, __FUNCTION__ ) );
	}
	PADDRINFOW	aiList = NULL;
	int			err = GetAddrInfo( server.c_str(), NULL, NULL, &aiList );

	if ( err != 0 ) {
		throw( CosignError( (DWORD)err, __LINE__ - 2, __FUNCTION__ ) );
	}

	PADDRINFOW	aiCur =  NULL;
	SOCKET		s;
	struct sockaddr_in	sin;
	memset( &sin, 0, sizeof( struct sockaddr_in ) );
	sin.sin_port = htons( port );
	sin.sin_family = AF_INET;
	Snet*		snet;

	for ( aiCur = aiList, numServers = 0; aiCur != NULL; aiCur = aiCur->ai_next, numServers++, s = INVALID_SOCKET ) {
		CosignTrace1( "aiCur->ai_addr: %s\n", inet_ntoa( ((struct sockaddr_in*)(aiCur->ai_addr))->sin_addr ) );
		if ( (s = socket( AF_INET, SOCK_STREAM, NULL )) == INVALID_SOCKET ) {
			throw( CosignError( (DWORD)WSAGetLastError(), __LINE__ - 1, __FUNCTION__ ) );
		}
		sin.sin_addr.S_un = ((struct sockaddr_in*)(aiCur->ai_addr))->sin_addr.S_un;
		if ( connect( s, (struct sockaddr*)&sin, sizeof(struct sockaddr_in) ) == SOCKET_ERROR ) {
			throw( CosignError( (DWORD)WSAGetLastError(), __LINE__ - 1, __FUNCTION__ ) );
		}
		snet = new Snet();
		snet->attach( s );
		snet->getLine();
		CosignTrace1( "<< %s", snet->data.c_str() );
		Add( snet );
	}
}

void
ConnectionList::Add( Snet* sn ) {
	this->connections.push_back( sn );
}


COSIGNSTATUS
ConnectionList::CheckCookie( std::string* cookie, CosignServiceInfo* csi, BOOL tryAgain ) {

	Snet*	snet;
	std::string	out;
	std::string	in;
	int		goodConnections = 0;
	COSIGNSTATUS	status = COSIGNRETRY;

	CosignTrace1( L"connections.size() = %d", connections.size() );
	for( unsigned int i = 0; i < connections.size() && status == COSIGNRETRY; i++ ) {
		curConnection = snet = connections[ i ];
		CosignTrace1( L"CheckCookie iter %d", i );
		if ( !snet->tlsStarted() ) {
			out = "STARTTLS 2\r\n";
			CosignTrace1( ">> %s", out.c_str() );
			if ( snet->write( out ) == -1 ) {
				/// xxx on errors, delete connection?  Mark it as bad?
				CosignLog( L"Error writing data to socket %d\n", i );
				continue;
			}
			if ( snet->getLine() == -1 ) {
				CosignLog( L"Error reading data from socket %d\n", i );
				continue;
			}
			CosignTrace1( "<< %s", snet->data.c_str() );
			
			if ( snet->startTls( certificateContext, (WCHAR*)server.c_str() ) != 0 ) {
				CosignLog( L"Error starting TLS on socket %d\n", i );
				snet->close();
				continue;
			}
			if ( snet->getLine() == -1 ) {
				CosignLog( L"Error reading data(3) from socket %d\n", i );
				continue;
			}
			CosignTrace1( "<< %s\n", snet->data.c_str() );
		}
		
		out = "CHECK " + *cookie + "\r\n";
		CosignTrace1( ">> %s", out.c_str() );
		if ( snet->write( out ) == -1 ) {
			CosignLog( L"Error writing data(2) to socket %d\n", i );
			continue;
		}
		if ( snet->getLine() == -1 ) {
			CosignLog( L"Error reading data(4) from socket %d\n", i );
			continue;
		}
		CosignTrace1( "<< %s", snet->data.c_str() );
		in = snet->data;
		switch( in[ 0 ] ) {
		case '2':
			// Success!
			CosignTrace1( "Server returned 2xx: %s", in.c_str() );
			status = COSIGNLOGGEDIN;
			break;
		case '4':
			// Logged out
			CosignTrace1( "User is logged out: %s", in.c_str() );
			status = COSIGNLOGGEDOUT;
			break;
		case '5' :
			// Choose another connection
			CosignTrace1( "Trying a different server: %s", in.c_str() );
			status = COSIGNRETRY;
			break;
		default :
			CosignLog( "Server returned unexpected response: %s", in.c_str() );
			status = COSIGNERROR;
			break;
		}
		goodConnections++;
	}
	if ( goodConnections < connections.size() && tryAgain ) {
		/// repopulate and try again
		CosignTrace0( L"Repopulating and trying again..." );
		Depopulate();
		Populate();
		status = CheckCookie( cookie, csi, FALSE );
	}

    /*
     * DAP UPENN: If status is COSIGNLOGGEDIN but goodConnnections is 0,
     * that means we repopulated and tried again successfully above and,
     * therefore, this block shouldn't run
     */
    if ( status == COSIGNLOGGEDIN && goodConnections != 0) {
		CosignTrace0( L"Putting values into csi" );
		std::vector<std::string>	authData;
		std::stringstream	cookieParser( in );
		copy( std::istream_iterator<std::string>(cookieParser), std::istream_iterator<std::string>(), std::back_inserter(authData) );
		if ( authData.size() < 4 ) {
			CosignLog( L"Incorrect number of arguments.  Expected at least 4, received %d", (int)authData.size() );
			return( COSIGNERROR );
		}
		csi->ipAddr = authData[ 1 ];
		csi->user = authData[ 2 ];
		csi->strFactors = csi->realm = authData[ 3 ];
		csi->factors.push_back( authData[ 3 ] );
		for ( unsigned int i = 4; i < authData.size(); i++ ) {
			csi->strFactors += " " + authData[i];
			csi->factors.push_back( authData[i] );
		}
		csi->krb5TicketPath.clear();
	}
	return( status );
}

void
ConnectionList::RetrieveProxyCookies( std::string& cookie ) {

	if ( curConnection == NULL ) {
		CosignLog( L"Current connection is not set.  Could not retrieve proxy cookies." );
		return;
	}

	HANDLE	hpf = INVALID_HANDLE_VALUE;
	DWORD	bytesWritten = 0;
	DWORD	err;
   DWORD   success = 0;
   std::string   in;
   std::basic_string <char>::size_type   index;
   std::basic_string <char>::size_type   last;
   std::string crlf = "\r\n";
   std::string line;
   std::string status;

	try { 


	// Create file to hold proxy cookie data
	WCHAR	tempFileName[ 32768 ];
	CosignTrace1( L"proxy Cookies Diretory path = %s", proxyCookiesDirectory.c_str() );
	if ( GetTempFileName( proxyCookiesDirectory.c_str(), L"pck", 0, tempFileName ) == 0 ) {
		err = GetLastError();
		CosignLog( L"GetTempFileName failed with 0x%x", err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}

	CosignTrace1( L"tempFileName = %s", tempFileName );
	hpf = CreateFile( tempFileName,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_TEMPORARY,
		NULL );
	if ( hpf == INVALID_HANDLE_VALUE ) {
		err = GetLastError();
		CosignLog( L"CreateFile failed with 0x%x", err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}

	// Retrieve proxy cookies and store
	Snet*	snet = curConnection;
	std::string out = "RETR " + cookie + " cookies\r\n";
	CosignTrace1( ">> %s", out.c_str() );
	if ( snet->write( out ) == -1 ) {
		CosignLog( "Error writing data to socket \"%s\"\n", out.c_str() );
      goto done;
	}

	while(1) {

		if ( snet->getLine() == -1 ) {
			CosignLog( L"Error reading data from socket" );
         goto done;
		}
		in = snet->data;

		for ( index = 0; index < in.length(); index += 2 ) {
			last = index;
			index = in.find( crlf, index );
			line = in.substr( last, index - last );
			CosignTrace1( "Parsed line << %s", line.c_str() );
			if ( line.length() < 4 ) {
				CosignTrace1( "Error RETR cookies.  Expected more data: %s", in.c_str() );
            goto done;
			}
			status = line.substr( 0, 4 );
			if ( status[ 0 ] != '2' ||
				!isdigit( status[ 1 ] ) ||
				!isdigit( status[ 2 ] ) ) {
				CosignTrace1( "Error RETR cookies.  Server replied: %s", in.c_str() );
            goto done;
			}
			if ( status[ 3 ] == '-' ) {
				// Write cookie to file
				bytesWritten = 0;
				line.replace( 0, 4, "" );
				line += "\r\n";
				const char*	szLine = line.c_str();
				CosignTrace1( "Writing to file: %s", line.c_str() );
				if ( !WriteFile( hpf,
					line.c_str(),
					(DWORD)line.length(),
					&bytesWritten,
					NULL ) ) {

					err = GetLastError();
					CosignLog( L"WriteFile(%s) failed with 0x%x", out.c_str(), err );
					throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
				}
			}
		}
		if ( status.length() >= 4 && status[ 3 ] != '-' ) {
			CosignTrace0( L"Breaking out of RETR loop" );
         success = 1;
			break;
		}
	}

done:
	if ( hpf != INVALID_HANDLE_VALUE ) {
		if ( !CloseHandle( hpf ) ) {
			CosignLog( L"CloseHandle( proxyTmpFile ) failed with 0x%x", GetLastError() );
		}
	}
   if ( !success ) {
      CosignLog( L"Failed to retrieve proxy cookies" );
      return;
   }
	
	std::wstring	wcookie;
	StringToWString( cookie, wcookie );
	index = wcookie.find( L'=' );
	index++;
	if ( index != std::wstring::npos ) {
		wcookie.replace( 0, index, L"" );
	}
	std::wstring	proxyCookiePath = this->proxyCookiesDirectory + wcookie;

	CosignTrace2( L"Copying %s to %s", tempFileName, proxyCookiePath.c_str() );
	if ( !CopyFileEx( tempFileName, proxyCookiePath.c_str(), NULL, NULL, FALSE, 0 ) ) {
		err = GetLastError();
		CosignLog( L"Could not copy file %s to %s: 0x%x", tempFileName, proxyCookiePath.c_str(), err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}
	if ( !DeleteFile( tempFileName ) ) {
		err = GetLastError();
		CosignLog( L"Could not delete temp file %s: 0x%x", tempFileName, err );
		throw( CosignError( err, __LINE__ - 2, __FUNCTION__ ) );
	}

	} catch ( CosignError ce ) {
		if ( hpf != INVALID_HANDLE_VALUE ) {
			if ( !CloseHandle( hpf ) ) {
				CosignLog( L"CloseHandle( proxyTmpFile ) failed with 0x%x", GetLastError() );
			}
		}
		ce.showError();
	}
}

void ConnectionList::RetrieveKerberosTicket() {

	CosignLog( L"Kerberos ticket retrievel not yet implemented." );
}
