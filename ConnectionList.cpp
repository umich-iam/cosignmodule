
#define SECURITY_WIN32

#include <ws2tcpip.h>
#include <security.h>
#include <schnlsp.h>
#include <string>
#include <vector>
#include <sstream>
#include <windows.h>
#include "Snetpp.h"
#include "CosignServiceInfo.h"
#include "ConnectionList.h"
#include "Log.h"

inline PCCERT_CONTEXT
GetCertFromStore( std::wstring cn, HCERTSTORE	cs ) {

	PCCERT_CONTEXT	ctx = NULL;
	PCCERT_CONTEXT	prevCtx = NULL;
	WCHAR	pszNameString[ 1024 ];

	if ( (cs = CertOpenStore( CERT_STORE_PROV_SYSTEM,
		PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		NULL,
		CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY")) == NULL ) {
		throw( CosignError( GetLastError(), __LINE__ - 1, __FUNCTION__ ) );
	}
	while ( (ctx =
		CertFindCertificateInStore(
			cs, 
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 
			0, 
			CERT_FIND_ANY,
			NULL,
			prevCtx )) != NULL ) {
		if ( CertGetNameString( ctx, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, pszNameString, 1024 ) == 1 ) {
			throw( CosignError( GetLastError(), __LINE__ -1, __FUNCTION__ ) );
		}
		if ( wcsstr( pszNameString, cn.c_str() ) != NULL ) {
			// Success happens here
			CosignLog( L"Found matching certificate!\n" );
			return( ctx );
		}
		prevCtx = ctx;
	}
	CosignLog( L"Could not find matching certificate.\n" );
	return( NULL );
}

ConnectionList::ConnectionList() {
	numServers = 0;
	certificateContext = NULL;
	port = -1;
	mutex = INVALID_HANDLE_VALUE;
}

ConnectionList::~ConnectionList() {
	/// xxx maybe shouldn't wait forever?
	CosignLog( L"Waiting for mutex before destructing." );
	WaitForSingleObject( mutex, INFINITE );
	CosignLog( L"Obtained mutex.  Deconstruction continues." );
	CloseHandle( mutex );
	Depopulate();
	CertFreeCertificateContext( certificateContext );
	
}

void
ConnectionList::Init( std::wstring s, int p, PCCERT_CONTEXT	ctx ) {

	server = s;
	port = p;
	certificateContext = ctx;
	mutex = CreateMutex( NULL, FALSE, NULL );
	if ( mutex == NULL ) {
		throw( CosignError( (DWORD)GetLastError(), __LINE__ - 2, __FUNCTION__ ) );
	}
}

void
ConnectionList::Depopulate() {
	for( int i = 0; i < connections.size(); i++ ) {
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
		CosignLogA( "aiCur->ai_addr: %s\n", inet_ntoa( ((struct sockaddr_in*)(aiCur->ai_addr))->sin_addr ) );
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
		CosignLogA( "<< %s", snet->data.c_str() );
		Add( snet );
	}
	this->server = server;
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

	CosignLog( L"connections.size() = %d", connections.size() );
	for( int i = 0; i < connections.size() && status == COSIGNRETRY; i++ ) {
		snet = connections[ i ];
		CosignLog( L"CheckCookie iter %d", i );
		if ( snet->tlsStarted() ) {
			CosignLog( L"Apparently, tls already started up" );
		} else {
			CosignLog( L"Starting TLS" );
			out = "STARTTLS 2\r\n";
			CosignLogA( ">> %s", out.c_str() );
			if ( snet->write( out ) == -1 ) {
				/// xxx on errors, delete connection?  Mark it as bad?
				CosignLog( L"Error writing data to socket %d\n", i );
				continue;
				//throw( SslTestError( (DWORD)WSAGetLastError(), __LINE__ - 1, __FUNCTION__ ) );
			}
			if ( snet->getLine() == -1 ) {
				CosignLog( L"Error reading data from socket %d\n", i );
				continue;
				//throw( SslTestError( (DWORD)WSAGetLastError(), __LINE__ - 1, __FUNCTION__ ) );
			}
			CosignLogA( "<< %s", snet->data.c_str() );
			
			if ( snet->startTls( certificateContext, (WCHAR*)server.c_str() ) != 0 ) {
				CosignLog( L"Error starting TLS on socket %d\n", i );
				snet->close();
				continue;
			}
			if ( snet->getLine() == -1 ) {
				CosignLog( L"Error reading data(3) from socket %d\n", i );
				continue;
			}
			CosignLogA( "<< %s\n", snet->data.c_str() );
		}

		out = "CHECK " + *cookie + "\r\n";
		CosignLogA( ">> %s", out.c_str() );
		if ( snet->write( out ) == -1 ) {
			CosignLog( L"Error writing data(2) to socket %d\n", i );
			continue;
		}
		if ( snet->getLine() == -1 ) {
			CosignLog( L"Error reading data(4) from socket %d\n", i );
			continue;
		}
		CosignLogA( "<< %s", snet->data.c_str() );
		in = snet->data;
		switch( in[ 0 ] ) {
		case '2':
			// Success!
			CosignLogA( "Server returned 2xx: %s", in.c_str() );
			status = COSIGNLOGGEDIN;
			break;
		case '4':
			// Logged out
			CosignLogA( "User is logged out: %s", in.c_str() );
			status = COSIGNLOGGEDOUT;
			break;
		case '5' :
			// Choose another connection
			CosignLogA( "Trying a different server: %s", in.c_str() );
			status = COSIGNRETRY;
			break;
		default :
			CosignLogA( "Server returned unexpected response: %s", in.c_str() );
			status = COSIGNERROR;
			break;
		}
		goodConnections++;
	}
	if ( goodConnections == 0 && tryAgain ) {
		/// repopulate and try again
		CosignLog( L"Repopulating and trying again..." );
		Depopulate();
		Populate();
		CheckCookie( cookie, csi, FALSE );
	}

	if ( status == COSIGNLOGGEDIN ) {
		CosignLog( L"Putting values into csi" );
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
		for ( int i = 4; i < authData.size(); i++ ) {
			csi->strFactors += " " + authData[i];
			csi->factors.push_back( authData[i] );
		}
		csi->krb5TicketPath.clear();
	}
	return( status );
}
