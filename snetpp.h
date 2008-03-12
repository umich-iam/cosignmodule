/*
#include <windows.h>
#include <winsock.h>
#include <ws2tcpip.h>
#include <security.h>
#include <schnlsp.h>
#include <string>
#include <iostream>
*/

static const int READBUFSIZE	= 1024;
enum 	SNETSOCKETSTATE { MOREDATA, FUZZY, DONE };


class Snet {

private:
	SOCKET s;
	int			readbuflen;
	char		readbuf[ READBUFSIZE ];
	CtxtHandle	ctx;
	BOOL		useTls;
	SecPkgContext_StreamSizes streamSizes;
	BYTE*		writeBuffer;
	DWORD		writeBufferLength;
	BYTE*		readBuffer;
	DWORD		readBufferLength;

	int	setStreamBufferSize();
	int secureRead();
	int secureWrite( std::string str );
	int secureGetLine();

public:
	// Data that is recv()'d is placed here.
	// Each call to read() or get_line() overwrites any existing data in the buffer.
	std::string data;

	Snet();
	~Snet();
	int close();
	int getLine();
	int write( std::string str );
	int read();
	int	startTls( PCCERT_CONTEXT	certCtx, WCHAR*	server);
	BOOL tlsStarted() { return( useTls ); };
	void attach( SOCKET s );

};
