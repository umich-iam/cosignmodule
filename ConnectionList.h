/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*
#include <vector>
#include "snetpp.h"
*/

class ConnectionList {

public:
	HANDLE		mutex;
	~ConnectionList();
	ConnectionList();
	void Populate();
	COSIGNSTATUS  CheckCookie( std::string* cookie, CosignServiceInfo* csi, BOOL tryAgain );
	void RetrieveProxyCookies( std::string& cookie );
	void RetrieveKerberosTicket();
	void Init( std::wstring& server, int port, PCCERT_CONTEXT ctx, std::wstring& kerbDir, std::wstring& proxyDir );
	void Depopulate();
	bool getProxyCookies();
	bool getKerberosTickets() { return( !kerberosTicketsDirectory.empty() ); }

private:
	int				numServers;
	int				port;
	Snet*			curConnection;
	std::vector<Snet*>	connections;
	PCCERT_CONTEXT	certificateContext;
	std::wstring	server;
	std::wstring	proxyCookiesDirectory;
	std::wstring	kerberosTicketsDirectory;

	void Add( Snet* sn );

};