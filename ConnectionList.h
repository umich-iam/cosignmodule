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
	void Init( std::wstring server, int port, PCCERT_CONTEXT	ctx );

private:
	int				numServers;
	int				port;
	std::vector<Snet*>	connections;
	PCCERT_CONTEXT	certificateContext;
	std::wstring			server;

	void Add( Snet* sn );
	void Depopulate();


};