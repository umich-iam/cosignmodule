
/*

#include <string>
*/

class CosignSettings {

public:
	CosignSettings();
	~CosignSettings();
	void dump();
	
	/*
	bool	run_inDefaultMode;
	char*	server;
	char*	cookieDBPath;
	/// may be replaced with better logging facility
	char*	logFilePath;
	/// I'm thinking there may be a better way to organize sockets
	/// IoCompletionPorts, maybe?
	int		connPoolSize;
	DWORD	cookieDBExpireTime;
	tristate	checkIpAddr;
	bool	httpsOnly;
	char*	CAFilePath;
	char*	chainFilePath;
	char*	privateKeyFilePath;
	char*	redirect;
	char*	postErrorUrl;
	int		port;
	bool	getKerberosTicket;
	char*	kerberosTicketDir;
	bool	getProxyCookies;
	char*	proxyCookieDir;
	int		hashLength;
	int		protocolVersionNeeded;
	*/
	std::wstring webloginServer;
	std::string	 postErrorRedirectUrl;
	int			 port;
	std::string	 loginUrl;
	std::wstring certificateCommonName;
	std::wstring cookieDbDirectory;
	ULONGLONG	 cookieDbExpireTime;
};