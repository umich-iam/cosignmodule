/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

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
	char*	logFilePath;
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
	std::wstring kerberosTicketsDirectory;
	std::wstring proxyCookiesDirectory;
	std::string	 validReference;
	std::string  validationErrorUrl;

};