/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*
#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include <windows.h>
#include <sal.h>
#include <httpserv.h>
#include <stdio.h>
#include <comutil.h>
#include <string>

#include "CookieGenerator.h"
#include "Settings.h"
#include "snetpp.h"
*/

static std::string VERSION = "3.1.0 RC4 build 5";

enum PROTECTEDSTATUS { cosignUnprotected, cosignProtected, cosignAllowPublicAccess };


class CosignModule : public CHttpModule {

public :
	REQUEST_NOTIFICATION_STATUS
	OnAuthenticateRequest(
		IHttpContext*	context,
		IN IAuthenticationProvider* pProvider );
	
	REQUEST_NOTIFICATION_STATUS
    OnExecuteRequestHandler(
        IN IHttpContext *                       pHttpContext,
        IN IHttpEventProvider *                 pProvider
    );

	int CheckCookie( std::string* cookie );

	CosignModule( IAppHostAdminManager** aham, ConnectionList* cl, CookieDatabase* cdb );
	~CosignModule();

private :

	HANDLE	eventLog;
	CookieGenerator*	cg;
	CookieDatabase*		cdb;
	ConnectionList*		cl;
	
	//Configuration data
	IAppHostAdminManager* aham;
	std::string	loginUrl;
	std::string	siteEntry;
	std::string postErrorRedirectUrl;
	std::string	serviceName;
	BOOL	cookiesSecure;
	BOOL	cookiesHttpOnly;
	BOOL	compatibilityMode;
	BOOL	CosignNoAppendRedirectPort;
	std::vector<std::string>		factors;
	std::string strFactors;
	std::vector<std::string>		suffixes;
	std::string validReference;
	std::string validationErrorRedirect;

	BOOL Log( LPCWSTR str );
	BOOL Log( PCSTR str );
	PROTECTEDSTATUS GetConfig( IHttpContext*	context );
	REQUEST_NOTIFICATION_STATUS SetCookieAndRedirect( IHttpContext* context );
	REQUEST_NOTIFICATION_STATUS	RedirectToLoginServer( IHttpContext* context );
	int ParseServiceCookie( std::string& cookie, std::string& serviceCookie );
	COSIGNSTATUS	NetCheckCookie( std::string& cookie,  CosignServiceInfo& csi, BOOL retrieve, COSIGNSTATUS fileStatus );
	PROTECTEDSTATUS	GetValidationConfig( IHttpContext* context );

};

class CosignModuleFactory : public IHttpModuleFactory {

public:
	CosignModuleFactory::CosignModuleFactory( IAppHostAdminManager** aham );
	
	HRESULT GetHttpModule(
		OUT	CHttpModule** ppModule,
		IN IModuleAllocator* pAllocator );
		
	void Terminate();
	DWORD Init();
private:
	IAppHostAdminManager* aham;
	IHttpTraceContext* htc;
	CosignSettings	config;
	Snet			snet;
	HCERTSTORE		certificateStore;
	ConnectionList	cl;
	CookieDatabase	cdb;

	void CreateSnetConnections();
};
