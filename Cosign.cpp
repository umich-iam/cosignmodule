

#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#define SECURITY_WIN32
#include <windows.h>
#include <sal.h>
#include <httpserv.h>
#include <stdio.h>
#include <comutil.h>
#include <string>
#include <bcrypt.h>
#include <winsock.h>
#include <ws2tcpip.h>
#include <security.h>
#include <schnlsp.h>
#include <iostream>
#include <vector>

#include "fbase64.h"
#include "CookieGenerator.h"
#include "Settings.h"
#include "snetpp.h"
#include "Log.h"
#include "CosignServiceInfo.h"
#include "ConnectionList.h"
#include "CookieDatabase.h"
#include "CosignModule.h"

HRESULT
__stdcall
RegisterModule(
	DWORD serverVersion,
	IHttpModuleRegistrationInfo* info,
	IHttpServer*	server ) {

	DWORD threadId = GetCurrentThreadId();
	CosignLog( L"RegisterModule thread id = %ul\n", threadId );

	UNREFERENCED_PARAMETER( serverVersion );
	CosignModuleFactory*	cmf;

	OutputDebugString( L"Module registerification.\n" );
	IAppHostAdminManager *aham = server->GetAdminManager();
	cmf = new CosignModuleFactory( &aham );
	OutputDebugString( L"Init()'ing cosign module factory" );
	if ( cmf->Init() != 0 ) {
		return( E_FAIL );
	}
	OutputDebugString( L"Done Init()'ing cosign module factory." );

	return( info->SetRequestNotifications(
		cmf,
		RQ_AUTHENTICATE_REQUEST,
		0
	) );

/* xxx not sure if necessary to be notified of configuration changes or if configuration data can be read
	by each CosignModule instance with minimal performance penalty
	
	info->SetGlobalNotifications( GL_CONFIGURATION_CHANGE );
	*/
}
