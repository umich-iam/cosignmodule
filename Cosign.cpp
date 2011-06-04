/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

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
#include "CosignConfigChangeModule.h"

HRESULT
__stdcall
RegisterModule(
	DWORD serverVersion,
	IHttpModuleRegistrationInfo* info,
	IHttpServer*	server ) {

	UNREFERENCED_PARAMETER( serverVersion );
	CosignModuleFactory*	cmf;
	HRESULT	hr;
	

	IAppHostAdminManager *aham = server->GetAdminManager();
	cmf = new CosignModuleFactory( &aham );
	if ( !cmf ) {
		return( HRESULT_FROM_WIN32( ERROR_NOT_ENOUGH_MEMORY ) );
	}

	DWORD err  = cmf->Init();
	if ( err != 0 ) {
		OutputDebugString( L"[CosignModule] Error Initializing cosignmodule object.");
		return( HRESULT_FROM_WIN32( err ) );
	}
	
	OutputDebugString( L"[CosignModule] Setting request notifications...");
	hr = info->SetRequestNotifications(
		cmf,
		RQ_AUTHENTICATE_REQUEST | RQ_EXECUTE_REQUEST_HANDLER,
		0 );
	if ( FAILED(hr) ) {
		OutputDebugString( L"[CosignModule] Set request notifications failed." );
		return( hr );
	}
	OutputDebugString( L"[CosignModule] Setting priority for request notifications.");
	info->SetPriorityForRequestNotification( RQ_AUTHENTICATE_REQUEST, PRIORITY_ALIAS_FIRST );

	OutputDebugString( L"[CosignModule] Returning from RegisterModule.");
	return( hr );

/*	CosignConfigChangeModule*	cccm = new CosignConfigChangeModule;

	if ( !cccm ) {
		return( HRESULT_FROM_WIN32( ERROR_NOT_ENOUGH_MEMORY ) );
	}

	hr = info->SetGlobalNotifications( cccm, GL_CONFIGURATION_CHANGE );
	if ( FAILED(hr) ) {
		return( hr );
	}

	hr = info->SetPriorityForGlobalNotification( GL_CONFIGURATION_CHANGE, PRIORITY_ALIAS_LOW );
	if ( FAILED(hr) ) {
		return( hr );
	}

	return( hr );
*/
/* xxx not sure if necessary to be notified of configuration changes or if configuration data can be read
	by each CosignModule instance with minimal performance penalty
	
	info->SetGlobalNotifications( GL_CONFIGURATION_CHANGE );
	*/
}
