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
#include <stdarg.h>

#include "Log.h"
#include "CosignConfigChangeModule.h"

GLOBAL_NOTIFICATION_STATUS 
CosignConfigChangeModule::OnGlobalConfigurationChange( IGlobalConfigurationChangeProvider* confChange ) { 

	CosignLog( L"Configuration changed at %s", confChange->GetChangePath() );

	/// Get new config data
	/// If nothing is different, return

	/// If webloginServer name has changed
	/// OR if certificateCommonName has changed
	///		Get connection list mutex
	///		Destroy connections
	///		Make a new connection list
	///		Release mutex

	/// If cookieDb directory has changed
	///		Get cookie DB mutex
	///		Copy name of new directory
	///		Release mutex

	/// If kerberosTickets directory has changed
	///		Get kerberosTickets dir mutex
	///		Copy name of new directory
	///		Release mutex

	/// If proxyCookies directory has changed
	///		Get proxyCookies dir mutex
	///		Copy name of new directory
	///		Release mutex

	/// Assign new configuration variables

	return( GL_NOTIFICATION_CONTINUE );
}