/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>

#include "Settings.h"
#include "Log.h"

CosignSettings::CosignSettings() {
	port = 6663;
	cookieDbExpireTime = 120 * 10000000;
}

CosignSettings::~CosignSettings() {
}

void
CosignSettings::dump() {

	CosignLog( L"cookieDbExpireTime = %u", cookieDbExpireTime );
	CosignLog( L"webloginServer = %s", webloginServer.c_str() );
	CosignLog( L"cookieDbDirectory = %s", cookieDbDirectory.c_str() );
	CosignLog( L"certificateCommonName = %s", certificateCommonName.c_str() );
	CosignLog( L"kerberosTicketsDirectory = %s", kerberosTicketsDirectory.c_str() );
	CosignLog( L"proxyCookiesDirectory = %s", proxyCookiesDirectory.c_str() );
}
