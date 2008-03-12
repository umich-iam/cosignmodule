#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>

#include "Settings.h"
#include "Log.h"

CosignSettings::CosignSettings() {
	loginUrl.clear();
	port = 6663;
	postErrorRedirectUrl.clear();
	webloginServer.clear();
}

CosignSettings::~CosignSettings() {
}

void
CosignSettings::dump() {

	/*CosignLog( L"cookieDbExpireTime = %u\nport = %d\n"
			   L"webloginServer = %s\ncertificateCommonName = %s\ncookieDbDirectory = %s\n",
		this->cookieDbExpireTime, this->port, this->webloginServer.c_str(),
		this->certificateCommonName.c_str(), this->cookieDbDirectory.c_str() );*/
	CosignLog( L"cookieDbExpireTie = %u", cookieDbExpireTime );
	CosignLog( L"webloginServer = %s", webloginServer.c_str() );
	CosignLog( L"cookieDbDirectory = %s", cookieDbDirectory.c_str() );
	CosignLog( L"certificateCommonName = %s", certificateCommonName.c_str() );
}
