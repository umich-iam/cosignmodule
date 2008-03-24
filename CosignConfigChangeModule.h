/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*
#include <windows.h>
#include <sal.h>
#include <httpserv.h>
*/
class CosignConfigChangeModule : public CGlobalModule
{
public:
	GLOBAL_NOTIFICATION_STATUS OnGlobalConfigurationChange(
		IN IGlobalConfigurationChangeProvider* pProvider );

	VOID Terminate() { delete this; }
};
