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
#include <algorithm>
#include <regex>

#include "fbase64.h"
#include "CookieGenerator.h"
#include "Settings.h"
#include "snetpp.h"
#include "Log.h"
#include "CosignServiceInfo.h"
#include "ConnectionList.h"
#include "CookieDatabase.h"
#include "CosignModule.h"
#include "CosignUser.h"


inline PCSTR GetSerVar( PCSTR varName, IHttpContext* context )
{
	PCSTR	value = NULL;
	DWORD	length = 0;
	context->GetServerVariable( varName, &value, &length );
	value = (PCSTR)context->AllocateRequestMemory( length + 1 );
	if ( value == NULL ) {
		CosignLog( L"Not enough memory to allocate for SERVER_PORT_SECURE" );
		return( NULL );
	}

	context->GetServerVariable( varName, &value, &length );
	return( value );
}
inline PCCERT_CONTEXT
RetrieveCertFromStore( std::wstring cn, HCERTSTORE	cs ) {

	PCCERT_CONTEXT	ctx = NULL;
	PCCERT_CONTEXT	prevCtx = NULL;
	WCHAR	pszNameString[ 1024 ];

	if ( (cs = CertOpenStore( CERT_STORE_PROV_SYSTEM,
		PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		NULL,
		CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY")) == NULL ) {
		throw( CosignError( GetLastError(), __LINE__ - 1, __FUNCTION__ ) );
	}
	while ( (ctx =
		CertFindCertificateInStore(
			cs, 
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 
			0, 
			CERT_FIND_ANY,
			NULL,
			prevCtx )) != NULL ) {
		if ( CertGetNameString( ctx, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, pszNameString, 1024 ) > 1 ) {
			if ( wcsstr( pszNameString, cn.c_str() ) != NULL ) {
				CosignLog( L"Found matching certificate!\n" );
				return( ctx );
			}
		}
		prevCtx = ctx;
	}
	CosignLog( L"Could not find matching certificate.\n" );
	return( NULL );
}

inline void
GetElement( 
	IAppHostElement*	ahe,
	BSTR*				bstrName,
	IAppHostElement**	ahe2	) {

	HRESULT hr = ahe->GetElementByName( *bstrName, ahe2 );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not retrieve cosign %s element", *bstrName );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
}

inline void
GetPropertyValueByName(
	IAppHostElement*	ahe,
	VARIANT*			value, 
	BSTR*				name,
	VARTYPE				type ) {

	IAppHostProperty*	ahp		= NULL;
	HRESULT	hr;

	hr = ahe->GetPropertyByName( *name, &ahp );
	if ( FAILED(hr) || ahp == NULL ) {
		CosignLog( L"GetPropertyValueByName( %s ) failed.  Property not found.", *name );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
	hr = ahp->get_Value( value );
	if ( FAILED(hr) ) {
		CosignLog( L"GetPropertyValueByName( %s ) failed.  Value not set.", *name );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
	if ( value->vt != type ) {
		CosignLog( L"GetPropertyValueByName( %s ) failed.  Property type %d differs from type expected %d.",
			*name, value->vt, type );
#ifdef COSIGNTRACE
		switch ( value->vt ) {

		case VT_EMPTY:
			OutputDebugString( L"value is a VT_EMPTY" );
			break;
		
		case VT_NULL	:
			OutputDebugString( L"value is a VT_NULL" );
			break;
		
		case VT_I2	:
			OutputDebugString( L"value is a VT_I2" );
			break;
			
		case VT_I4	:
			OutputDebugString( L"value is a VT_I4" );
			break;
			
		case VT_R4	:
			OutputDebugString( L"value is a VT_R4" );
			break;
			
		case VT_R8	:
			OutputDebugString( L"value is a VT_R8" );
			break;
		
		case VT_CY	:
			OutputDebugString( L"value is a VT_CY" );
			break;
			
		case VT_DATE	:
			OutputDebugString( L"value is a VT_DATE" );
			break;
			
		case VT_BSTR	:
			OutputDebugString( L"value is a VT_BSTR" );
			break;
			
		case VT_DISPATCH	:
			OutputDebugString( L"value is a VT_DISPATCH" );
			break;
			
		case VT_ERROR	:
			OutputDebugString( L"value is a VT_ERROR" );
			break;
			
		case VT_BOOL	:
			OutputDebugString( L"value is a VT_BOOL" );
			break;
			
		case VT_VARIANT	:
			OutputDebugString( L"value is a VT_VARIANT" );
			break;
			
		case VT_UNKNOWN	:
			OutputDebugString( L"value is a VT_UNKNOWN" );
			break;
			
		case VT_DECIMAL	:
			OutputDebugString( L"value is a VT_DECIMAL" );
			break;
			
		case VT_I1	:
			OutputDebugString( L"value is a VT_I1" );
			break;
			
		case VT_UI1	:
			OutputDebugString( L"value is a VT_UI1" );
			break;
			
		case VT_UI2	:
			OutputDebugString( L"value is a VT_UI2" );
			break;
			
		case VT_UI4	:
			OutputDebugString( L"value is a VT_UI4" );
			break;
			
		case VT_I8	:
			OutputDebugString( L"value is a VT_I8" );
			break;
			
		case VT_UI8	:
			OutputDebugString( L"value is a VT_UI8" );
			break;
			
		case VT_INT	:
			OutputDebugString( L"value is a VT_INT" );
			break;
			
		case VT_UINT	:
			OutputDebugString( L"value is a VT_UINT" );
			break;
			
		case VT_VOID	:
			OutputDebugString( L"value is a VT_VOID" );
			break;
			
		case VT_HRESULT	:
			OutputDebugString( L"value is a VT_HRESULT" );
			break;
			
		case VT_PTR	:
			OutputDebugString( L"value is a VT_PTR" );
			break;
			
		case VT_SAFEARRAY	:
			OutputDebugString( L"value is a VT_SAFEARRAY" );
			break;
			
		case VT_CARRAY	:
			OutputDebugString( L"value is a VT_CARRAY" );
			break;
			
		case VT_USERDEFINED:
			OutputDebugString( L"value is a VT_USERDEFINED" );
			break;
			
		case VT_LPSTR	:
			OutputDebugString( L"value is a VT_LPSTR" );
			break;
			
		case VT_LPWSTR	:
			OutputDebugString( L"value is a VT_LPWSTR" );
			break;
			
		case VT_RECORD	:
			OutputDebugString( L"value is a VT_RECORD" );
			break;
			
		case VT_INT_PTR	:
			OutputDebugString( L"value is a VT_INT_PTR" );
			break;
			
		case VT_UINT_PTR	:
			OutputDebugString( L"value is a VT_UINT_PTR" );
			break;
			
		case VT_FILETIME	:
			OutputDebugString( L"value is a VT_FILETIME" );
			break;
			
		case VT_BLOB	:
			OutputDebugString( L"value is a VT_BLOB" );
			break;
			
		case VT_STREAM	:
			OutputDebugString( L"value is a VT_STREAM" );
			break;
			
		case VT_STORAGE	:
			OutputDebugString( L"value is a VT_STORAGE" );
			break;
			
		case VT_STREAMED_OBJECT	:
			OutputDebugString( L"value is a VT_STREAMED_OBJECT" );
			break;
			
		case VT_STORED_OBJECT	:
			OutputDebugString( L"value is a VT_STORED_OBJECT" );
			break;
			
		case VT_BLOB_OBJECT	:
			OutputDebugString( L"value is a VT_BLOB_OBJECT" );
			break;
			
		case VT_CF	:
			OutputDebugString( L"value is a VT_CF" );
			break;
			
		case VT_CLSID	:
			OutputDebugString( L"value is a VT_CLSID" );
			break;
			
		case VT_VERSIONED_STREAM	:
			OutputDebugString( L"value is a VT_VERSIONED_STREAM" );
			break;
			
		case VT_BSTR_BLOB:
			OutputDebugString( L"value is a VT_BSTR_BLOB" );
			break;
			
		case VT_VECTOR	:
			OutputDebugString( L"value is a VT_VECTOR" );
			break;
			
		case VT_ARRAY	:
			OutputDebugString( L"value is a VT_ARRAY" );
			break;
			
		case VT_BYREF	:
			OutputDebugString( L"value is a VT_BYREF" );
			break;
			
		case VT_RESERVED	:
			OutputDebugString( L"value is a VT_RESERVED" );
			break;
			
		case VT_ILLEGAL	:
			OutputDebugString( L"value is a VT_ILLEGAL" );
			break;
	
		default:
			OutputDebugString( L"value is another type" );
			break;
		}
#endif		
	}
}

PROTECTEDSTATUS
CosignModule::GetValidationConfig( IHttpContext* context ) {

	HRESULT	hr;
	int		retCode			= 0;
	PROTECTEDSTATUS	retStatus = cosignUnprotected;
	PCTSTR	appConfigPath	= NULL;
	VARIANT	value;
	char*	strValue		= NULL;
	BSTR	bstrSection		= SysAllocString( L"system.webServer/cosign" );
	BSTR	bstrService		= SysAllocString( L"service" );
	BSTR	bstrName		= SysAllocString( L"name" );
	BSTR    bstrProtected	= SysAllocString( L"protected" );
	BSTR	bstrStatus		= SysAllocString( L"status" );
	BSTR	bstrLoginUrl			= SysAllocString(L"loginUrl");
	BSTR	bstrPostErrorRedirectUrl= SysAllocString(L"postErrorRedirectUrl");
	BSTR	bstrWebloginServer		= SysAllocString(L"webloginServer" );
	BSTR	bstrCookies		= SysAllocString(L"cookies");
	BSTR	bstrSecure		= SysAllocString(L"secure");
	BSTR	bstrHttpOnly	= SysAllocString(L"httpOnly");
	BSTR	bstrAdd			= SysAllocString(L"add");
	BSTR	bstrFactor		= SysAllocString(L"factor");
	BSTR	bstrValidation	= SysAllocString(L"validation");
	BSTR	bstrValidReference = SysAllocString(L"validReference");
	BSTR	bstrErrorRedirectUrl = SysAllocString(L"errorRedirectUrl");

	BSTR	bstrConfigPath;
	IHttpApplication*	app	= NULL;
	IAppHostElement*	ahe	= NULL;
	IAppHostElement*	ahe2= NULL;
	IAppHostProperty*	ahp	= NULL;
	IMetadataInfo*			imi		= NULL;
	PCTSTR					metaPath= NULL;
	IAppHostConfigManager*	ahcm	= NULL;
	IAppHostConfigFile*		ahcf	= NULL;

	CosignTrace0( L"{*********************GetValidationConfig*********************}\n" );

	
	imi = context->GetMetadata();
	metaPath = imi->GetMetaPath();
		
	CosignTrace1( L"Metapath = %s\n", metaPath );
	bstrConfigPath = SysAllocString( metaPath );
	
	hr = aham->GetAdminSection( bstrSection, bstrConfigPath, &ahe );
	if ( FAILED(hr) || ahe == NULL ) {
		CosignLog( L"GetAdminSection( %s, %s ) failed.", bstrSection, bstrConfigPath );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
		
	/* Should never fail? */
/*	hr = ahe->GetElementByName( bstrProtected, &ahe2 );
	if ( FAILED(hr) || ahe2 == NULL ) {
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
	GetPropertyValueByName( ahe2, &value, &bstrStatus, VT_I4 );

	switch( V_I4(&value) ) {
	case 0:
		return( cosignUnprotected );
	case 1:
		retStatus = cosignProtected;
		break;
	case 2:
		retStatus = cosignAllowPublicAccess;
		break;
	default:
		throw( CosignError( E_FAIL, __LINE__ -2, __FILE__ ) );
		break;
	}
*/
	hr = ahe->GetElementByName( bstrValidation, &ahe2 );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not retrieve cosign <validation> element" );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
	GetPropertyValueByName( ahe2, &value, &bstrValidReference, VT_BSTR );
	strValue = _com_util::ConvertBSTRToString( value.bstrVal );
	this->validReference = strValue;
	delete strValue;

	GetPropertyValueByName( ahe2, &value, &bstrErrorRedirectUrl, VT_BSTR );
	strValue = _com_util::ConvertBSTRToString( value.bstrVal );
	this->validationErrorRedirect = strValue;
	delete strValue;


	hr = ahe->GetElementByName( bstrWebloginServer, &ahe2 );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not retrieve cosign <webloginServer> element" );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
	GetPropertyValueByName( ahe2, &value, &bstrLoginUrl, VT_BSTR );
	strValue = _com_util::ConvertBSTRToString( value.bstrVal );
	loginUrl = strValue;
	delete strValue;

	GetPropertyValueByName( ahe2, &value, &bstrPostErrorRedirectUrl, VT_BSTR );
	strValue = _com_util::ConvertBSTRToString( value.bstrVal );
	postErrorRedirectUrl = strValue;
	delete strValue;

	hr = ahe->GetElementByName( bstrService, &ahe2 );
	if ( FAILED(hr) || ahe2 == NULL ) {
		OutputDebugString( L"GetElementByName(\"service\") failed." );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
	GetPropertyValueByName( ahe2, &value, &bstrName, VT_BSTR );
	strValue = _com_util::ConvertBSTRToString( value.bstrVal ); 
	serviceName = strValue;
	delete strValue;
	const std::string cosignServicePrefix = "cosign-";
	if ( serviceName.find( cosignServicePrefix ) != 0 ) {
		serviceName.replace( 0, 0, cosignServicePrefix );
	}

	IAppHostElementCollection* ahec;
	hr = ahe2->get_Collection( &ahec );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not get service collection" );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	} 
	DWORD numFactors;
	hr = ahec->get_Count( &numFactors );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not get_count for factors" );
		throw( CosignError( hr, __LINE__ - 3, __FILE__ ) );
	}
	CosignTrace1( L"NumFactors = %u", numFactors );
	IAppHostElement* collElem;
	strFactors = "";
	for ( unsigned int i = 0; i < numFactors; i++ ) {
		VARIANT	index;
		index.vt = VT_UINT;
		index.uintVal = i;
		hr = ahec->get_Item( index, &collElem );
		if ( FAILED(hr) ) {
			CosignLog( L"Could not get collection." );
			throw( CosignError( hr, __LINE__ - 3, __FILE__ ) );
		}
		GetPropertyValueByName( collElem, &value, &bstrFactor, VT_BSTR );
		CosignTrace2( L"Got %s = %s", bstrFactor, value.bstrVal );
		strValue = _com_util::ConvertBSTRToString( value.bstrVal );
		if ( strFactors == "" ) {
			strFactors += strValue;
		} else {
			strFactors += ",";
			strFactors += strValue;
		}
		factors.push_back( strValue );
		delete strValue;
	}
#ifdef COSIGNTRACE
	for ( std::vector<std::string>::iterator iter = factors.begin(); iter != factors.end(); iter++ ) {
		CosignLog( "Factor from vector = %s", iter->c_str() );
	}
#endif


	/// xxx does this take into account elements that are optional?
	/// what will happen if we try to retrieve a value that hasn't been set?
	hr = ahe->GetElementByName( bstrCookies, &ahe2 );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not retrieve cosign <cookies> element" );
		throw( CosignError( hr, __LINE__ -2, __FUNCTION__ ) );
	}
	GetPropertyValueByName( ahe2, &value, &bstrSecure, VT_BOOL );
	cookiesSecure = V_BOOL(&value);

	GetPropertyValueByName( ahe2, &value, &bstrHttpOnly, VT_BOOL );
	cookiesHttpOnly = V_BOOL(&value);


	SysFreeString( bstrLoginUrl );
	SysFreeString( bstrPostErrorRedirectUrl	);
	SysFreeString( bstrSection );
	SysFreeString( bstrService );
	SysFreeString( bstrName );
	SysFreeString( bstrProtected );
	SysFreeString( bstrStatus );
	SysFreeString( bstrWebloginServer );
	SysFreeString( bstrCookies );
	SysFreeString( bstrSecure );
	SysFreeString( bstrHttpOnly	);
	SysFreeString( bstrAdd );
	SysFreeString( bstrFactor );
	SysFreeString( bstrValidation );
	SysFreeString( bstrValidReference );
	SysFreeString( bstrErrorRedirectUrl );

	CosignTrace0( L"{*********************GetValidationConfig Done****************}\n" );
	return( retStatus );

}
/* 
 * GetConfig()
 * return:
 *	-1 error
 *   0 unprotected
 *   1 protected
 *   2 allowPublicAccess
 */
PROTECTEDSTATUS
CosignModule::GetConfig( IHttpContext* context ) {
	HRESULT	hr;
	int		retCode			= 0;
	PROTECTEDSTATUS	retStatus = cosignUnprotected;
	PCTSTR	appConfigPath	= NULL;
	VARIANT	value;
	char*	strValue		= NULL;
	BSTR	bstrSection		= SysAllocString( L"system.webServer/cosign" );
	BSTR	bstrService		= SysAllocString( L"service" );
	BSTR	bstrName		= SysAllocString( L"name" );
	BSTR    bstrProtected	= SysAllocString( L"protected" );
	BSTR	bstrStatus		= SysAllocString( L"status" );
	BSTR	bstrLoginUrl			= SysAllocString(L"loginUrl");
	BSTR	bstrPostErrorRedirectUrl= SysAllocString(L"postErrorRedirectUrl");
	BSTR	bstrWebloginServer		= SysAllocString(L"webloginServer" );
	BSTR	bstrCookies		= SysAllocString(L"cookies");
	BSTR	bstrSecure		= SysAllocString(L"secure");
	BSTR	bstrHttpOnly	= SysAllocString(L"httpOnly");
	BSTR	bstrAdd			= SysAllocString(L"add");
	BSTR	bstrFactor		= SysAllocString(L"factor");
	BSTR	bstrCompatibilityMode		= SysAllocString(L"compatibilityMode");
	BSTR	bstrMode		= SysAllocString(L"mode");
	BSTR	bstrConfigPath;
	IHttpApplication*	app	= NULL;
	IAppHostElement*	ahe	= NULL;
	IAppHostElement*	ahe2= NULL;
	IAppHostProperty*	ahp	= NULL;
	IMetadataInfo*			imi		= NULL;
	PCTSTR					metaPath= NULL;
	IAppHostConfigManager*	ahcm	= NULL;
	IAppHostConfigFile*		ahcf	= NULL;

	CosignTrace0( L"New GetConfig()uration logics!\n" );

	
	imi = context->GetMetadata();
	metaPath = imi->GetMetaPath();
		
	CosignTrace1( L"Metapath = %s\n", metaPath );
	bstrConfigPath = SysAllocString( metaPath );
	
	hr = aham->GetAdminSection( bstrSection, bstrConfigPath, &ahe );
	if ( FAILED(hr) || ahe == NULL ) {
		CosignLog( L"GetAdminSection( %s, %s ) failed.", bstrSection, bstrConfigPath );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
		
	/* Should never fail? */
	hr = ahe->GetElementByName( bstrProtected, &ahe2 );
	if ( FAILED(hr) || ahe2 == NULL ) {
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
	GetPropertyValueByName( ahe2, &value, &bstrStatus, VT_I4 );

	switch( V_I4(&value) ) {
	case 0:
		return( cosignUnprotected );
	case 1:
		retStatus = cosignProtected;
		break;
	case 2:
		retStatus = cosignAllowPublicAccess;
		break;
	default:
		throw( CosignError( E_FAIL, __LINE__ -2, __FILE__ ) );
		break;
	}

	hr = ahe->GetElementByName( bstrWebloginServer, &ahe2 );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not retrieve cosign <webloginServer> element" );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
	GetPropertyValueByName( ahe2, &value, &bstrLoginUrl, VT_BSTR );
	strValue = _com_util::ConvertBSTRToString( value.bstrVal );
	loginUrl = strValue;
	delete strValue;

	GetPropertyValueByName( ahe2, &value, &bstrPostErrorRedirectUrl, VT_BSTR );
	strValue = _com_util::ConvertBSTRToString( value.bstrVal );
	postErrorRedirectUrl = strValue;
	delete strValue;

	hr = ahe->GetElementByName( bstrService, &ahe2 );
	if ( FAILED(hr) || ahe2 == NULL ) {
		OutputDebugString( L"GetElementByName(\"service\") failed." );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	}
	GetPropertyValueByName( ahe2, &value, &bstrName, VT_BSTR );
	strValue = _com_util::ConvertBSTRToString( value.bstrVal ); 
	serviceName = strValue;
	delete strValue;
	const std::string cosignServicePrefix = "cosign-";
	if ( serviceName.find( cosignServicePrefix ) != 0 ) {
		serviceName.replace( 0, 0, cosignServicePrefix );
	}

	IAppHostElementCollection* ahec;
	hr = ahe2->get_Collection( &ahec );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not get service collection" );
		throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
	} 
	DWORD numFactors;
	hr = ahec->get_Count( &numFactors );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not get_count for factors" );
		throw( CosignError( hr, __LINE__ - 3, __FILE__ ) );
	}
	CosignTrace1( L"NumFactors = %u", numFactors );
	IAppHostElement* collElem;
	strFactors = "";
	for ( unsigned int i = 0; i < numFactors; i++ ) {
		VARIANT	index;
		index.vt = VT_UINT;
		index.uintVal = i;
		hr = ahec->get_Item( index, &collElem );
		if ( FAILED(hr) ) {
			CosignLog( L"Could not get collection." );
			throw( CosignError( hr, __LINE__ - 3, __FILE__ ) );
		}
		GetPropertyValueByName( collElem, &value, &bstrFactor, VT_BSTR );
		CosignTrace2( L"Got %s = %s", bstrFactor, value.bstrVal );
		strValue = _com_util::ConvertBSTRToString( value.bstrVal );
		if ( strFactors == "" ) {
			strFactors += strValue;
		} else {
			strFactors += ",";
			strFactors += strValue;
		}
		factors.push_back( strValue );
		delete strValue;
	}
#ifdef COSIGNTRACE
	for ( std::vector<std::string>::iterator iter = factors.begin(); iter != factors.end(); iter++ ) {
		CosignLog( "Factor from vector = %s", iter->c_str() );
	}
#endif


	hr = ahe->GetElementByName( bstrCookies, &ahe2 );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not retrieve cosign <cookies> element" );
		throw( CosignError( hr, __LINE__ -2, __FUNCTION__ ) );
	}
	GetPropertyValueByName( ahe2, &value, &bstrSecure, VT_BOOL );
	cookiesSecure = V_BOOL(&value);
	CosignLog( L"Setting <cookies secure> to %d", cookiesSecure );

	GetPropertyValueByName( ahe2, &value, &bstrHttpOnly, VT_BOOL );
	cookiesHttpOnly = V_BOOL(&value);
	CosignLog( L"Setting <cookies httpOnly> to %d", cookiesHttpOnly );

	hr = ahe->GetElementByName( bstrCompatibilityMode, &ahe2 );
	if ( FAILED(hr) ) {
		CosignLog( L"Could not retrieve cosign <compatibilityMode>" );
		compatibilityMode = FALSE;
	} else {
		GetPropertyValueByName( ahe2, &value, &bstrMode, VT_BOOL );
		compatibilityMode = V_BOOL(&value);
		CosignLog( L"Setting <compatibility> mode to %d", compatibilityMode );
	}

	SysFreeString( bstrLoginUrl );
	SysFreeString( bstrPostErrorRedirectUrl	);
	SysFreeString( bstrSection );
	SysFreeString( bstrService );
	SysFreeString( bstrName );
	SysFreeString( bstrProtected );
	SysFreeString( bstrStatus );
	SysFreeString( bstrWebloginServer );
	SysFreeString( bstrCookies );
	SysFreeString( bstrSecure );
	SysFreeString( bstrHttpOnly	);
	SysFreeString( bstrAdd );
	SysFreeString( bstrFactor );
	SysFreeString( bstrCompatibilityMode );
	SysFreeString( bstrMode );
	return( retStatus );
}

REQUEST_NOTIFICATION_STATUS
CosignModule::RedirectToLoginServer(
	IHttpContext*	context ) 
{
	DWORD spsSize = 0;
	PCSTR serverPortSecure = NULL;
	context->GetServerVariable( "SERVER_PORT_SECURE", &serverPortSecure, &spsSize);
	serverPortSecure = (PCSTR)context->AllocateRequestMemory( spsSize + 1 );
	context->GetServerVariable( "SERVER_PORT_SECURE", &serverPortSecure, &spsSize);
	if ( serverPortSecure == NULL ) {
		CosignLog( L"Not enough memory to allocate for SERVER_PORT_SECURE" );
		/// xxx set an error
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	CosignTrace1( "SERVER_PORT_SECURE = %s\n", serverPortSecure );

	std::string	protocol;
	if ( atoi(serverPortSecure) ) {
		protocol = "https";
	} else {
		protocol = "http";
	}

	/// xxx Note: Should also check SERVER_PORT to see if it is non-standard (443 or 80) and needs to be appended to destination
	PCSTR	port =  NULL;
	DWORD	portSize = 0;
	context->GetServerVariable( "SERVER_PORT", &port, &portSize );
	port = (PCSTR)context->AllocateRequestMemory( portSize + 1 );
	if ( port == NULL ) {
		CosignLog( "Not enough memory to allocate for SERVER_PORT" );
		/// xxx set an error
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	context->GetServerVariable( "SERVER_PORT", &port, &portSize );
	CosignTrace1( "SERVER_PORT = %s", port );
	
	PCSTR	url = NULL;
	DWORD	urlSize = 0;
	context->GetServerVariable( "URL", &url, &urlSize );
	url = (PCSTR)context->AllocateRequestMemory( urlSize + 1 );
	if ( url == NULL ) {
		CosignLog( L"Not enough memory to allocate for URL" );
		/// xxx set an error
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	context->GetServerVariable( "URL", &url, &urlSize );
	CosignTrace1( "URL = %s", url );

	PCSTR queryString = NULL;
	DWORD queryStringSize = 0;
	context->GetServerVariable( "QUERY_STRING", &queryString, &queryStringSize );
	if ( queryStringSize > 0 ) {
		queryString = (PCSTR)context->AllocateRequestMemory( queryStringSize + 1 );
		if ( queryString == NULL ) {
			CosignLog( L"Not enough memory to allocate for QUERY_STRING" );
			return( RQ_NOTIFICATION_FINISH_REQUEST );
		}
		context->GetServerVariable( "QUERY_STRING", &queryString, &queryStringSize );
		CosignTrace1( "QUERY_STRING", queryString );
	}

	DWORD serverNameSize = 0;
	PCSTR serverName = NULL;
	context->GetServerVariable( "SERVER_NAME", &serverName, &serverNameSize );
	serverName = (PCSTR)context->AllocateRequestMemory( serverNameSize + 1 );
	if ( serverName == NULL ) {
		CosignLog( L"Not enough memory to allocate for SERVER_NAME" );
		/// xxx set an error
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	context->GetServerVariable( "SERVER_NAME", &serverName, &serverNameSize );
	CosignTrace1( "SERVER_NAME = %s", serverName );

	std::string destination = protocol;
	destination += "://";
	destination += serverName;

	int portNumber = atoi( port );
	CosignTrace1( "portNumber = %d", portNumber );
	if (portNumber != 443 && portNumber != 80 ) {
		destination += ":";
		destination += port;
	}
	
	
	destination += url;
	if ( queryStringSize > 0 ) {
		destination += "?";
		destination += queryString;
	}

	
	std::string newLocation;
	if ( factors.size() > 0 ) {
		newLocation = loginUrl + "factors=" + strFactors + "&" + serviceName + "&" + destination;
	} else {
		newLocation = loginUrl + serviceName + "&" + destination;
	}
	CosignTrace1( "Redirecting to: %s\n", newLocation.c_str() );
	IHttpResponse*	response = context->GetResponse();
	response->Redirect( newLocation.c_str(), TRUE, FALSE );
	return( RQ_NOTIFICATION_FINISH_REQUEST );		

}

REQUEST_NOTIFICATION_STATUS
CosignModule::SetCookieAndRedirect(
	IHttpContext* context )
{
	char	newCookie[ 128 ];
	int		newCookieLength = 128;
	PCSTR	method = NULL;
	std::string	cookieHeader;
	std::string	newLocation;
	PCSTR	url = NULL;
	DWORD	urlSize;
	
	IHttpResponse*	response = context->GetResponse();
	IHttpRequest*	request = context->GetRequest();
	IHttpUrlInfo*	urlInfo = context->GetUrlInfo();
	BOOL	securePort = 0;
	//http + s + \0
	char	protocol[ 6 ];

	method = request->GetHttpMethod();
	CosignTrace1( "request->GetHttpMethod() = %s", method );

	urlSize = 0;
	context->GetServerVariable( "URL", &url, &urlSize );
	url = (PCSTR)context->AllocateRequestMemory( urlSize + 1 );
	if ( url == NULL ) {
		CosignLog( L"Not enough memory to allocate for URL" );
		/// xxx set an error
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	context->GetServerVariable( "URL", &url, &urlSize );
	CosignTrace1( "URL = %s", url );

	DWORD spsSize = 0;
	PCSTR serverPortSecure = NULL;
	context->GetServerVariable( "SERVER_PORT_SECURE", &serverPortSecure, &spsSize);
	serverPortSecure = (PCSTR)context->AllocateRequestMemory( spsSize + 1 );
	context->GetServerVariable( "SERVER_PORT_SECURE", &serverPortSecure, &spsSize);
	if ( serverPortSecure == NULL ) {
		CosignLog( L"Not enough memory to allocate for SERVER_PORT_SECURE" );
		/// xxx set an error
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	CosignTrace1( "SERVER_PORT_SECURE = %s\n", serverPortSecure );
	if ( atoi(serverPortSecure) ) {
		strcpy_s( protocol, sizeof protocol, "https" );
	} else {
		strcpy_s( protocol, sizeof protocol, "http" );
	}

	/// xxx Note: Should also check  SERVER_PORT to see if it is non-standard (443 or 80) and needs to be appended to destination

	DWORD serverNameSize = 0;
	PCSTR serverName = NULL;
	context->GetServerVariable( "SERVER_NAME", &serverName, &serverNameSize );
	serverName = (PCSTR)context->AllocateRequestMemory( serverNameSize + 1 );
	if ( serverName == NULL ) {
		CosignLog( L"Not enough memory to allocate for SERVER_NAME" );
		/// xxx set an error
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	context->GetServerVariable( "SERVER_NAME", &serverName, &serverNameSize );
	CosignTrace1( "SERVER_NAME = %s", serverName );

	CosignTrace0( L"No cookie.  Making a new one." );
	cg->MakeCookie( newCookie, newCookieLength );
	CosignTrace1( "New cookie = %s\nSetting header.\n", newCookie );
	

	cookieHeader = serviceName + "=" + newCookie + ";path=/" +
		(cookiesSecure ? ";secure" : "" ) +
		(cookiesHttpOnly ?" ;httponly" : "" ) +
		";";

	if ( response->SetHeader( "Set-Cookie", cookieHeader.c_str(), (USHORT)cookieHeader.length() + 1, TRUE ) != S_OK ) {
		CosignLog( L"Error setting cookie header" );
	}

	std::string destination = protocol;
	destination += "://";
	destination += serverName;
	destination += url;

	
	/// _snprintf_s( newLocation, newLocationSize, newLocationSize, "%s%s&%s", loginUrl.c_str(), cookieHeader, destination.c_str() );
	if ( factors.size() > 0 ) {
		newLocation = loginUrl + "factors=" + strFactors + "&" + serviceName + "=" + newCookie + "&" + destination;
	} else {
		newLocation = loginUrl + serviceName + "=" + newCookie + "&" + destination;
	}
	CosignTrace1( "Redirecting to: %s\n", newLocation.c_str() );
	response->Redirect( newLocation.c_str(), TRUE, FALSE );
	return( RQ_NOTIFICATION_FINISH_REQUEST );		
}

/*
 * ParseServiceCookie
 * return:
 *   0 - cookie found
 *   1 - cookie not found
 *  -1 - error occurred
 */
inline
int
CosignModule::ParseServiceCookie(
	std::string& ck,
	std::string& serviceCk ) {
	
	std::basic_string <char>::size_type	index;
	std::basic_string <char>::size_type	indexCkEnd;
	std::basic_string <char>::size_type	indexCkStart;
	
	index = ck.find( serviceName );
	
	if ( index == std::string::npos ) {
		CosignTrace1( "Could not find %s cookie.\n", serviceName.c_str() );
		return( 1 );
	}
	CosignTrace2( "Found %s cookie at position %u.\n", serviceName.c_str(), index );

	indexCkStart = ck.find( "=", index );
	if ( indexCkStart == std::string::npos ) {
		return( 1 );
	}
	indexCkStart++;
	if ( indexCkStart > ck.length() ) {
		return( 1 );
	}
	indexCkStart = ck.find_first_not_of( " \t", indexCkStart );
	indexCkEnd = ck.find( ";", indexCkStart );
	if ( indexCkEnd == std::string::npos ) {
		//Assume cookie goes to end of string
		indexCkEnd = ck.length();
	}
	serviceCk = ck.substr( indexCkStart, indexCkEnd - indexCkStart );
	const std::string validCookieChars = "_=@+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	if ( serviceCk.find_first_not_of( validCookieChars ) != std::string::npos ) {
		CosignLog( "Invalid characters found in cookie: %s", ck.c_str() );
		/// xxx critical error, log this
		return( -1 );
	}
	return( 0 );
}

REQUEST_NOTIFICATION_STATUS
CosignModule::OnAuthenticateRequest(
	IHttpContext*	context,
	IN IAuthenticationProvider* pProvider ) {

	CosignTrace1( L"OnAuthenticateRequest() Thread id = %ul\n", GetCurrentThreadId() );

	IHttpResponse*	response = context->GetResponse();
	IHttpRequest*	request = context->GetRequest();
	PCSTR	pcstrCookie;
	std::string	cookie;
	std::string	serviceCookie;
	USHORT	cookieSize;
	PROTECTEDSTATUS	protectedStatus;
	CosignServiceInfo	csi;
	std::string	ck;

	try {
		protectedStatus = GetConfig( context );
		switch( protectedStatus ) {
		case cosignUnprotected: //unprotected
			CosignTrace0( L"unprotected url" );
			return( RQ_NOTIFICATION_CONTINUE );
		case cosignProtected: //protected
			CosignTrace0( L"protected url" );
			break;
		case cosignAllowPublicAccess: //allowPublicAccess
			//carry on
			CosignTrace0( L"allowPublicAccess url" );
			break;
		default:
			/// xxx set some sort of error
			CosignTrace0( L"GetConfig failed." );
			return( RQ_NOTIFICATION_FINISH_REQUEST );
		}
	} catch ( CosignError ce ) {
		ce.showError();
		pProvider->SetErrorStatus( HRESULT_FROM_WIN32( ce.getError() ) );
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}

	CosignTrace0( L"Done getting config, get/setting cookie" );
	pcstrCookie = request->GetHeader( "Cookie", &cookieSize );
	if ( cookieSize == 0 || pcstrCookie == NULL ) {
		if ( protectedStatus == cosignAllowPublicAccess ) {
			goto convertUserData;
		}
		return( RedirectToLoginServer( context ) );
	} else {
		cookie = pcstrCookie;
		if ( cookie.length() == 0 ) {
			/// xxx Above check is extraneous
			CosignLog( L"OnAuthenticateRequest Not enough memory." );
			/// xxx pProvider->SetErrorStatus( blah );
			return( RQ_NOTIFICATION_FINISH_REQUEST );
		}
		CosignTrace1( "Cookie: \"%s\"\n", cookie.c_str() );

		if ( ParseServiceCookie( cookie, serviceCookie ) != 0 ) {
			if ( protectedStatus == cosignAllowPublicAccess ) {
				goto convertUserData;
			}
			return( RedirectToLoginServer( context ) );	
		}
		CosignTrace1( "Found service cookie: \"%s\"\n", serviceCookie.c_str() );
	}
	
	// Step one, check local cache and see if cached cookie is < 120 seconds
	// If cached cookie < 120 seconds old, populate server variables with cached data and return.

	ck = serviceName + "=" + serviceCookie;
	COSIGNSTATUS fileStatus = cdb->CheckCookie( serviceCookie, &csi );
	if ( fileStatus == COSIGNLOGGEDIN ) {
		CosignTrace0( L"Cookie DB logged in." );
		goto convertUserData;
	}
	// Step two, netcheck cookie

	COSIGNSTATUS status = NetCheckCookie( ck,  csi, TRUE, fileStatus );

	switch ( status ) {
		case COSIGNLOGGEDIN:
			if ( fileStatus == COSIGNOK ) {
				cdb->StoreCookie( serviceCookie, &csi );
			} else if ( fileStatus == COSIGNLOGGEDOUT ) {
				cdb->UpdateCookie( serviceCookie );
			}
			break;
		case COSIGNLOGGEDOUT:
			CosignTrace0( L"CheckCookie returned logged out, setting new cookie" );
			return( RedirectToLoginServer( context ) );
		case COSIGNERROR:
			CosignLog( L"CheckCookie returned an error" );
			if ( protectedStatus == cosignAllowPublicAccess ) {
				goto convertUserData;
			}
			return( RQ_NOTIFICATION_FINISH_REQUEST );
		case COSIGNRETRY:
			CosignTrace0( L"CheckCookie returned retry" );
			if ( protectedStatus == cosignAllowPublicAccess ) {
				goto convertUserData;
			}
			return( RedirectToLoginServer( context ) );
		default:
			CosignLog( L"CheckCookie returned unknown value" );
			return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	// Check factors
	for ( std::vector<std::string>::iterator iter = factors.begin(); iter != factors.end(); iter++ ) {
		if ( std::find( csi.factors.begin(), csi.factors.end(), *iter ) == csi.factors.end() ) {
			// factor not found
			if ( protectedStatus == cosignAllowPublicAccess ) {
				goto convertUserData;
			}
			return( RedirectToLoginServer( context ) );
		} 
	}

convertUserData:
	CosignTrace0( L"Converting user data to wide" );
	DWORD	bufferSize = (DWORD)((csi.strFactors.length() + csi.user.length() + csi.realm.length() + serviceName.length() + 1)*2);
	PWCHAR	buffer = (PWCHAR)context->AllocateRequestMemory( bufferSize );
	size_t	charsConverted;
	errno_t	err;
	HRESULT	hr;

	
	if ( !csi.strFactors.empty() ) {
		err = mbstowcs_s( &charsConverted, buffer, bufferSize, csi.strFactors.c_str(), bufferSize - 1);
		if ( err != 0 ) {
			CosignLog( "mcstowcs_s(%s) failed with %d", csi.strFactors.c_str(), err );
		}
		hr = context->SetServerVariable( "HTTP_COSIGN_FACTOR", buffer );
		hr = context->SetServerVariable( "COSIGN_FACTOR", buffer );
		if ( hr != S_OK ) {
			CosignLog( L"Could not set server variable COSIGN_FACTOR" );
		} else {
			CosignLog( L"Set HTTP_COSIGN_FACTOR" );
		}
	}

	if ( !csi.user.empty() ) {
		err = mbstowcs_s( &charsConverted, buffer, bufferSize, csi.user.c_str(), bufferSize - 1);
		if ( err != 0 ) {
			CosignLog( "mcstowcs_s(%s) failed with %d", csi.user.c_str(), err );
		}

        /*
         * Set REMOTE_USER by way of (IAuthenticationProvider*) pProvider->SetUser()
         * based on http://msdn.microsoft.com/en-us/library/ms689307.aspx
         */
        IHttpUser* currentUser = context->GetUser();

        DWORD usernameLength = (DWORD)csi.user.length() + 1;
        PWSTR username = (PWSTR)context->AllocateRequestMemory( usernameLength * sizeof(wchar_t) );

        MultiByteToWideChar(CP_ACP, 0, csi.user.c_str(), -1, username, usernameLength);

        if (NULL == currentUser) {
            CosignUser* cosignUser = new CosignUser( (PCWSTR)username );
            pProvider->SetUser(cosignUser);
        }
		if ( compatibilityMode ) {
			CosignLog( L"compatibilityMode is true so setting remote_user" );
			hr = context->SetServerVariable( "HTTP_REMOTE_USER", username );
		} else {
			CosignLog( L"compatibilityMode is false so NOT setting remote_user" );
		}
	}

	if ( !csi.realm.empty() ) {
		err = mbstowcs_s( &charsConverted, buffer, bufferSize, csi.realm.c_str(), bufferSize - 1);
		if ( err != 0 ) {
			CosignLog( L"mcstowcs_s(%s) failed with %d", csi.realm.c_str(), err );
		}
		hr = context->SetServerVariable( "HTTP_REMOTE_REALM", buffer );
		hr = context->SetServerVariable( "REMOTE_REALM", buffer );
		if ( hr != S_OK ) {
			CosignLog( L"Could not set server variable REMOTE_REALM" );
		}
	}
	
	if ( !serviceName.empty() ) {
		err = mbstowcs_s( &charsConverted, buffer, bufferSize, serviceName.c_str(), bufferSize - 1);
		if ( err != 0 ) {
			CosignLog( "mcstowcs_s(%s) failed with %d", serviceName.c_str(), err );
		}
		hr = context->SetServerVariable( "COSIGN_SERVICE", buffer );
		hr = context->SetServerVariable( "HTTP_COSIGN_SERVICE", buffer );
		if ( hr != S_OK ) {
			CosignLog( L"Could not set server variable COSIGN_SERVICE" );
		}
	}

	return( RQ_NOTIFICATION_CONTINUE );
}

COSIGNSTATUS
CosignModule::NetCheckCookie( std::string& cookie, CosignServiceInfo& csi, BOOL retrieve, COSIGNSTATUS fileStatus = COSIGNLOGGEDOUT )
{
	COSIGNSTATUS status = COSIGNERROR;
		CosignTrace0( L"CHECKing cookie, waiting for mutex." );
	///std::string	ck = serviceName + "=" + serviceCookie;
	DWORD wfso = WaitForSingleObject( cl->mutex, INFINITE );
	CosignTrace0( L"Obtained the mutex." );
	if ( wfso != WAIT_OBJECT_0 ) {
		if ( wfso == WAIT_FAILED ) {
			///  pProvider->SetErrorStatus( GetLastError() );
			CosignLog( L"Error waiting for connection list mutex: 0x%x", GetLastError() );
		} else {
			///  pProvider->SetErrorStatus( wfso );
			CosignLog( L"Error waiting for connection list mutex: 0x%x", wfso );
		}
		return( COSIGNERROR );
	}
	status = cl->CheckCookie( &cookie, &csi, TRUE );
	CosignTrace0( L"Cookie, user is logged in." );

		/*
		 * fileStatus == COSIGNOK means that the service cookie is not locally cached.
		 * If this is the case, then assume that proxy cookies and kerberos tickets
		 * have not yet been retrieved and get them now.
		 */
	if ( retrieve ) {
		if ( fileStatus == COSIGNOK && cl->getProxyCookies() ) {
			cl->RetrieveProxyCookies( cookie );
		}	
		if ( fileStatus == COSIGNOK && cl->getKerberosTickets() ) {
			cl->RetrieveKerberosTicket();
		}
	}
	if ( !ReleaseMutex( cl->mutex ) ) {
		CosignLog( L"Error releasing connection list mutex: 0x%x", GetLastError() );
		///  pProvider->SetErrorStatus( GetLastError() );
		return( COSIGNERROR );
	}
	CosignTrace0( L"Released the mutex." );
	return( status );
}

BOOL
CosignModule::Log(
	LPCWSTR str ){

	OutputDebugStringW( str );
	if ( eventLog != NULL ) {
		return( ReportEventW( eventLog, EVENTLOG_INFORMATION_TYPE, 0, 0,
                NULL, 1, 0, &str, NULL ) );
	}
	return( FALSE );
}

BOOL
CosignModule::Log(
	PCSTR str ){

	OutputDebugStringA( str );
	if ( eventLog != NULL ) {
		return( ReportEventA( eventLog, EVENTLOG_INFORMATION_TYPE, 0, 0,
                NULL, 1, 0, &str, NULL ) );
	}
	return( FALSE );
}

CosignModule::CosignModule( IAppHostAdminManager** aham, ConnectionList* cl, CookieDatabase* cdb ) {

	this->aham = *aham;
	this->cl = cl;
	this->cdb = cdb;
	eventLog = RegisterEventSource( NULL, L"IISADMIN" );
	cg = new CookieGenerator();
	
	loginUrl = "";
	serviceName = "";
	cookiesSecure = TRUE;
	cookiesHttpOnly = FALSE;
	CosignTrace0( L"CosignModule created." );
}

CosignModule::~CosignModule() {

	if ( eventLog != NULL ) {
		DeregisterEventSource( eventLog );
		eventLog = NULL;
	}
	if ( cg ) {
		delete cg;
	}
	CosignTrace0( L"CosignModule destructed." );
}

HRESULT
CosignModuleFactory::GetHttpModule(
	OUT CHttpModule**	ppModule,
	IN	IModuleAllocator*	pAllocator ) {

	CosignTrace1( L"GetHttpModule Thread id = %ul\n", GetCurrentThreadId() );

	UNREFERENCED_PARAMETER( pAllocator );	
	CosignModule*	mod	= new CosignModule( &aham, &cl, &cdb );

	if ( !mod ) {
		return HRESULT_FROM_WIN32( ERROR_NOT_ENOUGH_MEMORY );
	}
	*ppModule = mod;

	mod = NULL;
	return S_OK;
}

CosignModuleFactory::CosignModuleFactory( IAppHostAdminManager** aham ) {
	/// Should initialize stuff be done here or in RegisterModule?
	/// stuff to be initialized: reading config file, sockets,
	/// something that notices when the configuration file changes
	this->aham = *aham;
	CosignTrace0( L"CosignModuleFactory constructed." );
}

DWORD
CosignModuleFactory::Init() {

	HRESULT	hr;
	int		retCode = 0;
	BSTR	bstrSection			= SysAllocString(L"system.webServer/cosign");
	BSTR	bstrConfigPath		= SysAllocString(L"MACHINE/WEBROOT/APPHOST");
	BSTR	bstrWebloginServer	= SysAllocString(L"webloginServer");
	BSTR	bstrName			= SysAllocString(L"name");
	BSTR	bstrPort			= SysAllocString(L"port");
	BSTR	bstrCrypto			= SysAllocString(L"crypto");
	BSTR	bstrCertificateCommonName	= SysAllocString(L"certificateCommonName");
	BSTR	bstrCookieDb		= SysAllocString(L"cookieDb");
	BSTR	bstrDirectory		= SysAllocString(L"directory");
	BSTR	bstrExpireTime		= SysAllocString(L"expireTime");
	BSTR	bstrKerberosTickets	= SysAllocString(L"kerberosTickets");
	BSTR	bstrProxyCookies	= SysAllocString(L"proxyCookies");

	IAppHostElement*	ahe		= NULL;
	IAppHostElement*	ahe2	= NULL;
	IAppHostProperty*	ahp		= NULL;
	VARIANT				value;
	std::wstring		reason;

	try {
		CosignLog( "Initializing CosignModule version %s", VERSION.c_str() );
		hr = aham->GetAdminSection( bstrSection, bstrConfigPath, &ahe );
		if ( FAILED(hr) ) {
			switch( hr ) {
				case S_OK:
					reason = L"S_OK: Indicates that the operation was successful.";
					break;
				case ERROR_INVALID_DATA:
					reason = L"ERROR_INVALID_DATA: Indicates that the data is invalid.";
					break;
 
				case ERROR_FILE_NOT_FOUND:
					reason = L"ERROR_FILE_NOT_FOUND: Indicates that the requested path was not found.";
					break;
				case ERROR_INVALID_PARAMETER:
					reason = L"ERROR_INVALID_PARAMETER: Indicates that a parameter is incorrect.";
					break;
				case E_ACCESSDENIED:
					reason = L"E_ACCESSDENIED: Indicates that the operation was not successful because of access restrictions.";
					break;
				default:
					reason = L"Unknown error.";
					break;
			}
			CosignLog( L"Could not get cosign admin section. %s, %s.  reason: %s", bstrSection, bstrConfigPath, reason.c_str() );
			throw( CosignError( hr, __LINE__ -2, __FILE__ ) );
		}
		GetElement( ahe, &bstrWebloginServer, &ahe2 );
		GetPropertyValueByName( ahe2, &value, &bstrName, VT_BSTR );
		config.webloginServer = value.bstrVal;
		GetPropertyValueByName( ahe2, &value, &bstrPort, VT_I4 );
		config.port = value.intVal;

		GetElement( ahe, &bstrCrypto, &ahe2 );
		GetPropertyValueByName( ahe2, &value, &bstrCertificateCommonName, VT_BSTR );
		config.certificateCommonName = value.bstrVal;

		GetElement( ahe, &bstrCookieDb, &ahe2 );
		GetPropertyValueByName( ahe2, &value, &bstrDirectory, VT_BSTR );
		config.cookieDbDirectory = value.bstrVal;
		GetPropertyValueByName( ahe2, &value, &bstrExpireTime, VT_UI8 );
		config.cookieDbExpireTime = (ULONGLONG)value.uintVal;

		GetElement( ahe, &bstrKerberosTickets, &ahe2 );
		GetPropertyValueByName( ahe2, &value, &bstrDirectory, VT_BSTR );
		config.kerberosTicketsDirectory = L"\\\\?\\";
		config.kerberosTicketsDirectory += value.bstrVal;

		GetElement( ahe, &bstrProxyCookies, &ahe2 );
		GetPropertyValueByName( ahe2, &value, &bstrDirectory, VT_BSTR );
		config.proxyCookiesDirectory = L"\\\\?\\";
		config.proxyCookiesDirectory += value.bstrVal;

		if ( config.certificateCommonName.empty() ||
			config.cookieDbDirectory.empty() ||
			config.webloginServer.empty() ) {
			throw( CosignError( ERROR_INVALID_DATA, __LINE__ -1, __FILE__ ) );
		}


#ifdef COSIGNTRACE
		config.dump();
#endif
		SysFreeString( bstrName );
		SysFreeString( bstrPort );
		SysFreeString( bstrCrypto );
		SysFreeString( bstrSection );
		SysFreeString( bstrCookieDb );
		SysFreeString( bstrDirectory );
		SysFreeString( bstrExpireTime );
		SysFreeString( bstrConfigPath );
		SysFreeString( bstrWebloginServer );
		SysFreeString( bstrCertificateCommonName );

		PCCERT_CONTEXT	certificateContext = NULL;
		WSADATA			wsadata;
		int				err;

		certificateContext = RetrieveCertFromStore( config.certificateCommonName, certificateStore );
		if ( certificateContext == NULL ) {
			CosignLog( L"Could not RetrieveCertFromStore(), certificateContext is NULL" );
			throw( CosignError( (DWORD)GetLastError(), __LINE__ - 3, __FUNCTION__ ) );
		}
		if ( (err = WSAStartup( MAKEWORD(2, 2), &wsadata )) != 0 ) {
			throw( CosignError( (DWORD)err, __LINE__ - 1, __FUNCTION__ ) );
		}
		cl.Init(
			config.webloginServer,
			config.port,
			certificateContext,
			config.kerberosTicketsDirectory,
			config.proxyCookiesDirectory );
		cl.Populate();
		/// xxx HashLength will be a configuration item
		cdb.Init(
			config.cookieDbDirectory,
			config.cookieDbExpireTime, 0,
			config.kerberosTicketsDirectory,
			config.proxyCookiesDirectory );
	} catch ( CosignError ce ) {
		ce.showError();
		return( ce.getError() );
	}

	return( 0 );
}

void
CosignModuleFactory::Terminate() {

	cl.Depopulate();
	WSACleanup();
	CosignTrace0( L"CosignModuleFactory terminated." );
	delete this;
}

REQUEST_NOTIFICATION_STATUS
CosignModule::OnExecuteRequestHandler(
	IN IHttpContext *                       context,
	IN IHttpEventProvider *                 pProvider
) {
	// Parse query string
	PCSTR queryString = GetSerVar( "QUERY_STRING", context );
	std::string qs = queryString;
	CosignLog( "execreqhandler: qs = %s", qs.c_str() );

	/// xxx need better error handling of string parsing functions.
	// http://www.example.org/cosign/valid/?cosign-www.example=abc123&https://www.example.org/protected/
	size_t pos = qs.find_first_of( "=" );
	std::string serviceName = qs.substr( 0, pos );
	qs = qs.substr( pos );


	pos = qs.find_first_of( "&" );
	std::string serviceCookie = qs.substr( 1, pos - 1);
	std::string destination = qs.substr( pos+1 );

	// Get configuration data for validation URL and postErrorRedirectUrl
	this->validReference = "blargh";
	GetValidationConfig( context );
	//GetConfig( context );
	// Validate URL
	CosignLog( "Regex is %s", this->validReference.c_str() );
	//boost::regex	pattern( this->validReference );
	//boost::regex	pattern( this->validReference.c_str() );
	std::tr1::regex pattern( this->validReference.c_str() );
	if ( !std::tr1::regex_match( destination, pattern ) ) {
		CosignLog( "Destination of %s doesn't match %s", destination.c_str(), this->validReference.c_str() );
		IHttpResponse*	response = context->GetResponse();
		response->Redirect( this->validationErrorRedirect.c_str(), TRUE, FALSE );
		return( RQ_NOTIFICATION_FINISH_REQUEST );		
	}

	// CHECK service cookie
	CosignLog( "CHECK'ing cookie" );
	CosignServiceInfo	csi;

	serviceCookie = serviceName + "=" + serviceCookie;
	COSIGNSTATUS status = NetCheckCookie( serviceCookie, csi, FALSE );

	IHttpResponse* response = context->GetResponse();

	std::string cookieHeader = serviceCookie + ";path=/" +
		(cookiesSecure ? ";secure" : "" ) +
		(cookiesHttpOnly ?" ;httponly" : "" ) +
		";";

	if ( response->SetHeader( "Set-Cookie", cookieHeader.c_str(), (USHORT)cookieHeader.length() + 1, TRUE ) != S_OK ) {
		CosignLog( L"Error setting cookie header" );
	}



	response->Redirect( destination.c_str(), TRUE, FALSE );
    return( RQ_NOTIFICATION_FINISH_REQUEST );
}