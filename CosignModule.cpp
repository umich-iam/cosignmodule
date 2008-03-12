
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

#include "fbase64.h"
#include "CookieGenerator.h"
#include "Settings.h"
#include "snetpp.h"
#include "Log.h"
#include "CosignServiceInfo.h"
#include "ConnectionList.h"
#include "CookieDatabase.h"
#include "CosignModule.h"


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
		if ( CertGetNameString( ctx, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, pszNameString, 1024 ) == 1 ) {
			throw( CosignError( GetLastError(), __LINE__ -1, __FUNCTION__ ) );
		}
		if ( wcsstr( pszNameString, cn.c_str() ) != NULL ) {
			// Success happens here
			CosignLog( L"Found matching certificate!\n" );
			return( ctx );
		}
		prevCtx = ctx;
	}
	CosignLog( L"Could not find matching certificate.\n" );
	return( NULL );
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
		throw( -1 );
	}
	hr = ahp->get_Value( value );
	if ( FAILED(hr) ) {
		CosignLog( L"GetPropertyValueByName( %s ) failed.  Value not set.", *name );
		throw( -2 );
	}
	if ( value->vt != type ) {
		CosignLog( L"GetPropertyValueByName( %s ) failed.  Property type %d differs from type expected %d.",
			*name, value->vt, type );
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
		
		///throw( -3 );
	}
}

/* 
 * GetConfig()
 * return:
 *	-1 error
 *   0 unprotected
 *   1 protected
 *   2 allowPublicAccess
 */
int
CosignModule::GetConfig( IHttpContext* context ) {
	HRESULT	hr;
	int		retCode			= 0;
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
	BSTR	bstrConfigPath;
	IHttpApplication*	app	= NULL;
	IAppHostElement*	ahe	= NULL;
	IAppHostElement*	ahe2= NULL;
	IAppHostProperty*	ahp	= NULL;
	IMetadataInfo*			imi		= NULL;
	PCTSTR					metaPath= NULL;
	IAppHostConfigManager*	ahcm	= NULL;
	IAppHostConfigFile*		ahcf	= NULL;


/****************************************************************************************************************/
	OutputDebugString( L"NEW GetConfig()uration logics!\n" );
	try {
		imi = context->GetMetadata();
		metaPath = imi->GetMetaPath();
		
		CosignLog( L"Metapath = %s\n", metaPath );
		bstrConfigPath = SysAllocString( metaPath );
	
		hr = aham->GetAdminSection( bstrSection, bstrConfigPath, &ahe );
		if ( FAILED(hr) || ahe == NULL ) {
			OutputDebugString( L"GetAdminSection failed(3)." );
			throw( -1 );
		}
		
		/* Should never fail? */
		hr = ahe->GetElementByName( bstrProtected, &ahe2 );
		if ( FAILED(hr) || ahe2 == NULL ) {
			throw( -1 );
		}
		GetPropertyValueByName( ahe2, &value, &bstrStatus, VT_I4 );
		retCode = V_I4(&value);
		if ( retCode == 0 ) {
			// Unprotected.  No need to retrieve other values.
			CosignLog( L"Unprotected, throwing" );
			throw( retCode );
		}

		hr = ahe->GetElementByName( bstrWebloginServer, &ahe2 );
		if ( FAILED(hr) ) {
			CosignLog( L"Could not retrieve cosign <webloginServer> element" );
			throw( -1 );
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
			throw( -1 );
		}
		GetPropertyValueByName( ahe2, &value, &bstrName, VT_BSTR );
		strValue = _com_util::ConvertBSTRToString( value.bstrVal ); 
		serviceName = strValue;
		delete strValue;
/*************************************************************************************************/
		IAppHostElementCollection* ahec;
		hr = ahe2->get_Collection( &ahec );
		if ( FAILED(hr) ) {
			CosignLog( L"Could not get service collection" );
		} else {
			DWORD numFactors;
			hr = ahec->get_Count( &numFactors );
			if ( FAILED(hr) ) {
				CosignLog( L"Could not get_count for factors" );
				throw( CosignError( hr, __LINE__ - 3, __FILE__ ) );
			}
			CosignLog( L"NumFactors = %u", numFactors );
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
				CosignLog( L"Got %s = %s", bstrFactor, value.bstrVal );
				strValue = _com_util::ConvertBSTRToString( value.bstrVal );
				if ( strFactors == "" ) {
					strFactors += strValue;
				} else {
					strFactors += ",";
					strFactors += strValue;
				}
				//strFactors += (strFactors == "" ? "" : " " ) + strValue;
				factors.push_back( strValue );
				delete strValue;
				//ahec->I
			}
			for ( std::vector<std::string>::iterator iter = factors.begin(); iter != factors.end(); iter++ ) {
				CosignLogA( "Factor from vector = %s", iter->c_str() );
			}
			
		}
/*************************************************************************************************/
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

	} catch( CosignError ce ) {
		ce.showError();
	} catch ( int error ) {
		retCode = error;
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
	return( retCode );
}

REQUEST_NOTIFICATION_STATUS
CosignModule::SetCookieAndRedirect(
	IHttpContext* context ) {
	
	char	newCookie[ 128 ];
	int		newCookieLength = 128;
	PCSTR	method = NULL;
#ifdef __OLD_AND_BUSTED
	char*	cookieHeader;
	int		cookieHeaderSize;
	char*	newLocation;
	DWORD	newLocationSize;
#else //new hotness
	std::string	cookieHeader;
	std::string	newLocation;
#endif
	PCSTR	url = NULL;
	DWORD	urlSize;
	
	IHttpResponse*	response = context->GetResponse();
	IHttpRequest*	request = context->GetRequest();
	IHttpUrlInfo*	urlInfo = context->GetUrlInfo();
	BOOL	securePort = 0;
	//http + s + \0
	char	protocol[ 6 ];

	method = request->GetHttpMethod();
	CosignLogA( "request->GetHttpMethod() = %s", method );

	urlSize = 0;
	context->GetServerVariable( "URL", &url, &urlSize );
	url = (PCSTR)context->AllocateRequestMemory( urlSize + 1 );
	if ( url == NULL ) {
		CosignLog( L"Not enough memory to allocate for URL" );
		/// xxx set an error
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	context->GetServerVariable( "URL", &url, &urlSize );
	CosignLogA( "URL = %s", url );

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
	CosignLogA( "SERVER_PORT_SECURE = %s\n", serverPortSecure );
	if ( atoi(serverPortSecure) ) {
		strcpy_s( protocol, sizeof protocol, "https" );
	} else {
		strcpy_s( protocol, sizeof protocol, "http" );
	}

	/// xxx Note: Should also check SERVER_PORT to see if it is non-standard (443 or 80) and needs to be appended to destination

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
	CosignLogA( "SERVER_NAME = %s", serverName );

	CosignLog( L"No cookie.  Making a new one." );
	cg->MakeCookie( newCookie, newCookieLength );
	CosignLogA( "New cookie = %s\nSetting header.\n", newCookie );
	
#ifdef __OLD_AND_BUSTED
	// +2 for terminating '\0' and '='
	cookieHeaderSize = newCookieLength + (int)serviceName.length() + 2;
	cookieHeader = (char*)context->AllocateRequestMemory( cookieHeaderSize );
	_snprintf_s( cookieHeader, cookieHeaderSize, cookieHeaderSize, "%s=%s", serviceName.c_str(), newCookie );
	if ( response->SetHeader( "Set-Cookie", cookieHeader, (USHORT)strlen(cookieHeader), TRUE ) != S_OK ) {
		CosignLog( L"Error setting cookie header" );
	}

	std::string destination = protocol;
	destination += "://";
	destination += serverName;
	destination += url;

	newLocationSize = cookieHeaderSize + (int)loginUrl.length() + (int)destination.length() + 3;
	newLocation = (char*)context->AllocateRequestMemory( newLocationSize );
	_snprintf_s( newLocation, newLocationSize, newLocationSize, "%s%s&%s", loginUrl.c_str(), cookieHeader, destination.c_str() );
	CosignLogA( "Redirecting to: %s\n", newLocation );
	response->Redirect( newLocation, TRUE, FALSE );
	return( RQ_NOTIFICATION_FINISH_REQUEST );		
#else
	// new hotness

	cookieHeader = serviceName + "=" + newCookie + 
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
		CosignLog( L"redirect with factors" );
		newLocation = loginUrl + "factors=" + strFactors + "&" + serviceName + "=" + newCookie + "&" + destination;
	} else {
		CosignLog( L"redirect without factors" );
		newLocation = loginUrl + serviceName + "=" + newCookie + "&" + destination;
	}
	CosignLogA( "Redirecting to: %s\n", newLocation.c_str() );
	response->Redirect( newLocation.c_str(), TRUE, FALSE );
	return( RQ_NOTIFICATION_FINISH_REQUEST );		
#endif

	 
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
	std::string* ck,
	std::string* serviceCk ) {
	
	std::basic_string <char>::size_type	index;
	std::basic_string <char>::size_type	indexCkEnd;
	std::basic_string <char>::size_type	indexCkStart;
	
	index = ck->find( serviceName );
	
	if ( index == std::string::npos ) {
		CosignLogA( "Could not find %s cookie.\n", serviceName.c_str() );
		return( 1 );
	}
	CosignLogA( "Found %s cookie at position %u.\n", serviceName.c_str(), index );

	indexCkStart = ck->find( "=", index );
	if ( indexCkStart == std::string::npos ) {
		return( 1 );
	}
	indexCkStart++;
	if ( indexCkStart > ck->length() ) {
		return( 1 );
	}
	indexCkStart = ck->find_first_not_of( " \t", indexCkStart );
	indexCkEnd = ck->find( ";", indexCkStart );
	if ( indexCkEnd == std::string::npos ) {
		//Assume cookie goes to end of string
		indexCkEnd = ck->length();
	}
	*serviceCk = ck->substr( indexCkStart, indexCkEnd - indexCkStart );

	return( 0 );
}

REQUEST_NOTIFICATION_STATUS
CosignModule::OnAuthenticateRequest(
	IHttpContext*	context,
	IN IAuthenticationProvider* pProvider ) {

	DWORD threadId = GetCurrentThreadId();
	CosignLog( L"OnAuthenticateRequest() Thread id = %ul\n", threadId );

	IHttpResponse*	response = context->GetResponse();
	IHttpRequest*	request = context->GetRequest();
	PCSTR	pcstrCookie;
	std::string	cookie;
	std::string	serviceCookie;
	USHORT	cookieSize;

	switch( GetConfig( context ) ) {
	case 0: //unprotected
		OutputDebugString( L"unprotected url" );
		return( RQ_NOTIFICATION_CONTINUE );
	case 1: //protected
		OutputDebugString( L"protected url" );
		break;
	case 2: //allowPublicAccess
		//carry on
		OutputDebugString( L"allowPublicAccess url" );
		break;
	case -1:
	default:
		/// xxx set some sort of error
		OutputDebugString( L"GetConfig failed." );
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}

	OutputDebugString( L"Done getting config, get/setting cookie" );
	/// If we're getting and setting headers alot, may want a 'helper' function for this.
	pcstrCookie = request->GetHeader( "Cookie", &cookieSize );
	if ( cookieSize == 0 || pcstrCookie == NULL ) {
		CosignLog( L"Cookie size is 0, setting new cookie\n" );
		return( SetCookieAndRedirect( context ) );
	} else {
		cookie = pcstrCookie;
		if ( cookie.length() == 0 ) {
			/// xxx Above check is extraneous
			CosignLog( L"OnAuthenticateRequest Not enough memory!" );
			/// xxx pProvider->SetErrorStatus( blah );
			return( RQ_NOTIFICATION_FINISH_REQUEST );
		}
		CosignLogA( "Cookie: \"%s\"\n", cookie.c_str() );

		if ( ParseServiceCookie( &cookie, &serviceCookie ) != 0 ) {
			return( SetCookieAndRedirect( context ) );	
		}
		CosignLogA( "Found service cookie: \"%s\"\n", serviceCookie.c_str() );
	}
	
	/// Step one, check local cache and see if cached cookie is < 120 seconds
	/// If cached cookie < 120 seconds old, populate server variables with cached data and return.

	CosignServiceInfo	csi;
	std::string	ck = serviceName + "=" + serviceCookie;
	COSIGNSTATUS fileStatus = cdb->CheckCookie( serviceCookie, &csi );
	if ( fileStatus == COSIGNLOGGEDIN ) {
		CosignLog( L"Cookie DB logged in." );
		goto convertUserData;
	}
	/// Step two, netcheck cookie

	CosignLog( L"CHECKing cookie, waiting for mutex." );
	///std::string	ck = serviceName + "=" + serviceCookie;
	DWORD wfso = WaitForSingleObject( cl->mutex, INFINITE );
	CosignLog( L"Obtained the mutex." );
	if ( wfso != WAIT_OBJECT_0 ) {
		if ( wfso == WAIT_FAILED ) {
			///  pProvider->SetErrorStatus( GetLastError() );
			CosignLog( L"Error waiting for connection list mutex: 0x%x", GetLastError() );
		} else {
			///  pProvider->SetErrorStatus( wfso );
			CosignLog( L"Error waiting for connection list mutex: 0x%x", wfso );
		}
		
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	COSIGNSTATUS status = cl->CheckCookie( &ck, &csi, TRUE );
	if ( !ReleaseMutex( cl->mutex ) ) {
		CosignLog( L"Error releasing connection list mutex: 0x%x", GetLastError() );
		///  pProvider->SetErrorStatus( GetLastError() );
		return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	CosignLog( L"Released the mutex." );
	switch ( status ) {
		case COSIGNLOGGEDIN:
			if ( fileStatus == COSIGNOK ) {
				cdb->StoreCookie( serviceCookie, &csi );
			} else if ( fileStatus == COSIGNLOGGEDOUT ) {
				cdb->UpdateCookie( serviceCookie );
			}
			CosignLog( L"Cookie, user is logged in." );
			break;
		case COSIGNLOGGEDOUT:
			CosignLog( L"CheckCookie returned logged out, setting new cookie" );
			return( SetCookieAndRedirect( context ) );
		case COSIGNERROR:
			CosignLog( L"CheckCookie returned an error" );
			return( RQ_NOTIFICATION_FINISH_REQUEST );
		case COSIGNRETRY:
			CosignLog( L"CheckCookie returned retry" );
			return( SetCookieAndRedirect( context ) );
		default:
			CosignLog( L"CheckCookie returned unknown value" );
			return( RQ_NOTIFICATION_FINISH_REQUEST );
	}
	// Check factors
#ifdef __OLD_AND_BUSTED__
	if ( factors.size() > 0 ) {
		for( int i = 0; i < factors.size(); i++ ) {
			if ( std::find( csi.factors.begin(), csi.factors.end(), factors[0] ) == factors.end() ) {
				CosignLog( L"Not all factor satisfied!" );
				return( SetCookieAndRedirect( context ) );
			}
		}
	}
#else // new hotness
	for ( std::vector<std::string>::iterator iter = factors.begin(); iter != factors.end(); iter++ ) {
		CosignLogA( "Factors required (from factorsvector) = %s", iter->c_str() );
	}
	for ( std::vector<std::string>::iterator iter = csi.factors.begin(); iter != csi.factors.end(); iter++ ) {
		CosignLogA( "Factor fulfilled (from csi.factorsvector) = %s", iter->c_str() );
	}


	for ( std::vector<std::string>::iterator iter = factors.begin(); iter != factors.end(); iter++ ) {
		CosignLogA( "Looking for fulfillment of factor %s", iter->c_str() );
		if ( std::find( csi.factors.begin(), csi.factors.end(), *iter ) == csi.factors.end() ) {
			CosignLog( L"Ohs noes!  factor not found!  redirecting!" );
			return( SetCookieAndRedirect( context ) );
		} else {
			CosignLog( L"Nice factor satisfied!" );
		}
	}
#endif

convertUserData:
	CosignLog( L"Converting user data to wide" );
	DWORD	bufferSize = (DWORD)((csi.strFactors.length() + csi.user.length() + csi.realm.length() + serviceName.length() + 1)*2);
	PWCHAR	buffer = (PWCHAR)context->AllocateRequestMemory( bufferSize );
	size_t	charsConverted;
	errno_t	err;
	HRESULT	hr;

	err = mbstowcs_s( &charsConverted, buffer, bufferSize, csi.strFactors.c_str(), bufferSize - 1);
	if ( err != 0 ) {
		CosignLogA( "mcstowcs_s(%s) failed with %d", csi.strFactors.c_str(), err );
	}
	hr = context->SetServerVariable( "COSIGN_FACTOR", buffer );
	if ( hr != S_OK ) {
		CosignLog( L"Could not set server variable COSIGN_FACTOR" );
	}

	err = mbstowcs_s( &charsConverted, buffer, bufferSize, csi.user.c_str(), bufferSize - 1);
	if ( err != 0 ) {
		CosignLogA( "mcstowcs_s(%s) failed with %d", csi.user.c_str(), err );
	}
	hr = context->SetServerVariable( "REMOTE_USER", buffer );
	if ( hr != S_OK ) {
		CosignLog( L"Could not set server variable REMOTE_USER" );
	}

	err = mbstowcs_s( &charsConverted, buffer, bufferSize, csi.realm.c_str(), bufferSize - 1);
	if ( err != 0 ) {
		CosignLog( L"mcstowcs_s(%s) failed with %d", csi.realm.c_str(), err );
	}
	hr = context->SetServerVariable( "REMOTE_REALM", buffer );
	if ( hr != S_OK ) {
		CosignLog( L"Could not set server variable REMOTE_REALM" );
	}

	err = mbstowcs_s( &charsConverted, buffer, bufferSize, serviceName.c_str(), bufferSize - 1);
	if ( err != 0 ) {
		CosignLogA( "mcstowcs_s(%s) failed with %d", serviceName.c_str(), err );
	}
	hr = context->SetServerVariable( "COSIGN_SERVICE", buffer );
	if ( hr != S_OK ) {
		CosignLog( L"Could not set server variable COSIGN_SERVICE" );
	}

	return( RQ_NOTIFICATION_CONTINUE );
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
	Log( L"Instantiated CosignModule" );
	cg = new CookieGenerator();
	
	loginUrl = "";
	serviceName = "";
	cookiesSecure = TRUE;
	cookiesHttpOnly = FALSE;
	OutputDebugString( L"CosignModule created." );
}

CosignModule::~CosignModule() {

	if ( eventLog != NULL ) {
		DeregisterEventSource( eventLog );
		eventLog = NULL;
	}
	if ( cg ) {
		delete cg;
	}
	OutputDebugString( L"CosignModule destructed." );
}

HRESULT
CosignModuleFactory::GetHttpModule(
	OUT CHttpModule**	ppModule,
	IN	IModuleAllocator*	pAllocator ) {

	DWORD threadId = GetCurrentThreadId();
	CosignLog( L"GetHttpModule Thread id = %ul\n", threadId );

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
	OutputDebugString( L"CosignModuleFactory constructed." );
}

int
CosignModuleFactory::Init() {

	HRESULT		hr;
	int			retCode = 0;
	BSTR		bstrSection			= SysAllocString(L"system.webServer/cosign");
	BSTR		bstrConfigPath		= SysAllocString(L"MACHINE/WEBROOT/APPHOST");
	//BSTR		bstrConfigPath		= SysAllocString(L"MACHINE/WEBROOT");
	BSTR		bstrWebloginServer	= SysAllocString(L"webloginServer");
	BSTR		bstrName			= SysAllocString(L"name");
	BSTR		bstrPort			= SysAllocString(L"port");
	BSTR		bstrCrypto			= SysAllocString(L"crypto");
	BSTR		bstrCertificateCommonName	= SysAllocString(L"certificateCommonName");
	BSTR		bstrCookieDb		= SysAllocString(L"cookieDb");
	BSTR		bstrDirectory		= SysAllocString(L"directory");
	BSTR		bstrExpireTime		= SysAllocString(L"expireTime");
	IAppHostElement*	ahe		= NULL;
	IAppHostElement*	ahe2	= NULL;
	IAppHostProperty*	ahp		= NULL;
	VARIANT				value;

	/* xxx Might it make more sense to keep some of these values as BSTRs? */

	try {
		hr = aham->GetAdminSection( bstrSection, bstrConfigPath, &ahe );
		if ( FAILED(hr) ) {
			CosignLog( L"Could not get cosign admin section. %s, %s", bstrSection, bstrConfigPath );
			throw( -1 );
		}
		hr = ahe->GetElementByName( bstrWebloginServer, &ahe2 );
		if ( FAILED(hr) ) {
			CosignLog( L"Could not retrieve cosign <webloginServer> element" );
			throw( -1 );
		}

		GetPropertyValueByName( ahe2, &value, &bstrName, VT_BSTR );
		config.webloginServer = value.bstrVal;

		GetPropertyValueByName( ahe2, &value, &bstrPort, VT_I4 );
		config.port = value.intVal;

		hr = ahe->GetElementByName( bstrCrypto, &ahe2 );
		if ( FAILED(hr) ) {
			OutputDebugString( L"Could not retrieve cosign <crypto> element" );
			throw( -1 );
		}
		GetPropertyValueByName( ahe2, &value, &bstrCertificateCommonName, VT_BSTR );
		config.certificateCommonName = value.bstrVal;

		hr = ahe->GetElementByName( bstrCookieDb, &ahe2 );
		if ( FAILED(hr) ) {
			OutputDebugString( L"Could not retrieve cosign <cookieDb> element" );
			throw( -1 );
		}
		GetPropertyValueByName( ahe2, &value, &bstrDirectory, VT_BSTR );
		/// xxx expand any environment variables here
		config.cookieDbDirectory = value.bstrVal;

		GetPropertyValueByName( ahe2, &value, &bstrExpireTime, VT_UI8 );
		config.cookieDbExpireTime = (ULONGLONG)value.uintVal;

	} catch( int n ) {
		OutputDebugString( L"Error parsing cosign config values." );
		return( n );
	}
	config.dump();
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

	OutputDebugString( L"Retrieving cert from store." );
	PCCERT_CONTEXT	certificateContext = NULL;
	WSADATA			wsadata;
	int				err;

	try {
		certificateContext = RetrieveCertFromStore( config.certificateCommonName, certificateStore );
		if ( certificateContext == NULL ) {
			CosignLog( L"Could not RetrieveCertFromStore(), certificateContext is NULL" );
			throw( CosignError( (DWORD)GetLastError(), __LINE__ - 3, __FUNCTION__ ) );
		}
		if ( (err = WSAStartup( MAKEWORD(2, 2), &wsadata )) != 0 ) {
			throw( CosignError( (DWORD)err, __LINE__ - 1, __FUNCTION__ ) );
		}
		cl.Init( config.webloginServer, config.port, certificateContext );
		cl.Populate();
		/// xxx HashLength will be a configuration item
		cdb.Init( config.cookieDbDirectory, config.cookieDbExpireTime, 0 );
	} catch ( CosignError ce ) {
		ce.showError();
		retCode = -1;
	}

	return( retCode );
}

void
CosignModuleFactory::Terminate() {

	/// xxx WSACleanup() and socket termination code.
	OutputDebugString( L"CosignModuleFactory terminated." );
	delete this;
}
