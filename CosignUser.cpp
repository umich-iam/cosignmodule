#define _WINSOCKAPI_
#include <windows.h>
#include <io.h>
#include <sal.h>
#include <httpserv.h>

#include <string>
using namespace std;

#include "CosignUser.h"

// The CHttpUser method is the private virtual
// destructor for the CHttpUser class.
CosignUser::~CosignUser()
{
	userName = NULL;
}

// PRE: none.
// POST: sets the internal reference count to 1.
// The CHttpUser method is the public 
// constructor for the CHttpUser class.
CosignUser::CosignUser(PCWSTR currentUserName)
{
	userName = currentUserName;
    m_refs = 1;
}

// The GetRemoteUserName method 
// returns the remote name of the user.    
// return: L"ValidUser".
PCWSTR
CosignUser::GetRemoteUserName(VOID)
{
    return userName;
}

// The GetUserName method 
// returns the name of the user.
// return: L"ValidUser".
PCWSTR
CosignUser::GetUserName(VOID)
{
    return userName;
}

// The GetAuthenticationType method 
// returns the authentication type 
// for the user.
// return: L"Anonymous".
PCWSTR
CosignUser::GetAuthenticationType(VOID)
{
    return L"Cosign";
}

// The GetPassword method returns 
// the password for the user. This 
// password is empty because Anonymous
// authentication only requires only a
// non-NULL password value.
// return: L"".
PCWSTR
CosignUser::GetPassword(VOID)
{
    return L"";
}

// The GetImpersonationToken method returns 
// the impersonation token for the user.
// return: NULL.
HANDLE
CosignUser::GetImpersonationToken(VOID)
{
    return NULL;
}

// The GetPrimaryToken method returns 
// the primary token for the user.
// return: NULL.
HANDLE
CosignUser::GetPrimaryToken(VOID)
{
    return NULL;
}

// PRE: none.
// POST: the internal reference 
// count is incremented by 1.
// The ReferenceUser method should be called 
// when a new reference to a user is accessed.    
VOID
CosignUser::ReferenceUser(VOID)
{
    InterlockedIncrement(&m_refs);
}

// PRE: the internal reference 
// count is at least 1.
// POST: decrements the internal reference count 
// and deletes this if that count goes to 0.
VOID
CosignUser::DereferenceUser(VOID)
{
    if (0 == InterlockedDecrement(&m_refs))
    {
        delete this;
    }
}

// The SupportsIsInRole method returns a BOOL 
// indicating whether this user supports roles.
// return: FALSE.
BOOL
CosignUser::SupportsIsInRole(VOID)
{
    return FALSE;
}

// The IsInRole method returns E_NOTIMPL.
// return: E_NOTIMPL.
HRESULT
CosignUser::IsInRole
(
    IN PCWSTR pszRoleName,
    OUT BOOL* pfInRole
)
{
    return E_NOTIMPL;
}

// The GetUserVariable method returns NULL.
// return: NULL.
PVOID
CosignUser::GetUserVariable
(
    IN PCSTR pszVariableName
)
{
    return NULL;        
}
