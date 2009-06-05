
#include <windows.h>

class CosignUser : public IHttpUser {
public:
	virtual PCWSTR GetRemoteUserName(VOID);
	virtual PCWSTR GetUserName(VOID);
	virtual PCWSTR GetAuthenticationType(VOID);
	virtual PCWSTR GetPassword(VOID);
	virtual HANDLE GetImpersonationToken(VOID);
	virtual HANDLE GetPrimaryToken(VOID);
	virtual VOID ReferenceUser(VOID);
	virtual VOID DereferenceUser(VOID);
	virtual BOOL SupportsIsInRole(VOID);
	virtual HRESULT IsInRole(
        IN  PCWSTR  pszRoleName,
        OUT BOOL *  pfInRole
    );
	virtual PVOID GetUserVariable(
        IN PCSTR    pszVariableName
    );

	CosignUser(PCWSTR currentUserName);

private:
    LONG m_refs;
	PCWSTR userName;

	~CosignUser();
};