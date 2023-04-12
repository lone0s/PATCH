#include <iostream>
#include "PTHandler.h"

/*bool EnablePrivilege(HANDLE hToken, LPCTSTR szPrivilege, bool bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, szPrivilege, &luid))
    {
        std::cout << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        std::cout << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        return false;
    }

    return true;
}*/


/*int main() {
*//*    PTHandler pth;
    pth.showTokenInfo(GetCurrentProcess());
    std::cout << "needed size: " << pth.getTokenPrivNeededBufferSize() << std::endl ;
    pth.isSeDebugEnabled() ? std::cout << "SE_DEBUG Enabled" : std::cout << "SE_DEBUG Disabled";
    std::cout << std::endl;
    pth.enableSeDebugPrivileges();*//*

    LPCTSTR szPrivilege = SE_DEBUG_NAME; // Change this to the desired privilege
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::cout << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return 1;
    }

    if (!EnablePrivilege(hToken, szPrivilege, true))
    {
        CloseHandle(hToken);
        return 1;
    }

    std::cout << "Privilege enabled successfully" << std::endl;

    CloseHandle(hToken);
    return 0;
}*/

int main() {
    PTHandler ptHandler;
    ptHandler.showTokenInfo(GetCurrentProcess());
    ptHandler.enableSeDebugPrivileges();
    ptHandler.showTokenInfo(GetCurrentProcess());
}