//
// Created by ohno on 4/7/2023.
//

#include <stdexcept>
#include <iostream>
#include <tchar.h>
#include "PTHandler.h"

PTHandler::PTHandler() {
    /* Possiblement useless (très certainement même) */
    this->processHandle =  GetCurrentProcess();
    HANDLE tokenH;
    if (!OpenProcessToken(this -> processHandle, TOKEN_QUERY, &tokenH)) {
        throw std::runtime_error("[*] - Couldn't open current process token\n");
    }
    this -> tokenHandle = tokenH;
    DWORD tokenStatsSize = sizeof(this -> tokenStatistics);
    if (!GetTokenInformation(tokenH,
                             TokenStatistics,
                             &this -> tokenStatistics,
                             tokenStatsSize,
                             &tokenStatsSize))
    {
        throw std::runtime_error("[*] - Couldn't open current process token stats\n");
    }
}


//Open_Process
TOKEN_STATISTICS PTHandler::getProcessInformation(HANDLE processHandle) {
    HANDLE tokenH;
    if (!OpenProcessToken(processHandle,
                          TOKEN_QUERY,
                          &tokenH))
    {
        throw std::runtime_error("[*] - Couldn't open current process token???\n");
    }
    TOKEN_STATISTICS tokenStatistics;
    DWORD tokenStatsSize = sizeof(tokenStatistics);
    if (!GetTokenInformation(tokenH,
                             TokenStatistics,
                             &tokenStatistics,
                             tokenStatsSize,
                             &tokenStatsSize))
    {
        CloseHandle(tokenH);
        throw std::runtime_error("[*] - Couldn't get current process token statistics\n");
    }
    return tokenStatistics;
}

void PTHandler::showTokenInfo(HANDLE processHandle) {
    std::string impersonationLevels[] {"Anonymous", "Identification", "Impersonation", "Delegation"};
    TOKEN_STATISTICS tStats = getProcessInformation(processHandle);
    std::cout << "[*] [LUID] --> " << tStats.AuthenticationId.HighPart << tStats.AuthenticationId.LowPart << "\n";
    std::cout << "[*] [TYPE] --> " << tStats.TokenType << std::endl;
    std::cout << "[*] [Impersonation Level] --> " << impersonationLevels[tStats.ImpersonationLevel] << std::endl;
/*    LUID privilegeLuid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privilegeLuid)) {
        throw std::runtime_error("[*] - Couldn't get LUID for SeDebugPrivilege\n");
    }
    TOKEN_PRIVILEGES tempTP;
    tempTP.PrivilegeCount = 1;
    tempTP.Privileges[0].Luid = privilegeLuid;
    tempTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL isSeDebugEnabled = TRUE;*/
/*    if (PrivilegeCheck(tokenHandle, &tempTP.Privileges, &isSeDebugEnabled) != 0) {
        CloseHandle(tokenHandle);
        isSeDebugEnabled = FALSE;
    }
    std::cout << "[*] [SE_Debug enabled] -->" <<*/
}

BOOL PTHandler::enableSeDebugPrivileges() {
    BOOL res = TRUE;
    LPCSTR debugPriv = SE_DEBUG_NAME;
    LPCSTR tcbPriv = SE_TCB_NAME;

    LUID debugPrivilegeLuid;
    if (!LookupPrivilegeValue(NULL, debugPriv, &debugPrivilegeLuid)) {
        throw std::runtime_error("[*] - Couldn't get LUID for SeDebugPrivilege\n");
    }

    LUID tcbPrivilegeLuid;
    if (!LookupPrivilegeValue(NULL, tcbPriv, &tcbPrivilegeLuid)) {
        throw std::runtime_error("[*] - Couldn't get LUID for SeTcbPrivilege\n");
    }

    TOKEN_PRIVILEGES tempTP;
    tempTP.PrivilegeCount = 1;
    tempTP.Privileges[0].Luid = debugPrivilegeLuid;
    tempTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;



    if (!AdjustTokenPrivileges(this->tokenHandle, FALSE, &tempTP, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
            std::cout << "/!\\ Error: "<< GetLastError() << " <=> This token doesn't have the specified privilege\n\n";
        }
        else {
            std::cout << "/!\\ Error: "<< GetLastError() << "\n\n";
        }
        std::cout   << "/!\\ Couldn't adjust current process token privileges, maybe it's already enabled..\n";
        return FALSE;
    }
    std::cout << "[*] - Sucessfully added needed priorities..\n";
    return res;
}

BOOL PTHandler::isSeDebugEnabled() {
    DWORD dwLength = getTokenPrivNeededBufferSize();
    TOKEN_PRIVILEGES* tempTP = (TOKEN_PRIVILEGES*) malloc(dwLength);

    LPCTSTR debugPriv = SE_DEBUG_NAME;

    if (!GetTokenInformation(this -> tokenHandle, TokenPrivileges, tempTP, dwLength, &dwLength)) {
        std::cerr << "Error: "  << GetLastError() << std::endl;
        CloseHandle(this -> tokenHandle);
        return FALSE;
    }
    //To determine buffer size


    //May need to verify SID && privilege name to eliminate all false negatives
    TCHAR privName[1024]; //Buffer for name of privilege
    TCHAR sidName[1024];
    SID_NAME_USE sidNameUse;
    for (auto i = 0 ; i < tempTP -> PrivilegeCount ; ++i) {
        DWORD privSize = sizeof(privName) / sizeof(TCHAR);
        DWORD sidSize = sizeof(sidName) / sizeof(TCHAR);
        if (LookupPrivilegeName(nullptr, &tempTP -> Privileges[i].Luid, privName, &privSize)
            && LookupAccountSid(nullptr, &tempTP -> Privileges[i].Attributes, sidName, &sidSize, privName, &privSize, &sidNameUse)
            && (_tcscmp(privName, debugPriv) == 0)
            && tempTP -> Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
        {
                return TRUE;
        }
    }
    std::cerr << "/!\\ - Error: " << GetLastError();
    return FALSE;
}

DWORD PTHandler::getTokenPrivNeededBufferSize() {
    DWORD dwLength = 0;
    if (!GetTokenInformation(this -> tokenHandle, TokenPrivileges, nullptr, 0, &dwLength) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Error: "  << GetLastError() << std::endl;
        CloseHandle(this -> tokenHandle);
        return -1;
    }
    return dwLength;
}

void PTHandler::listExistingTokens() {

}


