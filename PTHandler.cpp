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
    if (!OpenProcessToken(this -> processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenH)) {
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
TOKEN_STATISTICS PTHandler::getProcessInformation(HANDLE pHandle) {
    HANDLE tokenH;
    if (!OpenProcessToken(pHandle,
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

void PTHandler::showTokenInfo(HANDLE pHandle) {
    std::string impersonationLevels[] {"Anonymous", "Identification", "Impersonation", "Delegation"};
    TOKEN_STATISTICS tStats = getProcessInformation(processHandle);
    std::cout << "[*] [LUID] --> " << tStats.AuthenticationId.HighPart << tStats.AuthenticationId.LowPart << "\n";
    std::cout << "[*] [TYPE] --> " << tStats.TokenType << std::endl;
    std::cout << "[*] [Impersonation Level] --> " << impersonationLevels[tStats.ImpersonationLevel] << std::endl;
    std::cout << (isSeDebugEnabled() ? "[*] - Se_Debug Enabled :-)\n" : "[*] - Se_Debug Disabled ://\n");
}

BOOL PTHandler::enableSeDebugPrivileges() const {
    LPCTSTR seDebugPriv = SE_DEBUG_NAME;
    LUID debugPrivilegeLuid;

    if (!LookupPrivilegeValue(NULL, seDebugPriv, &debugPrivilegeLuid)) {
        std::cout << "[*] - Couldn't get LUID for SeDebugPrivilege, error : "<< GetLastError() <<"\n";
        return false;
    }

    TOKEN_PRIVILEGES tempTP;
    tempTP.PrivilegeCount = 1;
    tempTP.Privileges[0].Luid = debugPrivilegeLuid;
    tempTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(this -> tokenHandle, FALSE, &tempTP, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cout << "[*] - Couldn't adjust token privilege, error : "<< GetLastError() <<"\n";
        return false;
    }
    std::cout << "[*] - Sucessfully added needed privilege :)..\n";
    return true;
}

BOOL PTHandler::isSeDebugEnabled() {
    DWORD dwLength = getTokenPrivNeededBufferSize();
    TOKEN_PRIVILEGES* tempTP = (TOKEN_PRIVILEGES*) malloc(dwLength);
    LPCTSTR debugPriv = SE_DEBUG_NAME;
    if (!GetTokenInformation(this -> tokenHandle, TokenPrivileges, tempTP, dwLength, &dwLength)) {
        std::cerr << "Error: "  << GetLastError() << std::endl;
        CloseHandle(this -> tokenHandle);
        return false;
    }
    TCHAR privName[1024]; //Buffer for name of privilege
    for (auto i = 0 ; i < tempTP -> PrivilegeCount ; ++i) {
        DWORD privSize = sizeof(privName) / sizeof(TCHAR);
        if (LookupPrivilegeName(nullptr, &tempTP -> Privileges[i].Luid, privName, &privSize)
            && (_tcscmp(privName, debugPriv) == 0)
            && tempTP -> Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                return true;
    }
    return false;
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
    //Listing all system handles
}

PTHandler::~PTHandler() {
    CloseHandle(processHandle);
    CloseHandle(tokenHandle);
    std::cout << "Cya later cowboy ;)\n";
}


