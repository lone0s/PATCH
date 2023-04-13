//
// Created by ohno on 4/7/2023.
//

#include <stdexcept>
#include <iostream>
#include <tchar.h>
#include "PTHandler.h"

PTHandler::PTHandler() {
//    Possiblement useless
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
            && tempTP -> Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
            free(tempTP);
            return true;
        }
    }
    free(tempTP);
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

/*void PTHandler::listExistingTokens() {
    //Listing all system handles
}*/
PTHandler::~PTHandler() {
    CloseHandle(processHandle);
    CloseHandle(tokenHandle);
    std::cout << "Cya later cowboy ;)\n";
}

/**
 * @brief PTHandler::printAdminProcessesDep
 * @details Prints all processes with admin privileges
 * @attention DEPRECATED (Non admin processes cannot be enumerated)
 */
void PTHandler::printAdminProcessesDep() {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        std::cout << "[*] - Couldn't enumerate processes, error: " << GetLastError() << std::endl;
    }
    cProcesses = cbNeeded / sizeof(DWORD);
    std::cout << "[*] - Number of processes: " << cProcesses << std::endl;
    std::cout << "[*] - Process ID | Process Name | Process Priority | Elevation Type" << std::endl;
    for(size_t i = 0 ; i < cProcesses ; ++i) {
        if (aProcesses[i] != 0) {
            HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE, aProcesses[i]);
            if (processHandle) {
//                if (isProcessAdmin(processHandle)) {
                printProcessIdNamePriorityAndElevationType(aProcesses[i]);
//                }
                CloseHandle(processHandle);
            }
        }
    }
}

void PTHandler::printProcessIdNamePriorityAndElevationType(DWORD processID) {
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE, processID);
    if (processHandle) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(processHandle, &hMod, sizeof(HMODULE), &cbNeeded) == 0) {
            std::cout << "[*] - Couldn't enumerate process modules for pid: " << processID << ", error: " << GetLastError() << std::endl;
            CloseHandle(processHandle);
            return;
        }
        char processName[1024];
        if (GetModuleBaseName(processHandle, hMod, processName, sizeof(processName)/sizeof(char)) == 0) {
            std::cout << "[*] - Couldn't get process name, error: " << GetLastError() << std::endl;
            CloseHandle(processHandle);
            return;
        }
        std::cout << "[*] - " << processID << " | ";
        std::cout << processName << " | ";
        std::cout << priorityClassToString(GetPriorityClass(processHandle)) << " | ";
        HANDLE hToken;
        if (OpenProcessToken(processHandle, TOKEN_QUERY, &hToken) == 0) {
            std::cout << "[*] - Couldn't open process token, error: " << GetLastError() << std::endl;
            CloseHandle(processHandle);
            return;
        }
        TOKEN_ELEVATION_TYPE elevationType;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevationType, &elevationType, sizeof(elevationType), &dwSize) == 0) {
            std::cout << "[*] - Couldn't get token elevation type, error: " << GetLastError() << std::endl;
            CloseHandle(processHandle);
            return;
        }
        std::cout << elevationTypeToString(elevationType) << std::endl;
        CloseHandle(hToken);
        CloseHandle(processHandle);
    }
}

std::string PTHandler::priorityClassToString(DWORD priorityClass) {
    switch (priorityClass) {
        case IDLE_PRIORITY_CLASS:
            return "IDLE_PRIORITY";
        case BELOW_NORMAL_PRIORITY_CLASS:
            return "BELOW_NORMAL_PRIORITY";
        case NORMAL_PRIORITY_CLASS:
            return "NORMAL_PRIORITY";
        case ABOVE_NORMAL_PRIORITY_CLASS:
            return "ABOVE_NORMAL_PRIORITY";
        case HIGH_PRIORITY_CLASS:
            return "HIGH_PRIORITY";
        case REALTIME_PRIORITY_CLASS:
            return "REALTIME_PRIORITY";
        default:
            return "UNKNOWN_PRIORITY";
    }
}

std::string PTHandler::elevationTypeToString(TOKEN_ELEVATION_TYPE elevationType) {
    switch (elevationType) {
        case TokenElevationTypeDefault :
            return "DEFAULT";
        case TokenElevationTypeFull :
            return "FULL";
        case TokenElevationTypeLimited :
            return "LIMITED";
        default:
            return "UNKNOWN";
    }
}

BOOL PTHandler::isProcessAdmin(HANDLE pHandle) {
    HANDLE hToken;
    if (!OpenProcessToken(pHandle, TOKEN_QUERY, &hToken)) {
        std::cerr << "Error: "  << GetLastError() << std::endl;
        CloseHandle(pHandle);
        return false;
    }
    TOKEN_ELEVATION_TYPE elevationType;
    DWORD dwSize;
    if (!GetTokenInformation(hToken, TokenElevationType, &elevationType, sizeof(elevationType), &dwSize)) {
        std::cout << "Couldn't get process's token info , error: " << GetLastError() << std::endl;
        return false;
    }
    return elevationType == TokenElevationTypeDefault;
}






