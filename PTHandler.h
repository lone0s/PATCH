//
// Created by ohno on 4/7/2023.
//
#include <windows.h>
#pragma comment(lib, "advapi32.lib")

#pragma once

class PTHandler {
    //TODO :
    /*      - Enable SeDebugPrivilege to bypass kernel access checks <-- OK
     *      - Show if current process has SE_Debug_Priv enabled
     *      - Enumerate all processes with rights
     *      - Get token from user chosen pid (Verify process still running + OpenProcess)
     *      - Duplicate Token (DuplicateTokenEx)
     *      - Create new process with duplicated token(CreateProcessWithToken)
     */

public:
    HANDLE processHandle;
    HANDLE tokenHandle;
    TOKEN_STATISTICS tokenStatistics;
    TOKEN_PRIVILEGES tokenPrivileges;

    PTHandler();
    ~PTHandler();
    BOOL isSeDebugEnabled();
    TOKEN_STATISTICS getProcessInformation(HANDLE pHandle);
    void showTokenInfo(HANDLE pHandle);
    DWORD getTokenPrivNeededBufferSize();
    BOOL enableSeDebugPrivileges() const;

//    void listExistingTokens();
};


