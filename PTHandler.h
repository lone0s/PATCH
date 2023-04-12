//
// Created by ohno on 4/7/2023.
//
#include <windows.h>


#pragma once

class PTHandler {
    HANDLE processHandle;
    HANDLE tokenHandle;
    TOKEN_STATISTICS tokenStatistics;
    TOKEN_PRIVILEGES  tokenPrivileges;
    //TODO :
    /*      - Enable SeDebugPrivilege to bypass kernel access checks
     *      - Show if current process has SE_Debug_Priv enabled
     *      - Enumerate all processes with rights
     *      - Get token from user chosen pid (Verify process still running + OpenProcess)
     *      - Duplicate Token (DuplicateTokenEx)
     *      - Create new process with duplicated token(CreateProcessWithToken)
     */

    public:
        BOOL isSeDebugEnabled();
        TOKEN_STATISTICS getProcessInformation(HANDLE processHandle);
        void showTokenInfo(HANDLE processHandle);
        DWORD getTokenPrivNeededBufferSize();
        BOOL enableSeDebugPrivileges();
        void listExistingTokens();
        PTHandler();
};


