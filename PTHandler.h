//
// Created by ohno on 4/7/2023.
//
#include <windows.h>
#include <Psapi.h>


#pragma once

class PTHandler {
    //TODO :
    /*      - Enable SeDebugPrivilege to bypass kernel access checks <-- OK
     *      - Show if current process has SE_Debug_Priv enabled <-- OK
     *      - Enumerate all processes with rights <-- OK (Admin processes not listed)
     *      //UPDATE : Might need to go through snapshots
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
    void printProcessIdNamePriorityAndElevationType(DWORD processID);
    std::string priorityClassToString(DWORD priorityClass);
    std::string elevationTypeToString(TOKEN_ELEVATION_TYPE elevationType);
    //    void listExistingTokens();
    void printAdminProcessesDep();

    BOOL isProcessAdmin(HANDLE pHandle);
};


