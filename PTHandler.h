//
// Created by ohno on 4/7/2023.
//
#include <windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>

#pragma once

class PTHandler {
    //TODO :
     /*      UPDATE : Might need to go through snapshots <-- Still doesn't work lol
     *       UPDATE : Might need to go through powershell <-- OK
     *       UPDATE : Need to load in memory all Process IDs, then iterate through them to find ones to steal
     */

public:
    HANDLE processHandle;
    HANDLE tokenHandle;
    TOKEN_STATISTICS tokenStatistics;
    TOKEN_PRIVILEGES tokenPrivileges;
    std::vector<DWORD> adminProcessIDs;

    PTHandler();
    ~PTHandler();

    BOOL isSeDebugEnabled();
    TOKEN_STATISTICS getProcessInformation(HANDLE pHandle);
    void showTokenInfo(HANDLE pHandle);
    DWORD getTokenPrivNeededBufferSize();
    BOOL enableSeDebugPrivileges() const;
    void printProcessIdNamePriorityAndElevationType(DWORD processID);
    //    void listExistingTokens();
    void printAdminProcessesDep();
    void printAdminProcesses();
    std::string priorityClassToString(DWORD priorityClass);
    std::string elevationTypeToString(TOKEN_ELEVATION_TYPE elevationType);
    BOOL isProcessAdmin(HANDLE hProcess);

    HANDLE stealTokenFromProcess(DWORD processID);
    void createProcessWithToken(HANDLE stolenToken, const std::string& processPath = R"(C:\Windows\System32\cmd.exe)");

    void fetchAdminTokensThroughPowershell(const std::string& outputPath);
    void loadAdminTokensFromPowershellOutput(const std::string& inputPath);
};


