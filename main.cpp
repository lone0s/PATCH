#include <iostream>
#include "PTHandler.h"

int main() {
    PTHandler ptHandler;
    ptHandler.showTokenInfo(GetCurrentProcess());
    ptHandler.enableSeDebugPrivileges();
    ptHandler.showTokenInfo(GetCurrentProcess());
    std::cout << std::endl;
    ptHandler.printProcessIdNamePriorityAndElevationType(GetCurrentProcessId());
    ptHandler.printAdminProcessesDep();
    return 0;
}