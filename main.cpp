#include <iostream>
#include "PTHandler.h"

int main() {
    PTHandler pth;
    pth.showTokenInfo(GetCurrentProcess());
    std::cout << "needed size: " << pth.getTokenPrivNeededBufferSize() << std::endl ;
    pth.isSeDebugEnabled() ? std::cout << "SE_DEBUG Enabled" : std::cout << "SE_DEBUG Disabled";
    std::cout << std::endl;
    pth.enableSeDebugPrivileges();
}
