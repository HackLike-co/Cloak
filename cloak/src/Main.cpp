#include "Cloak.hpp"

#ifdef DLL

DLLEXPORT VOID Start() {
    CloakMain( NULL );
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    if ( dwReason == DLL_PROCESS_ATTACH ) {
        CloakMain( NULL );
    }
}

#else

int main() {
    return CloakMain( NULL );
}

#endif // !DLL