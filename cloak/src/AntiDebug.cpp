#include "Cloak.hpp"

#ifdef ANTI_DEBUG

// https://github.com/vxunderground/VX-API/blob/main/VX-API/GetPeb.cpp
PPEB GetPeb() {
    #if defined(_WIN64)
	    return (PPEB)__readgsqword(0x60);
    #elif define(_WIN32)
        return (PPEB)__readfsdword(0x30);
    #endif
}

// https://github.com/vxunderground/VX-API/blob/main/VX-API/IsDebuggerPresentEx.cpp
BOOL IsDebugger() {
    return GetPeb()->BeingDebugged;
}

#endif // !ANTI_DEBUG