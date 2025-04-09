#include "Cloak.hpp"

#ifdef ANTI_VM

#define GB 1073741824

BOOL CALLBACK CheckResolution( HMONITOR hMonitor, HDC hdcMonitor, LPRECT lpRect, LPARAM lParam ) {
    MONITORINFO     mi  = { .cbSize = sizeof( MONITORINFO ) };
    int             x   = 0;
    int             y   = 0;

    if ( ! GetMonitorInfoA( hMonitor, &mi ) ) {
        #ifdef DEBUG
        printf( "[-] GetMonitorInfoA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    x = mi.rcMonitor.right - mi.rcMonitor.left;
    y = mi.rcMonitor.top - mi.rcMonitor.bottom;

    if ( x < 0 ) x = -x;
    if ( y < 0 ) y = -y;

    if ( ( x != 3840 && x != 2560 && x != 1920 && x != 1440 && x != 1366 && x != 1536 && x != 1280 && x != 1600 && x != 1360 ) || ( y != 1080 && y != 768 && y != 900 && y != 864 && y != 720 && y != 1440 && y != 2160 && y != 1024 )) {
        * ( ( BOOL * ) lParam ) = TRUE;
    }

    return TRUE;
}

BOOL IsVm() {
    // check cpu count
    SYSTEM_INFO si = { 0x00 };

    GetSystemInfo(&si);

    if ( si.dwNumberOfProcessors < 2 ) {
        #ifdef DEBUG
        printf( "[*] VM Detected -> CPU COUNT\n" );
        #endif // !DEBUG

        return TRUE;
    }

    // check memory
    // MEMORYSTATUSEX ms = { 0x00 };
    // ms.dwLength = sizeof( MEMORYSTATUSEX );

    // if ( ! GlobalMemoryStatusEx( &ms ) ) {
    //     #ifdef DEBUG
    //     printf( "[-] GlobalMemoryStatusEx Failed with Error -> %d\n", GetLastError() );
    //     #endif // !DEBUG
        
    //     return FALSE;
    // }

    // if ( ( DWORD ) ms.ullTotalPhys < ( DWORD ) ( 2 * GB ) ) {
    //     #ifdef DEBUG
    //     printf( "[*] VM Detected -> MEMORY\n" );
    //     printf( "[*] 2 * GB = %llu\n", ( 2 * GB ) );
    //     printf( "[*] Memory -> %llu bytes\n", ms.ullTotalPhys );
    //     printf( "[*] mem < 2 -> %d\n", ( ms.ullTotalPhys < ( 2 * GB ) ) );
    //     #endif // !DEBUG

    //     return TRUE;
    // }

    BOOL isVm = FALSE;
    EnumDisplayMonitors( NULL, NULL, ( MONITORENUMPROC ) CheckResolution, ( LPARAM ) ( & isVm ) );
    if ( isVm ) {
        #ifdef DEBUG
        printf( "[*] VM Detected -> Resolution\n" );
        #endif // !DEBUG

        return TRUE;
    }

    return FALSE;
}

#endif // !ANTI_VM