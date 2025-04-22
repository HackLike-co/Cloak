#include "Cloak.hpp"

#ifdef BASE64
#include <wincrypt.h>
#pragma comment (lib, "Crypt32.lib")

PBYTE DecodeBase64(IN LPCSTR Payload) {
    DWORD finalSize = 0;
    PBYTE pbPayload = NULL;

    // calculate size
    if ( ! CryptStringToBinaryA( Payload, 0, CRYPT_STRING_BASE64, NULL, &finalSize, NULL, NULL ) ) {
        #ifdef DEBUG
        printf( "[-] CryptStringToBinaryA 1 Failed with Error -> %d\n", GetLastError());
        #endif // !DEBUG
        
        return NULL;
    }

    // allocate memory
    pbPayload = ( PBYTE ) VirtualAlloc( 0, finalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( pbPayload == NULL ) {
        #ifdef DEBUG
        printf( "[-] VirtualAlloc Failed with Error -> %d\n", GetLastError());
        #endif // !DEBUG
        
        return NULL;
    }

    // decode
    if ( ! CryptStringToBinaryA( Payload, 0, CRYPT_STRING_BASE64, pbPayload, &finalSize, NULL, NULL ) ) {
        #ifdef DEBUG
        printf( "[-] CryptStringToBinaryA 2 Failed with Error -> %d\n", GetLastError());
        #endif // !DEBUG
        
        return NULL;
    }

    return pbPayload;
}

#endif // !BASE64