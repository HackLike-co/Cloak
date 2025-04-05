#include "Cloak.hpp"

#ifdef ANTI_DEBUG

#ifdef HASH_API
namespace antiDebug {
    constexpr int RandomCompileTimeSeed(void)
    {
        return '0' * -23784 +
            __TIME__[7] * 345 +
            __TIME__[6] * 12 +
            __TIME__[4] * 2345123 +
            __TIME__[3] * 623 +
            __TIME__[1] * 95897 +
            __TIME__[0] * 2;
    };
    
    constexpr auto g_KEY = RandomCompileTimeSeed() % RAND;
    
    constexpr DWORD HashStringCrc32(const char* String) {
        UINT32      uMask	= 0x00;
        UINT32      uHash	= g_KEY;
        INT         i		= 0x00;
    
        while ( String[i] != 0 ) {
            uHash = uHash ^ ( UINT32 ) String[i];
    
            for ( int ii = 0; ii < 8; ii++ ) {
                uMask = -1 * ( uHash & 1 );
                uHash = ( uHash >> 1 ) ^ ( 0xEDB88320 & uMask );
            }
    
            i++;
        }
    
        return ~uHash;
    }
    
    #define RTIME_HASHA( API ) antiDebug::HashStringCrc32( ( const char* ) API )
    #define CTIME_HASHA( API ) constexpr auto API##_CRC32A = antiDebug::HashStringCrc32( ( const char* ) #API );
    
    FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {
        PBYTE pBase = ( PBYTE ) hModule;
    
        PIMAGE_DOS_HEADER   pImgDosHeader  = ( PIMAGE_DOS_HEADER ) pBase;
        if ( pImgDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
            return NULL;
        }
    
        PIMAGE_NT_HEADERS   pImgNtHeaders  = ( PIMAGE_NT_HEADERS ) ( pBase + pImgDosHeader->e_lfanew );
        if ( pImgNtHeaders->Signature != IMAGE_NT_SIGNATURE ) {
            return NULL;
        }
    
        IMAGE_OPTIONAL_HEADER		ImgOptionalHeader		= pImgNtHeaders->OptionalHeader;
        PIMAGE_EXPORT_DIRECTORY		pImgExportDirectory     = ( PIMAGE_EXPORT_DIRECTORY ) ( pBase + ImgOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
        PDWORD						pdwFunctionNameArray	= ( PDWORD ) ( pBase + pImgExportDirectory->AddressOfNames );
        PDWORD						pdwFunctionAddressArray	= ( PDWORD ) ( pBase + pImgExportDirectory->AddressOfFunctions );
        PWORD						pwFunctionOrdinalArray	= ( PWORD ) ( pBase + pImgExportDirectory->AddressOfNameOrdinals );
    
        for ( DWORD i = 0; i < pImgExportDirectory->NumberOfFunctions; i++ ) {
            CHAR*	pFunctionName		= ( CHAR* ) ( pBase + pdwFunctionNameArray[i] );
            PVOID	pFunctionAddr   	= ( PVOID ) ( pBase + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]] );
    
            if ( dwApiNameHash == RTIME_HASHA( pFunctionName ) ) { 
                return ( FARPROC ) pFunctionAddr;
            }
        }
    
        return NULL;
    }
}

// ---

typedef HANDLE ( WINAPI * fnGetProcessHeap ) ();

typedef BOOL ( WINAPI * fnCloseHandle ) (
    HANDLE  hObject
);

CTIME_HASHA(GetProcessHeap)
CTIME_HASHA(CloseHandle)

BOOL IsDebuggerPresent() {
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnGetProcessHeap pGetProcessHeap = ( fnGetProcessHeap ) antiDebug::GetProcAddressH( hKernel32, GetProcessHeap_CRC32A );
    if ( pGetProcessHeap == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for GetProcessHeap\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnCloseHandle pCloseHandle = ( fnCloseHandle ) antiDebug::GetProcAddressH( hKernel32, CloseHandle_CRC32A );
    if ( pCloseHandle == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pCloseHandle\n" );
        #endif // !DEBUG
        
        return;
    }

    // ---

    DWORD t1 = { 0 };
    DWORD t2 = { 0 };
    DWORD t3 = { 0 };

    for ( int i = 0; i < 10; i++ ) {
        t1 = ( DWORD ) __rdtsc();
        pGetProcessHeap();
        t2 = ( DWORD ) __rdtsc();
        pCloseHandle( NULL );
        t3 = ( DWORD ) __rdtsc();

        if ( ( t3 - t2 ) / ( t2 - t1 ) >= 10 ) {
            return FALSE;
        }
    }

    return TRUE;
}

#else

BOOL IsDebuggerPresent() {
    DWORD t1 = { 0 };
    DWORD t2 = { 0 };
    DWORD t3 = { 0 };

    for ( int i = 0; i < 10; i++ ) {
        t1 = ( DWORD ) __rdtsc();
        GetProcessHeap();
        t2 = ( DWORD ) __rdtsc();
        CloseHandle( NULL );
        t3 = ( DWORD ) __rdtsc();

        if ( ( t3 - t2 ) / ( t2 - t1 ) >= 10 ) {
            return FALSE;
        }
    }

    return TRUE;
}

#endif // !HASH_API

#endif // !ANTI_DEBUG