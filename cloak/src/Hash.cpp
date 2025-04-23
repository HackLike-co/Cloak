#include "Config.hpp"

#ifdef HASH_API
#include <stdio.h>
#include "Hash.hpp"

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

VOID RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

    if ( SourceString ) {
        LPCWSTR s2;

        for ( s2 = SourceString; *s2; ++s2 );

        SIZE_T DestSize = ( ( int ) ( s2 - SourceString ) ) * sizeof( WCHAR );
        DestinationString->Length = ( USHORT ) DestSize;
        DestinationString->MaximumLength = ( USHORT ) DestSize + sizeof( WCHAR );
    }
    else {
        DestinationString->Length = 0x00;
        DestinationString->MaximumLength = 0x00;
    }

    DestinationString->Buffer = ( PWCHAR ) SourceString;
}

CTIME_HASHA(LdrLoadDll)

LPVOID LdrLoadDll(IN LPWSTR ModuleName) {
    NTSTATUS            STATUS              = 0x00;
    UNICODE_STRING      usDllName           = { 0 };
    LPVOID              pModule             = NULL;
    fnLdrLoadDll        pLdrLoadDll         = NULL;

    if ( ! ( pLdrLoadDll = ( fnLdrLoadDll ) GetProcAddressH( GetModuleHandleA( "NTDLL" ) , LdrLoadDll_CRC32A ) ) ) {
        #ifdef DEBUG
		printf( "[-] GetProcAddressH Failed With Error: %d \n", GetLastError() );
		#endif // !DEBUG

        return NULL;
    }

    RtlInitUnicodeString( &usDllName, ModuleName );

    if ( ( STATUS = pLdrLoadDll( NULL, NULL, &usDllName, &pModule ) ) != 0x00 ) {
		#ifdef DEBUG
        printf( "[-] LdrLoadDll Failed With Error: 0x%0.8X \n", STATUS );
		#endif // !DEBUG

        return NULL;
    }

    return pModule;
}

#endif // !HASH_API