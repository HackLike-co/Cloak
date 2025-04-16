#include "Config.hpp"

#ifdef HASH_API
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

#endif // !HASH_API