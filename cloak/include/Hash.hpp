#pragma once

#ifndef HASH_H
#define HASH_H

#include "Config.hpp"

#if defined HASH_API

#include <windows.h>

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

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);

#endif // !HASH_API

#endif // !HASH_H