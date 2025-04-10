#include "Cloak.hpp"

#ifdef CHECK_DOMAIN_JOINED
#include <lm.h>
#pragma comment(lib, "netapi32.lib")

BOOL CheckDomainJoined() {
    LPWSTR                  szNameBuf       = NULL;
    NET_API_STATUS          nasNetStatus    = 0x00;
    NETSETUP_JOIN_STATUS    BufType         = {  };

    if ( ( nasNetStatus = NetGetJoinInformation( NULL, &szNameBuf, &BufType ) ) != 0x00 ) {
        #ifdef DEBUG
        printf( "[-] NetGetJoinInformation Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
    }

    if ( szNameBuf != NULL ) {
        NetApiBufferFree( szNameBuf );
    }

    return ( ( nasNetStatus == 0x00 ) && ( BufType == NetSetupDomainName ) ) ? TRUE : FALSE;
}
#endif // !CHECK_DOMAIN_JOINED