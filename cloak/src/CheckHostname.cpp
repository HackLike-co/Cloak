#include "Cloak.hpp"

#ifdef CHECK_HOSTNAME
BOOL CheckHostname(IN LPSTR pwGuardHost) {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD sHostnameSize = MAX_COMPUTERNAME_LENGTH + 1;

    if ( ! GetComputerNameExA( ComputerNameNetBIOS, hostname, &sHostnameSize ) ) {
        if ( GetLastError() == ERROR_SUCCESS ) {
            return TRUE;
        }
        #ifdef DEBUG
        printf( "[-] GetComputerNameA Failed with Error -> %d\n", GetLastError() );
        #endif // !DEBUG
        
        return FALSE;
    }

    if ( strcmp( hostname, pwGuardHost ) == 0 ) {
        return TRUE;
    } else {
        return FALSE;
    }
}
#endif // !CHECK_HOSTNAME