#include "sm.h"
#include "enclave.h"
#include "server_enclave.h"
#include "ipi.h"
#include TARGET_PLATFORM_HEADER

/**************************************************************/
/*                   called by enclave                        */
/**************************************************************/
uintptr_t acquire_server_enclave(uintptr_t *regs, char* server_name_u)
{
    uintptr_t ret = 0;
    printm("M MODE: acquire encalve success\r\n");
    return ret;
}
