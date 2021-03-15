#ifndef _SERVER_ENCLAVE_H
#define _SERVER_ENCLAVE_H

#include "enclave.h"
#include "enclave_args.h"

struct server_enclave_t
{
    char server_name[NAME_LEN];
    struct enclave_t* entity;
};

#define SERVERS_PER_METADATA_REGION 100

uintptr_t create_server_enclave(struct enclave_sbi_param_t create_args);
uintptr_t destroy_server_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t acquire_server_enclave(uintptr_t *regs, char *server_name);

#endif /* _SERVER_ENCLAVE_H */
