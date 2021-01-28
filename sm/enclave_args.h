#ifndef _ENCLAVE_ARGS_H
#define _ENCLAVE_ARGS_H
#include "thread.h"
#define HASH_SIZE              32
#define PRIVATE_KEY_SIZE       32
#define PUBLIC_KEY_SIZE        64
#define SIGNATURE_SIZE         64
#define NAME_LEN                16

#define MANU_PUB_KEY           (void*)((unsigned long)0x801ff000)
#define DEV_PUB_KEY            (MANU_PUB_KEY + PUBLIC_KEY_SIZE)
#define DEV_PRI_KEY            (DEV_PUB_KEY + PUBLIC_KEY_SIZE)
#define SM_PUB_KEY             (DEV_PRI_KEY + PRIVATE_KEY_SIZE)
#define SM_PRI_KEY             (SM_PUB_KEY + PUBLIC_KEY_SIZE)
#define SM_HASH                (SM_PRI_KEY + PRIVATE_KEY_SIZE)
#define SM_SIGNATURE           (SM_HASH + HASH_SIZE)

struct mm_alloc_arg_t
{
  unsigned long req_size;
  uintptr_t resp_addr;
  unsigned long resp_size;
};

typedef enum
{
  NORMAL_ENCLAVE = 0,
  SERVER_ENCLAVE = 1
} enclave_type_t;

/*
 * enclave memory [paddr, paddr + size]
 * free_mem @ unused memory address in enclave mem
 */
struct enclave_sbi_param_t
{
  unsigned int *eid_ptr;
  char name[NAME_LEN];
  enclave_type_t type;

  unsigned long paddr;
  unsigned long size;
  unsigned long entry_point;
  unsigned long untrusted_ptr;
  unsigned long untrusted_size;
  unsigned long free_mem;

  //enclave shared mem with kernel
  unsigned long kbuffer;//paddr
  unsigned long kbuffer_size;

  //enclave shared mem with host
  unsigned long shm_paddr;
  unsigned long shm_size;

  unsigned long *ecall_arg0;
  unsigned long *ecall_arg1;
  unsigned long *ecall_arg2;
  unsigned long *ecall_arg3;
};

#define NAME_LEN  16

#endif /* _ENCLAVE_ARGS_H */
