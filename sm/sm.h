#ifndef _SM_H
#define _SM_H

#ifndef TARGET_PLATFORM_HEADER
#error "SM requires to specify a certain platform"
#endif 

#include TARGET_PLATFORM_HEADER
#include <stdint.h>
#include "enclave_args.h"
#include "ipi.h"

#define SM_BASE 0x80000000
#define SM_SIZE 0x200000

//SBI_CALL NUMBERS
#define SBI_MM_INIT            100
#define SBI_CREATE_ENCLAVE      99
#define SBI_ATTEST_ENCLAVE      98
#define SBI_RUN_ENCLAVE         97
#define SBI_STOP_ENCLAVE        96
#define SBI_RESUME_ENCLAVE      95
#define SBI_DESTROY_ENCLAVE     94
#define SBI_ALLOC_ENCLAVE_MM    93
#define SBI_MEMORY_EXTEND       92
#define SBI_MEMORY_RECLAIM      91
#define SBI_ENCLAVE_OCALL       90
#define SBI_EXIT_ENCLAVE        89
#define SBI_DEBUG_PRINT         88
#define SBI_ACQUIRE_SERVER      87
#define SBI_CALL_ENCLAVE        86
#define SBI_ENCLAVE_RETURN      85
#define SBI_CREATE_SERVER_ENCLAVE         84
#define SBI_DESTROY_SERVER_ENCLAVE        83

//Error code of SBI_ALLOC_ENCLAVE_MEM
#define ENCLAVE_NO_MEMORY       -2
#define ENCLAVE_ERROR           -1
#define ENCLAVE_SUCCESS          0
#define ENCLAVE_TIMER_IRQ        1

//error code of SBI_RESUME_RNCLAVE
#define RESUME_FROM_TIMER_IRQ    2000
#define RESUME_FROM_STOP         2003

typedef int page_meta;
#define NORMAL_PAGE                      ((page_meta)0x7FFFFFFF)
#define ZERO_MAP_PAGE                    ((page_meta)0x7FFFFFFE)
#define PRIVATE_PAGE                     ((page_meta)0x80000000)
#define IS_PRIVATE_PAGE(meta)            (((page_meta)meta) & PRIVATE_PAGE)
#define IS_PUBLIC_PAGE(meta)             (!IS_PRIVATE_PAGE(meta))
#define IS_ZERO_MAP_PAGE(meta)           (((page_meta)meta & NORMAL_PAGE) == ZERO_MAP_PAGE)
#define IS_SCHRODINGER_PAGE(meta)        (((page_meta)meta & NORMAL_PAGE) != NORMAL_PAGE)
#define MAKE_PRIVATE_PAGE(meta)          ((page_meta)meta | PRIVATE_PAGE)
#define MAKE_PUBLIC_PAGE(meta)           ((page_meta)meta & NORMAL_PAGE)
#define MAKE_ZERO_MAP_PAGE(meta)         (((page_meta)meta & PRIVATE_PAGE) | ZERO_MAP_PAGE)
#define MAKE_SCHRODINGER_PAGE(pri, pos)  (pri ? \
    (PRIVATE_PAGE | ((page_meta)pos & NORMAL_PAGE)) \
    : ((page_meta)pos & NORMAL_PAGE))
#define SCHRODINGER_PTE_POS(meta)        (IS_ZERO_MAP_PAGE(meta) ? -1 : ((int)meta & (int)0x7FFFFFFF))

void sm_init();

int enable_enclave();
int test_public_range(uintptr_t pfn, uintptr_t pagenum);

uintptr_t sm_mm_init(uintptr_t paddr, unsigned long size);

uintptr_t sm_mm_extend(uintptr_t paddr, unsigned long size);

uintptr_t sm_alloc_enclave_mem(uintptr_t mm_alloc_arg);

uintptr_t sm_create_enclave(uintptr_t enclave_create_args);

uintptr_t sm_attest_enclave(uintptr_t enclave_id, uintptr_t report, uintptr_t nonce);

uintptr_t sm_run_enclave(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_debug_print(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_stop_enclave(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_resume_enclave(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_destroy_enclave(uintptr_t *regs, uintptr_t enclave_id, uintptr_t destroy_flag);

uintptr_t sm_enclave_ocall(uintptr_t *regs, uintptr_t ocall_func_id, uintptr_t arg);

uintptr_t sm_exit_enclave(uintptr_t *regs, unsigned long retval);

uintptr_t sm_do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc);

int check_in_enclave_world();

uintptr_t sm_server_enclave_acquire(uintptr_t *regs, uintptr_t server_name);

uintptr_t sm_call_enclave(uintptr_t *regs, uintptr_t enclave_id, uintptr_t arg);

uintptr_t sm_enclave_return(uintptr_t *regs, uintptr_t arg);

uintptr_t sm_create_server_enclave(uintptr_t enclave_create_args);

uintptr_t sm_destroy_server_enclave(uintptr_t *regs, uintptr_t enclave_id);

#endif /* _SM_H */
