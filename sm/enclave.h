#ifndef _ENCLAVE_H
#define _ENCLAVE_H

#include <string.h>
#include "bits.h"
#include "vm.h"
#include "encoding.h"
#include "enclave_args.h"
#include "atomic.h" 
#include "mtrap.h"
#include "thread.h"
#include <stdint.h>
#include <stddef.h>

#define ENCLAVES_PER_METADATA_REGION 256
#define ENCLAVE_METADATA_REGION_SIZE ((sizeof(struct enclave_t)) * ENCLAVES_PER_METADATA_REGION)

struct link_mem_t
{
  unsigned long mem_size;
  unsigned long slab_size;
  unsigned long slab_num;
  char* addr;
  struct link_mem_t* next_link_mem;    
};

typedef enum 
{
  DESTROYED = -1,
  INVALID = 0,
  FRESH = 1,
  RUNNABLE,
  RUNNING,
  STOPPED, 
  ATTESTING,
  OCALLING
} enclave_state_t;

struct vm_area_struct
{
  unsigned long va_start;
  unsigned long va_end;

  struct vm_area_struct *vm_next;
  struct pm_area_struct *pma;
};

struct pm_area_struct
{
  unsigned long paddr;
  unsigned long size;
  unsigned long free_mem;

  struct pm_area_struct *pm_next;
};

struct page_t
{
  uintptr_t paddr;
  struct page_t *next;
};

/*
 * enclave memory [paddr, paddr + size]
 * free_mem @ unused memory address in enclave mem
 */
struct enclave_t
{
  unsigned int eid;
  enclave_type_t type;
  enclave_state_t state;

  ///vm_area_struct lists
  struct vm_area_struct* text_vma;
  struct vm_area_struct* stack_vma;
  uintptr_t _stack_top; ///lowest address of stack area
  struct vm_area_struct* heap_vma;
  uintptr_t _heap_top;  ///highest address of heap area
  struct vm_area_struct* mmap_vma;

  ///pm_area_struct list
  struct pm_area_struct* pma_list;
  struct page_t* free_pages;
  uintptr_t free_pages_num;

  //memory region of enclave
  unsigned long paddr;
  unsigned long size;

  //address of left available memory in memory region
  unsigned long free_mem;

  //TODO: dynamically allocated memory
  unsigned long* enclave_mem_metadata_page;

  //root page table of enclave
  unsigned long* root_page_table;

  //root page table register for host
  unsigned long host_ptbr;

  //entry point of enclave
  unsigned long entry_point;

  ///shared mem with kernel
  unsigned long kbuffer;//paddr
  unsigned long kbuffer_size;

  ///shared mem with host
  unsigned long shm_paddr;
  unsigned long shm_size;

  ///host memory arg
  unsigned long mm_arg_paddr;
  unsigned long mm_arg_size;

  unsigned long* ocall_func_id;
  unsigned long* ocall_arg0;
  unsigned long* ocall_arg1;
  unsigned long* ocall_syscall_num;

  //shared memory with host
  unsigned long untrusted_ptr;
  unsigned long untrusted_size;

  //enclave thread context
  //TODO: support multiple threads
  struct thread_state_t thread_context;
  unsigned int top_caller_eid;
  unsigned int caller_eid;
  unsigned int cur_callee_eid;
  unsigned char hash[HASH_SIZE];
};

struct cpu_state_t
{
  int in_enclave;
  int eid;
};

void acquire_enclave_metadata_lock();
void release_enclave_metadata_lock();

int get_curr_enclave_id();
struct enclave_t* get_enclave(int eid);

uintptr_t copy_from_host(void* dest, void* src, size_t size);
uintptr_t copy_to_host(void* dest, void* src, size_t size);
int copy_word_to_host(unsigned int* ptr, uintptr_t value);

struct link_mem_t* init_mem_link(unsigned long mem_size, unsigned long slab_size);
struct link_mem_t* add_link_mem(struct link_mem_t** tail);

struct enclave_t* alloc_enclave();
int free_enclave(int eid);

uintptr_t create_enclave(struct enclave_sbi_param_t create_args);
uintptr_t run_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t stop_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t resume_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t resume_from_stop(uintptr_t* regs, unsigned int eid);
uintptr_t exit_enclave(uintptr_t* regs, unsigned long retval);
uintptr_t do_timer_irq(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc);

struct call_enclave_arg_t
{
    uintptr_t req_arg;
    uintptr_t req_vaddr;
    uintptr_t req_size;
    uintptr_t resp_val;
    uintptr_t resp_vaddr;
    uintptr_t resp_size;
};

uintptr_t call_enclave(uintptr_t *regs, unsigned int enclave_id, uintptr_t arg);
uintptr_t enclave_return(uintptr_t *regs, uintptr_t arg);

#endif /* _ENCLAVE_H */
