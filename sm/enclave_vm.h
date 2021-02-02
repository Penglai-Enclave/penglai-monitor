#ifndef _ENCLAVE_VM_H
#define _ENCLAVE_VM_H

#include "enclave.h"
#include "encoding.h"
#include "vm.h"

//default layout of enclave
//#####################
//#   reserved for    #
//#       s mode      #
//##################### 0xffffffe000000000 //actually this is the start address of kernel's image
//#       hole        #
//##################### 0x0000004000000000
//#                   #
//#       stack       #
//#                   #
//##################### 0x0000003000000000
//#                   #
//#       mmap        #
//#                   #
//#                   #
//#       heap        #
//#                   #
//##################### 0x0000002000000000
//#  untrusted memory #
//#  shared with host #
//##################### 0x0000001000000000
//#     code & data   #
//##################### 0x0000000000001000
//#       hole        #
//##################### 0x0

#define ENCLAVE_DEFAULT_KBUFFER_SIZE              0x1000UL
#define ENCLAVE_DEFAULT_KBUFFER         0xffffffe000000000UL
#define ENCLAVE_DEFAULT_STACK_BASE      0x0000004000000000UL
#define ENCLAVE_DEFAULT_MMAP_BASE       0x0000003000000000UL
#define ENCLAVE_DEFAULT_HEAP_BASE       0x0000002000000000UL
#define ENCLAVE_DEFAULT_TEXT_BASE       0x0000000000001000UL

#define ENCLAVE_DEFAULT_STACK 0x0000004000000000;
//#define ENCLAVE_DEFAULT_STACK_SIZE 1024*1024

#define PTE_VALID(pte) (pte & PTE_V)
#define PTE_ILLEGAL(pte) ((pte & PTE_V) && (pte & PTE_W) && !(pte & PTE_R))
#define PTE_TO_PFN(pte) (pte >> PTE_PPN_SHIFT)
#define IS_LEAF_PTE(pte) ((pte & PTE_V) && (pte & PTE_R || pte & PTE_X))
#define RISCV_PGLEVELS ((VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS)

void traverse_vmas(uintptr_t root_page_table, struct vm_area_struct *vma);
int insert_vma(struct vm_area_struct **vma_list, struct vm_area_struct *vma, uintptr_t up_bound);
int delete_vma(struct vm_area_struct **vma_list, struct vm_area_struct *vma);
struct vm_area_struct* find_vma(struct vm_area_struct *vma_list, uintptr_t vaddr, uintptr_t size);
int insert_pma(struct pm_area_struct **pma_list, struct pm_area_struct *pma);
int delete_pma(struct pm_area_struct **pma_list, struct pm_area_struct *pma);

int check_enclave_layout(uintptr_t root_page_table, uintptr_t va_start, uintptr_t va_end, uintptr_t pa_start, uintptr_t pa_end);
void* va_to_pa(uintptr_t* root_page_table, void* va);

int mmap(uintptr_t* root_page_table, struct page_t **free_pages, uintptr_t vaddr, uintptr_t paddr, uintptr_t size);
int unmap(uintptr_t* root_page_table, uintptr_t vaddr, uintptr_t size);

#endif /* _ENCLAVE_VM_H */
