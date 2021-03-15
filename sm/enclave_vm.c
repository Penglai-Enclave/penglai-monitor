#include "vm.h"
#include "mtrap.h"
#include "enclave_vm.h"

/**
 * \brief internal functions of check_enclave_layout, it will recursively check the region
 *
 * \param page_table is an PT page (physical addr), it could be non-root PT page
 * \param vaddr is the start virtual addr of the PTE in page_table
 * \param level is the PT page level of page_table
 */
static int __check_enclave_layout(uintptr_t page_table, uintptr_t va_start, uintptr_t va_end, uintptr_t pa_start, uintptr_t pa_end, uintptr_t vaddr, int level)
{
  if(level < 0)
  {
    return -1;
  }

  uintptr_t* pte = (uintptr_t*)page_table;
  uintptr_t region_size  = RISCV_PGSIZE * (1 << (level*RISCV_PGLEVEL_BITS));
  for(int i=0; i < (RISCV_PGSIZE/sizeof(uintptr_t)); ++i)
  {
    uintptr_t addr0 = vaddr + i*region_size;
    uintptr_t addr1 = addr0 + region_size;
    if(addr1 <= va_start || addr0 >= va_end)
    {
      continue;
    }

    if(PTE_VALID(pte[i]))
    {
      if(PTE_ILLEGAL(pte[i]))
      {
        return -1;
      }
      addr0 = PTE_TO_PFN(pte[i]) << RISCV_PGSHIFT;
      addr1 = addr0 + region_size;
      if(IS_LEAF_PTE(pte[i]))
      {
        if(!(addr0 >= pa_start && addr1 <= pa_end))
        {
          // printm("here: addr0: %lx, addr1: 0x%lx, pa_start: 0x%lx, pa_end: 0x%lx\r\n", addr0, addr1, pa_start, pa_end);
          return -1;
        }
      }
      else if(__check_enclave_layout(PTE_TO_PFN(pte[i]) << RISCV_PGSHIFT, va_start, va_end,
            pa_start, pa_end, addr0, level-1))
      {
        return -1;
      }
    }
  }
  return 0;
}

/**
 * \brief check whether a VM region is mapped (only) to a PM region
 *
 * \param root_page_table is the root of the pgae table
 * \param va_start is the start of the VM region
 * \param va_end is the end of the VM region
 * \param pa_start is the start of the PM region
 * \param pa_end is the end of the PM region
 */
int check_enclave_layout(uintptr_t root_page_table, uintptr_t va_start, uintptr_t va_end, uintptr_t pa_start, uintptr_t pa_end)
{
  return __check_enclave_layout(root_page_table, va_start, va_end, pa_start, pa_end, 0, RISCV_PGLEVELS-1);
}

static void __traverse_vmas(uintptr_t page_table, struct vm_area_struct *vma_list, int *vma_num, uintptr_t *va_start, uintptr_t *va_end, uintptr_t vaddr, int level)
{
  if(level < 0)
  {
    return;
  }

  uintptr_t *pte = (uintptr_t*)page_table;
  uintptr_t region_size = RISCV_PGSIZE * (1 << (level * RISCV_PGLEVEL_BITS));
  for(int i = 0; i < (RISCV_PGSIZE / sizeof(uintptr_t)); ++i)
  {
    if(!PTE_VALID(pte[i]))
    {
      if((*va_start) && (*va_end))
      {
        vma_list[*vma_num].va_start = *va_start;
        vma_list[*vma_num].va_end = *va_end;
        vma_list[*vma_num].vm_next = (struct vm_area_struct*)(&vma_list[*vma_num + 1]);
        //printm("here1:vma_num:%d, va_start:0x%lx, va_end:0x%lx\r\n", *vma_num, *va_start, *va_end);
        *va_start = 0;
        *va_end = 0;
        *vma_num += 1;
      }
      continue;
    }

    if(IS_LEAF_PTE(pte[i]))
    {
      if(!(*va_start))
      {
        *va_start = vaddr + i*region_size;
      }
      *va_end = vaddr + (i+1)*region_size;
    }
    else
    {
      __traverse_vmas(PTE_TO_PFN(pte[i]) << RISCV_PGSHIFT, vma_list, vma_num,
          va_start, va_end, vaddr + i * region_size, level - 1);
    }
  }

  if(level == (RISCV_PGLEVELS - 1) && (*va_start) && (*va_end))
  {
    vma_list[*vma_num].va_start = *va_start;
    vma_list[*vma_num].va_end = *va_end;
    vma_list[*vma_num].vm_next = 0;
    //printm("here2:vma_num:%d, va_start:0x%lx, va_end:0x%lx\r\n", *vma_num, *va_start, *va_end);
    *va_start = 0;
    *va_end = 0;
    *vma_num += 1;
  }
  else if(level == (RISCV_PGLEVELS - 1) && *vma_num)
  {
    //printm("here3:vma_num:%d, va_start:0x%lx, va_end:0x%lx\r\n", *vma_num, vma_list[*vma_num-1].va_start, vma_list[*vma_num-1].va_end);
    vma_list[*vma_num - 1].vm_next = 0;
  }
}

//should only be called during create_enclave as two vma may be mistakely regarded as one
//after monitor map new pages for enclave
void traverse_vmas(uintptr_t root_page_table, struct vm_area_struct *vma_list)
{
  uintptr_t va_start = 0;
  uintptr_t va_end = 0;
  int vma_num = 0;
  __traverse_vmas(root_page_table, vma_list, &vma_num, &va_start, &va_end, 0, RISCV_PGLEVELS - 1);
  //printm("traverse_vmas: vma_num is %d\r\n", vma_num);
}

void* __va_to_pa(uintptr_t* page_table, uintptr_t *va, int level)
{
  if(!page_table || level<0)
    return NULL;

  uintptr_t page_size_bits = RISCV_PGSHIFT + level * RISCV_PGLEVEL_BITS;
  uintptr_t pos = (((uintptr_t)va) >> page_size_bits) & ((1<<RISCV_PGLEVEL_BITS)-1);
  uintptr_t pte = page_table[pos];
  uintptr_t next_page_table = PTE_TO_PFN(pte) << RISCV_PGSHIFT;
  if(PTE_VALID(pte))
  {
    if(IS_LEAF_PTE(pte))
    {
      uintptr_t pa = next_page_table + (((uintptr_t)va) & ((1 << page_size_bits) - 1));
      return (void*)pa;
    }
    else
    {
      return __va_to_pa((uintptr_t*)next_page_table, va, level-1);
    }
  }
  else
  {
    return NULL;
  }
}

void* va_to_pa(uintptr_t* root_page_table, void* va)
{
  void* result = NULL;
  result = __va_to_pa(root_page_table, va, RISCV_PGLEVELS - 1);
  return result;
}

int insert_vma(struct vm_area_struct **vma_list, struct vm_area_struct *vma, uintptr_t up_bound)
{
  if(vma->va_end > up_bound)
    return -1;

  struct vm_area_struct* first_vma = *vma_list;
  if(!first_vma || (first_vma->va_start >= vma->va_end))
  {
    vma->vm_next = first_vma;
    *vma_list = vma;
    return 0;
  }

  int found = 0;
  struct vm_area_struct* second_vma = first_vma->vm_next;
  while(second_vma)
  {
    if((first_vma->va_end <= vma->va_start) && (second_vma->va_start >= vma->va_end))
    {
      vma->vm_next = second_vma;
      first_vma->vm_next = vma;
      found = 1;
      break;
    }
    first_vma = second_vma;
    second_vma = second_vma->vm_next;
  }
  if(!found)
  {
    if(first_vma && (first_vma->va_end <= vma->va_start))
    {
      first_vma->vm_next = vma;
      vma->vm_next = NULL;
      return 0;
    }
    return -1;
  }

  return 0;
}

int delete_vma(struct vm_area_struct **vma_list, struct vm_area_struct *vma)
{
  struct vm_area_struct *last_vma = (struct vm_area_struct*)(*vma_list);
  if(last_vma->va_start <= vma->va_start && last_vma->va_end >= vma->va_end)
  {
    *vma_list = last_vma->vm_next;
    vma->vm_next = NULL;
    last_vma->vm_next = NULL;
    return 0;
  }

  struct vm_area_struct *cur_vma = last_vma->vm_next;
  while(cur_vma)
  {
    if(cur_vma->va_start <= vma->va_start && cur_vma->va_end >= vma->va_end)
    {
      last_vma->vm_next = cur_vma->vm_next;
      vma->vm_next = NULL;
      cur_vma->vm_next = NULL;
      return 0;
    }
    last_vma = cur_vma;
    cur_vma = cur_vma->vm_next;
  }

  return -1;
}

struct vm_area_struct* find_vma(struct vm_area_struct *vma_list, uintptr_t vaddr, uintptr_t size)
{
  uintptr_t va_start = vaddr;
  uintptr_t va_end = vaddr + size;
  struct vm_area_struct *vma = vma_list;
  while(vma)
  {
    if(vma->va_start <= va_start && vma->va_end >= va_end)
    {
      return vma;
    }
    vma = vma->vm_next;
  }
  return NULL;
}

int insert_pma(struct pm_area_struct **pma_list, struct pm_area_struct *pma)
{
  pma->pm_next = *pma_list;
  *pma_list = pma;
  return 0;
}

int delete_pma(struct pm_area_struct **pma_list, struct pm_area_struct *pma)
{
  struct pm_area_struct *last_pma = *pma_list;
  if(last_pma->paddr == pma->paddr && last_pma->size == pma->size)
  {
    *pma_list = last_pma->pm_next;
    pma->pm_next = NULL;
    last_pma->pm_next = NULL;
    return 0;
  }

  struct pm_area_struct *cur_pma = last_pma->pm_next;
  while(cur_pma)
  {
    if(cur_pma->paddr == pma->paddr && cur_pma->size == pma->size)
    {
      last_pma->pm_next = cur_pma->pm_next;
      pma->pm_next = NULL;
      cur_pma->pm_next = NULL;
      return 0;
    }
    last_pma = cur_pma;
    cur_pma = cur_pma->pm_next;
  }

  return -1;
}

static uintptr_t *__pte_walk_create(uintptr_t *page_table, struct page_t **free_pages, uintptr_t va, int level)
{
  uintptr_t pos = (va >> (RISCV_PGSHIFT + level * RISCV_PGLEVEL_BITS)) & ((1<<RISCV_PGLEVEL_BITS) - 1);
  if(level == 0)
  {
    return &(page_table[pos]);
  }

  if(!(page_table[pos] & PTE_V))
  {
    if(!(*free_pages))
    {
      printm("__pte_walk_create: free_pages is empty\r\n");
      return NULL;
    }
    uintptr_t paddr = (*free_pages)->paddr;
    *free_pages = (*free_pages)->next;
    page_table[pos] = pte_create(paddr>>RISCV_PGSHIFT, PTE_V);
  }
  return __pte_walk_create((uintptr_t*)(PTE_TO_PFN(page_table[pos]) << RISCV_PGSHIFT),
      free_pages, va, level - 1);
}

static uintptr_t *pte_walk_create(uintptr_t *root_page_table, struct page_t **free_pages, uintptr_t va)
{
  return __pte_walk_create(root_page_table, free_pages, va, RISCV_PGLEVELS - 1);
}

static uintptr_t *__pte_walk(uintptr_t *page_table, uintptr_t va, int level)
{
  uintptr_t pos = (va >> (RISCV_PGSHIFT + level * RISCV_PGLEVEL_BITS)) & ((1<<RISCV_PGLEVEL_BITS) - 1);
  if(level == 0)
  {
    return &(page_table[pos]);
  }

  if(!(page_table[pos] & PTE_V))
  {
    return NULL;
  }

  //we do not support 2M page now
  /*
  if((page_table[pos] & PTE_R) || (page_table[pos] & PTE_W))
  {
    return &(page_table[pos]);
  }
  */

  return __pte_walk((uintptr_t*)(PTE_TO_PFN(page_table[pos]) << RISCV_PGSHIFT), va, level - 1);
}

static uintptr_t *pte_walk(uintptr_t *root_page_table, uintptr_t va)
{
  return __pte_walk(root_page_table, va, RISCV_PGLEVELS - 1);
}

static int map_one_page(uintptr_t *root_page_table, struct page_t **free_pages, uintptr_t va, uintptr_t pa, uintptr_t flag)
{
  uintptr_t *pte = pte_walk_create(root_page_table, free_pages, va);
  if(!pte)
  {
    return -1;
  }
  if(PTE_VALID(*pte))
  {
    printm("mmap: va 0x%lx is already mmaped: pte: 0x%lx\r\n", va, *pte);
  }

  *pte = pte_create(pa>>RISCV_PGSHIFT, flag | PTE_V);
  return 0;
}

static int unmap_one_page(uintptr_t *root_page_table, uintptr_t va)
{
  uintptr_t *pte = pte_walk(root_page_table, va);
  if(!pte)
    return -1;
  *pte = 0;
  return 0;
}

int mmap(uintptr_t* root_page_table, struct page_t **free_pages, uintptr_t vaddr, uintptr_t paddr, uintptr_t size)
{
  uintptr_t va = vaddr;
  uintptr_t pa = paddr;
  uintptr_t va_end = vaddr + size;
  while(va < va_end)
  {
    if(map_one_page(root_page_table, free_pages, va, pa, PTE_D | PTE_A | PTE_R | PTE_W | PTE_U | PTE_V) != 0)
    {
      printm("mmap failed\r\n");
      return -1;
    }
    va += RISCV_PGSIZE;
    pa += RISCV_PGSIZE;
  }
  return 0;
}

int unmap(uintptr_t* root_page_table, uintptr_t vaddr, uintptr_t size)
{
  uintptr_t va = vaddr;
  uintptr_t va_end = vaddr + size;
  while(va < va_end)
  {
    unmap_one_page(root_page_table, va);
    va += RISCV_PGSIZE;
  }
  return 0;
}
