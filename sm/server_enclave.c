#include "sm.h"
#include "enclave.h"
#include "enclave_vm.h"
#include "server_enclave.h"
#include "ipi.h"
#include TARGET_PLATFORM_HEADER

struct link_mem_t* server_enclave_head = NULL;
struct link_mem_t* server_enclave_tail = NULL;

static int server_name_cmp(char* name1, char* name2)
{
    for(int i=0; i<NAME_LEN; ++i)
    {
        if(name1[i] != name2[i])
        {
            return 1;
        }
        if(name1[i] == 0)
        {
            return 0;
        }
    }
    return 0;
}

static struct server_enclave_t* __alloc_server_enclave(char *server_name)
{
    struct enclave_t* enclave = alloc_enclave();
    if(!enclave)
        return NULL;

    struct link_mem_t *cur, *next;
    struct server_enclave_t* server_enclave = NULL;
    int found = 0;

    //server_enclave metadata list hasn't be initialized yet
    if(server_enclave_head == NULL)
    {
        server_enclave_head = init_mem_link(sizeof(struct server_enclave_t)*SERVERS_PER_METADATA_REGION, sizeof(struct server_enclave_t));
        if(!server_enclave_head)
        {
            goto failed;
        }
        server_enclave_tail = server_enclave_head;
    }

    //check whether server name already existed
    for(cur = server_enclave_head; cur != NULL; cur = cur->next_link_mem)
    {
        for(int i = 0; i < (cur->slab_num); i++)
        {
            server_enclave = (struct server_enclave_t*)(cur->addr) + i;
            if(server_enclave->entity && server_name_cmp(server_name, server_enclave->server_name)==0)
            {
                printm("server already existed!\r\n");
                server_enclave = (void*)(-1UL);
                goto failed;
            }
        }
    }

    found = 0;
    for(cur = server_enclave_head; cur != NULL; cur = cur->next_link_mem)
    {
        for(int i = 0; i < (cur->slab_num); i++)
        {
            server_enclave = (struct server_enclave_t*)(cur->addr) + i;
            if(!(server_enclave->entity))
            {
                memcpy(server_enclave->server_name, server_name, NAME_LEN);
                server_enclave->entity = enclave;
                found = 1;
                break;
            }
        }
        if(found)
            break;
    }

    //don't have enough enclave metadata
    if(!found)
    {
        next = add_link_mem(&server_enclave_tail);
        if(next == NULL)
        {
            printm("M mode: __alloc_server_enclave: don't have enough mem\r\n");
            server_enclave = NULL;
            goto failed;
        }
        server_enclave = (struct server_enclave_t*)(next->addr);
        memcpy(server_enclave->server_name, server_name, NAME_LEN);
        server_enclave->entity = enclave;
    }

    return server_enclave;

    failed:
    if(enclave)
        free_enclave(enclave->eid);
    if(server_enclave)
        memset((void*)server_enclave, 0, sizeof(struct server_enclave_t));

    return NULL;
}


static struct server_enclave_t* __get_server_enclave_by_name(char* server_name)
{
    struct link_mem_t *cur;
    struct server_enclave_t *server_enclave;
    int i, found;

    found = 0;
    for(cur = server_enclave_head; cur != NULL; cur = cur->next_link_mem)
    {
        for(int i=0; i < (cur->slab_num); ++i)
        {
            server_enclave = (struct server_enclave_t*)(cur->addr) + i;
            if(server_enclave->entity && server_name_cmp(server_enclave->server_name, server_name)==0)
            {
                found = 1;
                break;
            }
        }
    }

    //haven't alloc this eid 
    if(!found)
    {
        printm("M mode: __get_server_enclave_by_name: haven't alloc this enclave:%s\r\n", server_name);
        server_enclave = NULL;
    }

    return server_enclave;
}

/**************************************************************/
/*                   called by host                           */
/**************************************************************/
uintptr_t create_server_enclave(struct enclave_sbi_param_t create_args)
{
  struct enclave_t* enclave = NULL;
  struct server_enclave_t* server_enclave = NULL;
  uintptr_t ret = 0;

  acquire_enclave_metadata_lock();

  if((create_args.paddr & (RISCV_PGSIZE - 1)) || (create_args.size & (RISCV_PGSIZE - 1)) || create_args.size < RISCV_PGSIZE)
  {
    ret = ENCLAVE_ERROR;
    goto failed;
  }
   //check enclave memory layout
  if(check_enclave_layout(create_args.paddr + RISCV_PGSIZE, 0, -1UL, create_args.paddr, create_args.paddr + create_args.size) != 0)
  {
    ret = ENCLAVE_ERROR;
    goto failed;
  }

  server_enclave = __alloc_server_enclave(create_args.name);
  if(server_enclave == (void*)(-1UL))
  {
    ret = ENCLAVE_ERROR;
    goto failed;
  }
  if(!server_enclave)
  {
    //printm("create_server_enclave: no mem\r\n");
    ret = ENCLAVE_NO_MEMORY;
    goto failed;
  }

  enclave = server_enclave->entity;
  enclave->paddr = create_args.paddr;
  enclave->size = create_args.size;
  enclave->entry_point = create_args.entry_point;
  enclave->free_mem = create_args.free_mem;
  enclave->ocall_func_id = create_args.ecall_arg0;
  enclave->ocall_arg0 = create_args.ecall_arg1;
  enclave->ocall_arg1 = create_args.ecall_arg2;
  enclave->ocall_syscall_num = create_args.ecall_arg3;
  enclave->host_ptbr = read_csr(satp);
  enclave->root_page_table = create_args.paddr + RISCV_PGSIZE;
  enclave->thread_context.encl_ptbr = ((create_args.paddr + RISCV_PGSIZE) >> (RISCV_PGSHIFT) | SATP_MODE_CHOICE);
  enclave->type = SERVER_ENCLAVE;
  //we directly set server_enclave's state as RUNNABLE as it won't be called by run_enclave call
  enclave->state = RUNNABLE;
  enclave->caller_eid = -1;
  enclave->top_caller_eid = -1;
  enclave->cur_callee_eid = -1;

  //traverse vmas
  struct pm_area_struct* pma = (struct pm_area_struct*)(create_args.paddr);
  struct vm_area_struct* vma = (struct vm_area_struct*)(create_args.paddr + sizeof(struct pm_area_struct));
  pma->paddr = create_args.paddr;
  pma->size = create_args.size;
  pma->free_mem = create_args.free_mem;
  if(pma->free_mem < pma->paddr || pma->free_mem >= pma->paddr+pma->size
     || pma->free_mem & ((1<<RISCV_PGSHIFT) - 1))
  {
    ret = ENCLAVE_ERROR;
    printm("fail: ENCLAVE_ERROR");
    return ret;
  }
  pma->pm_next = NULL;
  enclave->pma_list = pma;
  traverse_vmas(enclave->root_page_table, vma);

  //FIXME: here we assume there are exactly text(include text/data/bss) vma and stack vma
  while(vma)
  {
    if(vma->va_start == ENCLAVE_DEFAULT_TEXT_BASE)
    {
      enclave->text_vma = vma;
    }
    if(vma->va_end == ENCLAVE_DEFAULT_STACK_BASE)
    {
      enclave->stack_vma = vma;
      enclave->_stack_top = enclave->stack_vma->va_start;
    }
    vma->pma = pma;
    vma = vma->vm_next;
  }
  if(enclave->text_vma)
    enclave->text_vma->vm_next = NULL;
  if(enclave->stack_vma)
    enclave->stack_vma->vm_next = NULL;
  enclave->_heap_top = ENCLAVE_DEFAULT_HEAP_BASE;
  enclave->heap_vma = NULL;
  enclave->mmap_vma = NULL;

  enclave->free_pages = NULL;
  enclave->free_pages_num = 0;
  uintptr_t free_mem = create_args.paddr + create_args.size - RISCV_PGSIZE;
  while(free_mem >= create_args.free_mem)
  {
    struct page_t *page = (struct page_t*)free_mem;
    page->paddr = free_mem;
    page->next = enclave->free_pages;
    enclave->free_pages = page;
    enclave->free_pages_num += 1;
    free_mem -= RISCV_PGSIZE;
  }

  copy_word_to_host((unsigned int*)create_args.eid_ptr, enclave->eid);
  release_enclave_metadata_lock();
  return ret;

failed:
  release_enclave_metadata_lock();
  printm("M MODE: acquire encalve failed\r\n");
  return ret;
}

//host call this function to destroy an existing enclave
uintptr_t destroy_server_enclave(uintptr_t* regs, unsigned int eid)
{
  return 0;
}

/**************************************************************/
/*                   called by enclave                        */
/**************************************************************/
uintptr_t acquire_server_enclave(uintptr_t *regs, char* server_name_u)
{
  uintptr_t ret = 0;
  struct enclave_t *enclave = NULL;
  struct server_enclave_t *server_enclave = NULL;
  char *server_name = NULL;
  int eid = 0;
  if(check_in_enclave_world() < 0)
  {
    return -1UL;
  }

  acquire_enclave_metadata_lock();

  eid = get_curr_enclave_id();
  enclave = get_enclave(eid);
  if(!enclave)
  {
    ret = -1UL;
    goto failed;
  }

  server_name = va_to_pa((uintptr_t*)(enclave->root_page_table), server_name_u);
  if(!server_name)
  {
    ret = -1UL;
    goto failed;
  }
  printm("server_enclave: after get server_name server_name is: %s\r\n", server_name);

  server_enclave = __get_server_enclave_by_name(server_name);
  if(!server_enclave)
  {
    ret = -1UL;
    goto failed;
  }
  ret = server_enclave->entity->eid;

  release_enclave_metadata_lock();
  printm("M MODE: acquire encalve success ret %d\r\n", ret);
  return ret;

failed:
  release_enclave_metadata_lock();
  printm("M MODE: acquire encalve failed\r\n");
  return ret;
}
