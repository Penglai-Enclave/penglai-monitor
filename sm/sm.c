#include "atomic.h"
#include "sm.h"
#include "pmp.h"
#include "enclave.h"
#include "math.h"
#include "enclave_vm.h"
#include "server_enclave.h"

static int sm_initialized = 0;
static spinlock_t sm_init_lock = SPINLOCK_INIT;

void sm_init()
{
  platform_init();
}

uintptr_t sm_mm_init(uintptr_t paddr, unsigned long size)
{
  uintptr_t retval = 0;

  retval = mm_init(paddr, size);

  return retval;
}

uintptr_t sm_mm_extend(uintptr_t paddr, unsigned long size)
{
  uintptr_t retval = 0;

  retval = mm_init(paddr, size);

  return retval;
}

uintptr_t pt_area_base = 0;
uintptr_t pt_area_size = 0;
uintptr_t mbitmap_base = 0;
uintptr_t mbitmap_size = 0;
uintptr_t pgd_order = 0;
uintptr_t pmd_order = 0;
spinlock_t mbitmap_lock = SPINLOCK_INIT;

/**
 * This function validates whether the enclave environment is ready
 * It will check the PT_AREA and MBitmap.
 * If the two regions are properly configured, it means the host OS
 * has invoked SM_INIT sbi call and everything to run enclave is ready
 */
int enable_enclave()
{
  return pt_area_base && pt_area_size && mbitmap_base && mbitmap_size;
}

/**
 * The function checks whether a range of physical meory is untrusted memory (for 
 *  Host OS/apps to use)
 * Return value:
 * 	-1: some pages are not public (untrusted)
 * 	 0: all pages are public (untrusted)
 */
int test_public_range(uintptr_t pfn, uintptr_t pagenum)
{
  if(!enable_enclave())
    return 0;

  if(pfn < ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT))
    return -1;

  pfn = pfn - ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT);
  page_meta* meta = (page_meta*)mbitmap_base + pfn;
  if((uintptr_t)(meta + pagenum) > (mbitmap_base + mbitmap_size))
    return -1;

  uintptr_t cur = 0;
  while(cur < pagenum)
  {
    if(!IS_PUBLIC_PAGE(*meta))
      return -1;
    meta += 1;
    cur += 1;
  }

  return 0;
}

//TODO: delete this function
uintptr_t sm_debug_print(uintptr_t* regs, uintptr_t arg0)
{
  print_buddy_system();
  return 0;
}

uintptr_t sm_alloc_enclave_mem(uintptr_t mm_alloc_arg)
{
  struct mm_alloc_arg_t mm_alloc_arg_local;
  uintptr_t retval = 0;

  retval = copy_from_host(&mm_alloc_arg_local,
      (struct mm_alloc_arg_t*)mm_alloc_arg,
      sizeof(struct mm_alloc_arg_t));
  if(retval != 0)
  {
    printm("M mode: sm_alloc_enclave_mem: unknown error happended when copy from host\r\n");
    return ENCLAVE_ERROR;
  }

  unsigned long resp_size = 0;
  void* paddr = mm_alloc(mm_alloc_arg_local.req_size, &resp_size);
  if(paddr == NULL)
  {
    printm("M mode: sm_alloc_enclave_mem: no enough memory\r\n");
    return ENCLAVE_NO_MEMORY;
  }

  //grant kernel access to this memory
  if(grant_kernel_access(paddr, resp_size) != 0)
  {
    printm("M mode: ERROR: faile to grant kernel access to pa 0x%lx, size 0x%lx\r\n", paddr, resp_size);
    mm_free(paddr, resp_size);
    return ENCLAVE_ERROR;
  }

  mm_alloc_arg_local.resp_addr = (uintptr_t)paddr;
  mm_alloc_arg_local.resp_size = resp_size;

  copy_to_host((struct mm_alloc_arg_t*)mm_alloc_arg,
      &mm_alloc_arg_local,
      sizeof(struct mm_alloc_arg_t));

  return ENCLAVE_SUCCESS;
}

uintptr_t sm_create_enclave(uintptr_t enclave_sbi_param)
{
  struct enclave_sbi_param_t enclave_sbi_param_local;
  uintptr_t retval = 0;

  retval = copy_from_host(&enclave_sbi_param_local,
      (struct enclave_sbi_param_t*)enclave_sbi_param,
      sizeof(struct enclave_sbi_param_t));

  void* paddr = (void*)enclave_sbi_param_local.paddr;
  unsigned long size = (unsigned long)enclave_sbi_param_local.size;
  if(retrieve_kernel_access(paddr, size) != 0)
  {
    mm_free(paddr, size);
    return -1UL;
  }

  //TODO: not finished yet
  retval = create_enclave(enclave_sbi_param_local);

  return retval;
}

uintptr_t sm_run_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval;

  retval = run_enclave(regs, (unsigned int)eid);

  return retval;
}

uintptr_t sm_stop_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval;

  retval = stop_enclave(regs, (unsigned int)eid);

  return retval;
}

uintptr_t sm_resume_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval = 0;
  uintptr_t resume_func_id = regs[11];

  switch(resume_func_id)
  {
    case RESUME_FROM_TIMER_IRQ:
      //printm("resume from timer irq\r\n");
      *HLS()->timecmp = regs[12];
      clear_csr(mip, MIP_STIP);
      set_csr(mie, MIP_MTIP);
      retval = resume_enclave(regs, eid);
      break;
    case RESUME_FROM_STOP:
      //printm("resume from stop\r\n");
      retval = resume_from_stop(regs, eid);
      break;
    default:
      break;
  }

  return retval;
}

uintptr_t sm_exit_enclave(uintptr_t* regs, unsigned long retval)
{
  uintptr_t ret;

  ret = exit_enclave(regs, retval);

  return ret;
}

uintptr_t sm_do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc)
{
  uintptr_t ret;

  ret = do_timer_irq(regs, mcause, mepc);

  return ret;
}

uintptr_t sm_server_enclave_acquire(uintptr_t *regs, uintptr_t server_name)
{
  uintptr_t ret = 0;

  ret = acquire_server_enclave(regs, (char*)server_name);

  return ret;
}

uintptr_t sm_call_enclave(uintptr_t* regs, uintptr_t eid, uintptr_t arg)
{
  uintptr_t retval = 0;

  retval = call_enclave(regs, (unsigned int)eid, arg);

  return retval;
}

uintptr_t sm_enclave_return(uintptr_t* regs, uintptr_t arg)
{
  uintptr_t ret = 0;

  ret = enclave_return(regs, arg);

  return ret;
}

uintptr_t sm_create_server_enclave(uintptr_t enclave_sbi_param)
{
  struct enclave_sbi_param_t enclave_sbi_param_local;
  uintptr_t retval = 0;
  if(test_public_range(PADDR_TO_PFN(enclave_sbi_param),1)<0){
    return ENCLAVE_ERROR;
  }
  retval = copy_from_host(&enclave_sbi_param_local,
      (struct enclave_sbi_param_t*)enclave_sbi_param,
      sizeof(struct enclave_sbi_param_t));
  if(retval != 0)
    return ENCLAVE_ERROR;

  retval = create_server_enclave(enclave_sbi_param_local);

  return retval;
}

uintptr_t sm_destroy_server_enclave(uintptr_t *regs, uintptr_t enclave_id)
{
  uintptr_t ret = 0;

  ret = destroy_server_enclave(regs, enclave_id);

  return ret;
}
