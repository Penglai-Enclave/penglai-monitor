#include "mtrap.h"
#include "mcall.h"
#include "htif.h"
#include "atomic.h"
#include "bits.h"
#include "vm.h"
#include "uart.h"
#include "uart16550.h"
#include "finisher.h"
#include "fdt.h"
#include "unprivileged_memory.h"
#include "disabled_hart_mask.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef SM_ENABLED
#include "sm.h"
#endif

void __attribute__((noreturn)) bad_trap(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc)
{
  die("machine mode: unhandlable trap %d @ %p", read_csr(mcause), mepc);
}

static uintptr_t mcall_console_putchar(uint8_t ch)
{
  if (uart) {
    uart_putchar(ch);
  } else if (uart16550) {
    uart16550_putchar(ch);
  } else if (htif) {
    htif_console_putchar(ch);
  }
  return 0;
}

void putstring(const char* s)
{
  while (*s)
    mcall_console_putchar(*s++);
}

void vprintm(const char* s, va_list vl)
{
  char buf[256];
  vsnprintf(buf, sizeof buf, s, vl);
  putstring(buf);
}

void printm(const char* s, ...)
{
  va_list vl;

  va_start(vl, s);
  vprintm(s, vl);
  va_end(vl);
}

static void send_ipi(uintptr_t recipient, int event)
{
  if (((disabled_hart_mask >> recipient) & 1)) return;
  atomic_or(&OTHER_HLS(recipient)->mipi_pending, event);
  mb();
  *OTHER_HLS(recipient)->ipi = 1;
}

static uintptr_t mcall_console_getchar()
{
  if (uart) {
    return uart_getchar();
  } else if (uart16550) {
    return uart16550_getchar();
  } else if (htif) {
    return htif_console_getchar();
  } else {
    return '\0';
  }
}

static uintptr_t mcall_clear_ipi()
{
  return clear_csr(mip, MIP_SSIP) & MIP_SSIP;
}

static uintptr_t mcall_shutdown()
{
  poweroff(0);
}

static uintptr_t mcall_set_timer(uint64_t when)
{
  *HLS()->timecmp = when;
  clear_csr(mip, MIP_STIP);
  set_csr(mie, MIP_MTIP);
  return 0;
}

static void send_ipi_many(uintptr_t* pmask, int event)
{
  _Static_assert(MAX_HARTS <= 8 * sizeof(*pmask), "# harts > uintptr_t bits");
  uintptr_t mask = hart_mask;
  if (pmask)
    mask &= load_uintptr_t(pmask, read_csr(mepc));

  // send IPIs to everyone
  for (uintptr_t i = 0, m = mask; m; i++, m >>= 1)
    if (m & 1)
      send_ipi(i, event);

  if (event == IPI_SOFT)
    return;

  // wait until all events have been handled.
  // prevent deadlock by consuming incoming IPIs.
  uint32_t incoming_ipi = 0;
  for (uintptr_t i = 0, m = mask; m; i++, m >>= 1)
    if (m & 1)
      while (*OTHER_HLS(i)->ipi)
        incoming_ipi |= atomic_swap(HLS()->ipi, 0);

  // if we got an IPI, restore it; it will be taken after returning
  if (incoming_ipi) {
    *HLS()->ipi = incoming_ipi;
    mb();
  }
}

void mcall_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  write_csr(mepc, mepc + 4);

  uintptr_t n = regs[17], arg0 = regs[10], arg1 = regs[11], arg2 = regs[12], retval, ipi_type;

  switch (n)
  {
    case SBI_CONSOLE_PUTCHAR:
      retval = mcall_console_putchar(arg0);
      break;
    case SBI_CONSOLE_GETCHAR:
      retval = mcall_console_getchar();
      break;
    case SBI_SEND_IPI:
      ipi_type = IPI_SOFT;
      goto send_ipi;
    case SBI_REMOTE_SFENCE_VMA:
    case SBI_REMOTE_SFENCE_VMA_ASID:
      ipi_type = IPI_SFENCE_VMA;
      goto send_ipi;
    case SBI_REMOTE_FENCE_I:
      ipi_type = IPI_FENCE_I;
send_ipi:
      send_ipi_many((uintptr_t*)arg0, ipi_type);
      retval = 0;
      break;
    case SBI_CLEAR_IPI:
      retval = mcall_clear_ipi();
      break;
    case SBI_SHUTDOWN:
      retval = mcall_shutdown();
      break;
    case SBI_SET_TIMER:
#if __riscv_xlen == 32
      retval = mcall_set_timer(arg0 + ((uint64_t)arg1 << 32));
#else
      retval = mcall_set_timer(arg0);
#endif
      break;

#ifdef SM_ENABLED

    case SBI_MM_INIT:
      retval = sm_mm_init(arg0, arg1);
      break;
    case SBI_MEMORY_EXTEND:
      retval = sm_mm_extend(arg0, arg1);
      break;
    case SBI_ALLOC_ENCLAVE_MM:
      retval = sm_alloc_enclave_mem(arg0);
      break;
    case SBI_CREATE_ENCLAVE:
      retval = sm_create_enclave(arg0);
      break;
    case SBI_ATTEST_ENCLAVE:
      retval = 0;//sm_attest_enclave(arg0, arg1, arg2);
    case SBI_RUN_ENCLAVE:
      retval = sm_run_enclave(regs, arg0);
      break;
    case SBI_STOP_ENCLAVE:
      retval = sm_stop_enclave(regs, arg0);
      break;
    case SBI_RESUME_ENCLAVE:
      retval = sm_resume_enclave(regs, arg0);
      break;
    case SBI_DESTROY_ENCLAVE:
      retval = 0;//sm_destroy_enclave(regs, arg0,arg1);
      break;
    case SBI_ENCLAVE_OCALL:
      retval = sm_enclave_ocall(regs, arg0, arg1, arg2);
      break;
    case SBI_EXIT_ENCLAVE:
      retval = sm_exit_enclave(regs, arg0);
      break;
    case SBI_CREATE_SERVER_ENCLAVE:
      retval = sm_create_server_enclave(arg0);
      break;
    case SBI_DESTROY_SERVER_ENCLAVE:
      retval = sm_destroy_server_enclave(regs, arg0);
      break;
    case SBI_ACQUIRE_SERVER:
      retval = sm_server_enclave_acquire(regs, arg0);
      break;
    case SBI_CALL_ENCLAVE:
      retval = sm_call_enclave(regs, arg0, arg1);
      break;
    case SBI_ENCLAVE_RETURN:
      retval = sm_enclave_return(regs, arg0);
      break;
    //TODO: delete this SBI_CALL
    case SBI_DEBUG_PRINT:
      printm("SBI_DEBUG_PRINT\r\n");
      retval = sm_debug_print(regs, arg0);
      break;

#endif /* SM_ENABLED */

    default:
      retval = -ENOSYS;
      break;
  }
  regs[10] = retval;
}

void redirect_trap(uintptr_t epc, uintptr_t mstatus, uintptr_t badaddr)
{
  write_csr(sbadaddr, badaddr);
  write_csr(sepc, epc);
  write_csr(scause, read_csr(mcause));
  write_csr(mepc, read_csr(stvec));

  uintptr_t new_mstatus = mstatus & ~(MSTATUS_SPP | MSTATUS_SPIE | MSTATUS_SIE);
  uintptr_t mpp_s = MSTATUS_MPP & (MSTATUS_MPP >> 1);
  new_mstatus |= (mstatus * (MSTATUS_SPIE / MSTATUS_SIE)) & MSTATUS_SPIE;
  new_mstatus |= (mstatus / (mpp_s / MSTATUS_SPP)) & MSTATUS_SPP;
  new_mstatus |= mpp_s;
  write_csr(mstatus, new_mstatus);

  extern void __redirect_trap();
  return __redirect_trap();
}

void pmp_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  redirect_trap(mepc, read_csr(mstatus), read_csr(mbadaddr));
}

#ifdef SM_ENABLED
void handle_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc)
{
  if(check_in_enclave_world() < 0)
  {
    clear_csr(mie, MIP_MTIP);
    set_csr(mip, MIP_STIP);
    return;
  }

  sm_do_timer_irq(regs, mcause, mepc);
}

void enclave_call_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  if(check_in_enclave_world() < 0)
    bad_trap(regs, 0, mepc);
  else
    mcall_trap(regs, mcause, mepc);
}

void spmp_inst_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  if(check_in_enclave_world() < 0)
    bad_trap(regs, mcause, mepc);

#ifdef SPMP_ENABLED
  if(read_spmpexpt(spmpexpt))
  {
    //TODO: deal with spmp trap
    printm("M mode: spmp_inst_trap, badaddr: 0x%lx, badepc: 0x%lx\r\n", read_csr(mbadaddr), read_csr(mepc));
    set_spmpexpt(spmpexpt, 0);
    bad_trap(regs, mcause, mepc);
  }
#endif /* SPMP_ENABLED */

  //TODO: deal with enclave page fault
  printm("M mode: inst_page_fault, badaddr: 0x%lx, badepc: 0x%lx\r\n", read_csr(mbadaddr), read_csr(mepc));
  bad_trap(regs, mcause, mepc);
}

void spmp_load_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  if(check_in_enclave_world() < 0)
    bad_trap(regs, mcause, mepc);

#ifdef SPMP_ENABLED
  if(read_spmpexpt(spmpexpt))
  {
    //TODO: deal with spmp trap
    printm("M mode: spmp_load_trap, badaddr: 0x%lx, badepc: 0x%lx\r\n", read_csr(mbadaddr), read_csr(mepc));
    set_spmpexpt(spmpexpt, 0);
    bad_trap(regs, mcause, mepc);
  }
#endif /* SPMP_ENABLED */


  //TODO: deal with enclave page fault
  printm("M mode: load_page_fault, badaddr: 0x%lx, badepc: 0x%lx\r\n", read_csr(mbadaddr), read_csr(mepc));
  bad_trap(regs, mcause, mepc);
}

void spmp_store_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  if(check_in_enclave_world() < 0)
    bad_trap(regs, mcause, mepc);

#ifdef SPMP_ENABLED
  if(read_spmpexpt(spmpexpt))
  {
    //TODO: deal with spmp trap
    printm("M mode: spmp_store_trap, badaddr: 0x%lx, badepc: 0x%lx\r\n", read_csr(mbadaddr), read_csr(mepc));
    set_spmpexpt(spmpexpt, 0);
    bad_trap(regs, mcause, mepc);
  }
#endif /* SPMP_ENABLED */

  //TODO: deal with enclave page fault
  printm("M mode: store_page_fault, badaddr: 0x%lx, badepc: 0x%lx\r\n", read_csr(mbadaddr), read_csr(mepc));
  bad_trap(regs, mcause, mepc);
}
#endif /* SM_ENABLED */

static void machine_page_fault(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc)
{
  // MPRV=1 iff this trap occurred while emulating an instruction on behalf
  // of a lower privilege level. In that case, a2=epc and a3=mstatus.
  if (read_csr(mstatus) & MSTATUS_MPRV) {
    return redirect_trap(regs[12], regs[13], read_csr(mbadaddr));
  }
  bad_trap(regs, dummy, mepc);
}

void trap_from_machine_mode(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc)
{
  uintptr_t mcause = read_csr(mcause);

  switch (mcause)
  {
    case CAUSE_LOAD_PAGE_FAULT:
    case CAUSE_STORE_PAGE_FAULT:
    case CAUSE_FETCH_ACCESS:
    case CAUSE_LOAD_ACCESS:
    case CAUSE_STORE_ACCESS:
      return machine_page_fault(regs, dummy, mepc);
    default:
      bad_trap(regs, dummy, mepc);
  }
}

void poweroff(uint16_t code)
{
  printm("Power off\r\n");
  finisher_exit(code);
  if (htif) {
    htif_poweroff();
  } else {
    send_ipi_many(0, IPI_HALT);
    while (1) { asm volatile ("wfi\n"); }
  }
}
