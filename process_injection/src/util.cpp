#include "util.h"
#include <processthreadsapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <windows.h>
#ifdef DEBUG
#include <stdio.h>
#endif

const struct func_with_module alertable_functions[] = {
    {"C:\\Windows\\System32\\ntdll.dll", "NtDelayExecution"},
    {"C:\\Windows\\System32\\ntdll.dll", "NtWaitForSingleObject"},
    {"C:\\Windows\\System32\\ntdll.dll", "NtWaitForMultipleObjects"},
    {"C:\\Windows\\System32\\ntdll.dll", "NtSignalAndWaitForSingleObject"},
    {"C:\\Windows\\System32\\win32u.dll", "NtUserMsgWaitForMultipleObjectsEx"},
};

HANDLE open_process(LPCSTR procname, DWORD permissions, BOOL using_pid) {
  if (using_pid) {
    // assume we have already checked procname is numeric
    return OpenProcess(permissions, FALSE, atoi(procname));
  }
  // process iterator
  PROCESSENTRY32 proc_entry;
  HANDLE to_return = NULL;
  HANDLE proc_handle = NULL;
  proc_entry.dwSize = sizeof(PROCESSENTRY32);

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  // iterate over processes in snapshot
  if (Process32First(snapshot, &proc_entry)) {
    do {
      if (stricmp(procname, proc_entry.szExeFile) == 0) {
        proc_handle = OpenProcess(permissions, FALSE, proc_entry.th32ProcessID);
        // if we do not have sufficient permissions, keep searching
        if (proc_handle != NULL) {
          to_return = proc_handle;
          break;
        }
        CloseHandle(proc_handle);
      }
    } while (Process32Next(snapshot, &proc_entry));
  }
  CloseHandle(snapshot);
  return proc_handle;
  ;
}

std::pair<LPVOID, size_t> load_sections(DWORD_PTR dll_buffer, SIZE_T dll_size) {
  PIMAGE_NT_HEADERS pe_headers = (PIMAGE_NT_HEADERS)(
      ((PIMAGE_DOS_HEADER)dll_buffer)->e_lfanew + dll_buffer);

  // allocate new buffer and copy headers, ensuring it's zeroed
  BYTE *new_buffer = (BYTE *)calloc(pe_headers->OptionalHeader.SizeOfImage, 1);
  memcpy(new_buffer, (LPVOID)dll_buffer,
         pe_headers->OptionalHeader.SizeOfHeaders);

  // file header starts 4 bytes after pe header
  DWORD number_of_sections =
      ((PIMAGE_FILE_HEADER)((DWORD_PTR)pe_headers + 0x4))->NumberOfSections;

  // section table starts right after optional header
  PIMAGE_SECTION_HEADER section_table = (PIMAGE_SECTION_HEADER)(
      (DWORD_PTR)&pe_headers->OptionalHeader +
      (DWORD_PTR)((PIMAGE_FILE_HEADER)((DWORD_PTR)pe_headers + 0x4))
          ->SizeOfOptionalHeader);

  // copy sections

  while (number_of_sections > 0) {
    memcpy(section_table->VirtualAddress + new_buffer,
           (LPVOID)(section_table->PointerToRawData + dll_buffer),
           section_table->SizeOfRawData);
    section_table++;
    number_of_sections--;
  }

  std::pair<LPVOID, size_t> to_return = std::pair<LPVOID, size_t>(
      (LPVOID)new_buffer, pe_headers->OptionalHeader.SizeOfImage);

  return to_return;
}

HMODULE get_remote_module(HANDLE proc, const char *target_module_name) {
  size_t modules_needed = 200;

  HMODULE *modules = (HMODULE *)malloc(sizeof(HMODULE) * modules_needed);
  DWORD bytes_needed;

  // get array of all the modules in process
  if (EnumProcessModules(proc, modules, sizeof(HMODULE) * modules_needed,
                         &bytes_needed) == 0) {
#ifdef DEBUG
    printf("Failed to enumerate process modules. Error code: %d\n",
           GetLastError());
#endif
    return NULL;
  }

  // if we didn't have enough space for all of the modules, retry with enough
  // space
  if (bytes_needed > sizeof(HMODULE) * modules_needed) {
    free(modules);
    modules_needed = bytes_needed / sizeof(HMODULE);
    modules = (HMODULE *)malloc(bytes_needed);
    if (EnumProcessModules(proc, modules, bytes_needed, &bytes_needed) == 0) {
#ifdef DEBUG
      printf("Failed to enumerate process modules. Error code: %d\n",
             GetLastError());
#endif
      return NULL;
    }
  }

  // iterate over each of the modules until we find one whose name matches our
  // target module
  char module_name[200];
  HMODULE target_module = NULL;
  for (int ii = 0; ii < modules_needed; ii++) {
    if (GetModuleFileNameExA(proc, modules[ii], module_name,
                             sizeof(module_name) / sizeof(module_name[0])) ==
        0) {
#ifdef DEBUG
      printf("Failed to get module file name: %d\n", GetLastError());
#endif
      return NULL;
    }
    // found our target module
    if (_stricmp(target_module_name, module_name) == 0) {
      target_module = modules[ii];
      break;
    }
  }
  free(modules);
  return target_module;
}

DWORD_PTR get_remote_proc_address(HANDLE proc, const char *target_module_name,
                                  const char *target_function_name) {

  DWORD_PTR module_base =
      (DWORD_PTR)get_remote_module(proc, target_module_name);

  if (module_base == NULL) {
#ifdef DEBUG
    printf("Failed to find module %s in process modules\n", target_module_name);
#endif
    return FALSE;
  }

  // now load the module into a buffer in our address space so we can explore it
  // and find the RVA of our target function

  // should be big enough for most modules? we'll see
  size_t bufsize = 0x200000;
  char *module_buffer = (char *)malloc(bufsize);

  // read module into our buffer
  ReadProcessMemory(proc, (LPCVOID)module_base, module_buffer, bufsize, NULL);

  DWORD_PTR start_addr = (DWORD_PTR)module_buffer;

  // get to exports
  PIMAGE_NT_HEADERS pe_headers = (PIMAGE_NT_HEADERS)(
      start_addr + ((PIMAGE_DOS_HEADER)start_addr)->e_lfanew);

  PIMAGE_DATA_DIRECTORY export_directory = (PIMAGE_DATA_DIRECTORY)(
      &((pe_headers)
            ->OptionalHeader.DataDirectory)[IMAGE_DIRECTORY_ENTRY_EXPORT]);

  PIMAGE_EXPORT_DIRECTORY export_table =
      (PIMAGE_EXPORT_DIRECTORY)(export_directory->VirtualAddress + start_addr);

  // get different export tables
  LPDWORD address_table =
      (LPDWORD)(start_addr + export_table->AddressOfFunctions);
  LPDWORD name_pointer_table =
      (LPDWORD)(start_addr + export_table->AddressOfNames);
  LPWORD ordinal_table =
      (LPWORD)(start_addr + export_table->AddressOfNameOrdinals);

  DWORD_PTR func_addr = NULL;
  for (unsigned int ii = 0; ii < export_table->NumberOfNames; ii++) {
    // found the function
    if (strcmp((char *)(start_addr + *name_pointer_table),
               target_function_name) == 0) {
      func_addr = (module_base + address_table[*ordinal_table]);
      break;
    }
    name_pointer_table++;
    ordinal_table++;
  }
  free(module_buffer);
  return func_addr;
}

HANDLE find_alertable_thread(HANDLE proc, DWORD permissions) {
  // thread iterator
  THREADENTRY32 thread_entry;
  HANDLE to_return = NULL;
  HANDLE thread_handle = NULL;
  thread_entry.dwSize = sizeof(THREADENTRY32);
  DWORD pid = GetProcessId(proc);

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  // iterate over processes in snapshot
  if (Thread32First(snapshot, &thread_entry)) {
    do {
      // skip if this is not a thread for the process we care about
      if (thread_entry.th32OwnerProcessID != pid) {
        continue;
      }
      thread_handle = OpenThread(permissions, FALSE, thread_entry.th32ThreadID);
      if (thread_handle != NULL) {
        if (thread_alertable(thread_handle, proc)) {
          to_return = thread_handle;
          break;
        }
        CloseHandle(thread_handle);
      }
    } while (Thread32Next(snapshot, &thread_entry));
  }
  CloseHandle(snapshot);
  return to_return;
}

BOOL thread_alertable(HANDLE thread, HANDLE proc) {
  if (SuspendThread(thread) == -1) {
#ifdef DEBUG
    printf("Failed to suspend thread to get thread context: %d\n",
           GetLastError());
#endif
    return FALSE;
  }
  CONTEXT thread_context = {0};
  thread_context.ContextFlags = CONTEXT_FULL;
  if (GetThreadContext(thread, &thread_context) == 0) {
#ifdef DEBUG
    printf("Failed to get thread context: %d\n", GetLastError());
#endif
    if (ResumeThread(thread) == -1) {
#ifdef DEBUG
      printf("Failed to resume thread: %d\n", GetLastError());
#endif
      return FALSE;
    }
  };

  struct func_with_module fwm;
  DWORD64 func_addr;
  for (int ii = 0;
       ii < sizeof(alertable_functions) / sizeof(alertable_functions[0]);
       ii++) {
    fwm = alertable_functions[ii];
    func_addr = get_remote_proc_address(proc, fwm.module_name, fwm.func_name);
    // in all of these functions, this is where the thread waits
    BOOL alertable = FALSE;
    if (func_addr + 0x14 == thread_context.Rip) {
      // now we must check if the alertable parameter of the corresponding
      // function is true, kind have to hard-code this
      // We can figure out which registers to check based on the declaration of
      // the function, since parameters go Rcx -> Rdx -> R8 -> R9 -> stack[5]
      // onwards

      if (strcmp(fwm.func_name, "NtDelayExecution") == 0) {
        alertable = thread_context.Rcx & TRUE;
      } else if (strcmp(fwm.func_name, "NtWaitForSingleObject") == 0) {
        alertable = thread_context.Rdx & TRUE;
      } else if (strcmp(fwm.func_name, "NtWaitForMultipleObjects") == 0) {
        alertable = thread_context.R9 & TRUE;
      } else if (strcmp(fwm.func_name, "NtSignalAndWaitForSingleObject") == 0) {
        alertable = thread_context.R8 & TRUE;
      } else if (strcmp(fwm.func_name, "NtUserMsgWaitForMultipleObjectsEx") ==
                 0) {
        DWORD_PTR p[6];
        // reading stack
        ReadProcessMemory(proc, (LPVOID)thread_context.Rsp, p, sizeof(p), NULL);
        alertable = p[5] & MWMO_ALERTABLE;
      }
    }
    if (!alertable) {
      // keep alertable thread suspended, resume the rest
      if (ResumeThread(thread) == -1) {
#ifdef DEBUG
        printf("Failed to resume thread: %d\n", GetLastError());
#endif
        return FALSE;
      }
    } else {
      return TRUE;
    }
  }
  return FALSE;
}
