#include "memory_writers/memset.h"
#include "util.h"
#include <synchapi.h>

#ifdef DEBUG
#include <errhandlingapi.h>
#include <stdio.h>
#endif

Memset::Memset(HANDLE target_process) { this->target_process = target_process; }

Memset::~Memset() {}

DWORD_PTR Memset::write(LPVOID data_to_write, DWORD size,
                        DWORD_PTR preferred_addr, ULONG permissions) {

  int count = 0;
  HANDLE alertable_thread = NULL;
  while (count < 20 && alertable_thread == NULL) {
    alertable_thread = find_alertable_thread(
        this->target_process, THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                  THREAD_SUSPEND_RESUME |
                                  THREAD_QUERY_INFORMATION);
    count++;
    Sleep(500);
  }
  if (alertable_thread == NULL) {
#ifdef DEBUG
    printf("Failed to find alertable thread in target process\n");
#endif
    return NULL;
  }

#ifdef DEBUG
  printf("Found alertable thread TID %x\n", GetThreadId(alertable_thread));
#endif

  NtQueueApcThread_t NtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(
      GetModuleHandleA("ntdll"), "NtQueueApcThread");

  DWORD_PTR addr_to_write;
  // what address should we write at?
  if (preferred_addr == NULL) {
    addr_to_write =
        (DWORD_PTR)VirtualAllocEx(this->target_process, NULL, size,
                                  MEM_COMMIT | MEM_RESERVE, permissions);
    if (addr_to_write == NULL) {
#ifdef DEBUG
      printf("Failed to allocate memory in target process. Error code: %d\n",
             GetLastError());
#endif
      return NULL;
    }
  } else {
    addr_to_write = preferred_addr;
  }

  PVOID memset_addr = (PVOID)get_remote_proc_address(
      this->target_process, "C:\\Windows\\System32\\ntdll.dll", "memset");

  NTSTATUS result;
  for (unsigned int ii = 0; ii < size; ii++) {

    // write each byte one at a time
    result = NtQueueApcThread(alertable_thread, memset_addr,
                              (PVOID)(addr_to_write + ii),
                              (PVOID)(*((BYTE *)data_to_write + ii)), 1);

    if (result != 0) {
#ifdef DEBUG
      printf("Failed to queue APC: %x\n", result);
#endif
      return NULL;
    }
  }

  ResumeThread(alertable_thread);
  return addr_to_write;
}

BOOL Memset::has_address_control() { return TRUE; }
