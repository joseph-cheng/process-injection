#include "memory_writers/wpm.h"
#include <memoryapi.h>
#include <windows.h>

#ifdef DEBUG
#include <errhandlingapi.h>
#include <iostream>
#endif

WPM::WPM(HANDLE target_process) { this->target_process = target_process; }

WPM::~WPM() {}

DWORD_PTR WPM::write(LPVOID data_to_write, DWORD size, DWORD_PTR preferred_addr,
                     ULONG permissions) {

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

  // write data to allocated memory
  BOOL success = WriteProcessMemory(this->target_process, (LPVOID)addr_to_write,
                                    data_to_write, size, NULL);
  if (!success) {
#ifdef DEBUG
    std::cerr << "Failed to write data to process memory. Error code: "
              << GetLastError() << std::endl;
#endif
    return NULL;
  }
  return addr_to_write;
}

BOOL WPM::has_address_control() { return TRUE; }
