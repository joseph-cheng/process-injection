#pragma once

#include "memory_writers/memory_writer.h"
#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll")

using NtQueueApcThread_t = NTSTATUS (*)(HANDLE, PVOID, PVOID, PVOID, ULONG);

class Memset : public MemoryWriter {
public:
  Memset(HANDLE target_process);
  ~Memset();
  DWORD_PTR write(LPVOID data_to_write, DWORD size, DWORD_PTR preferred_addr,
                  ULONG permissions);
  BOOL has_address_control();
};
