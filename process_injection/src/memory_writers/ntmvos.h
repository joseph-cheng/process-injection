#pragma once
#include "memory_writers/memory_writer.h"
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll")
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

typedef enum _SECTION_INHERIT {
  ViewShare = 1,
  ViewUnmap = 2
} SECTION_INHERIT,
    *PSECTION_INHERIT;

// god bless c++11
using NtCreateSection_t = NTSTATUS (*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                       PLARGE_INTEGER, ULONG, ULONG, HANDLE);
using NtMapViewOfSection_t = NTSTATUS (*)(HANDLE, HANDLE, PVOID *, ULONG_PTR,
                                          SIZE_T, PLARGE_INTEGER, PSIZE_T,
                                          SECTION_INHERIT, ULONG, ULONG);

class NTMVoS : public MemoryWriter {
public:
  NTMVoS(HANDLE target_process);
  ~NTMVoS();
  DWORD_PTR write(LPVOID data_to_write, DWORD size, DWORD_PTR preferred_addr,
                  ULONG permissions);
  BOOL has_address_control();
};
