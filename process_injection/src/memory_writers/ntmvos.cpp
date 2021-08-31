#include "memory_writers/ntmvos.h"

#ifdef DEBUG
#include <errhandlingapi.h>
#include <iostream>
#endif

NTMVoS::NTMVoS(HANDLE target_process) { this->target_process = target_process; }

NTMVoS::~NTMVoS() {}

// can't write to allocated memory, so preferred_addr is ignored
DWORD_PTR NTMVoS::write(LPVOID data_to_write, DWORD size,
                        DWORD_PTR preferred_addr, ULONG permissions) {
  NTSTATUS result;
  HANDLE section;
  LARGE_INTEGER li_size;
  li_size.QuadPart = size;

  // create section to hold data to write
  // sections are shared, so mapping a view into both this process and the
  // target process means we can write to the view in this process, and the
  // target process can read it in their process

  NtCreateSection_t NtCreateSection = (NtCreateSection_t)GetProcAddress(
      GetModuleHandleA("ntdll"), "NtCreateSection");
  NtMapViewOfSection_t NtMapViewOfSection =
      (NtMapViewOfSection_t)GetProcAddress(GetModuleHandleA("ntdll"),
                                           "NtMapViewOfSection");

  result = NtCreateSection(
      &section, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE,
      NULL, &li_size, permissions, SEC_COMMIT, NULL);

  if (result != 0) {
#ifdef DEBUG
    printf("Failed to create section: %x\n", result);
#endif
    return NULL;
  }

  DWORD_PTR local_start_addr = NULL;
  SIZE_T bytes_mapped = (SIZE_T)size;

  // map section into this process with RW permissions
  // assume that permission is at least PAGE_READWRITE
  result = NtMapViewOfSection(section, NtCurrentProcess(),
                              (PVOID *)&local_start_addr, NULL, size, NULL,
                              &bytes_mapped, ViewUnmap, 0, PAGE_READWRITE);

  if (result != 0) {
#ifdef DEBUG
    printf("Failed to map section into this process: %x\n", result);
#endif
    return NULL;
  }

  DWORD_PTR start_addr = NULL;
  bytes_mapped = (SIZE_T)size;

  // map section into target process with whatever permissions are supplied
  // (e.g. RX)
  result = NtMapViewOfSection(section, this->target_process,
                              (PVOID *)&start_addr, NULL, size, NULL,
                              &bytes_mapped, ViewUnmap, 0, permissions);

  if (result != 0) {
#ifdef DEBUG
    printf("Failed to map section into target process: %x\n", result);
#endif
    return NULL;
  }

  RtlCopyMemory((void *)local_start_addr, data_to_write, size);

  return start_addr;
}

BOOL NTMVoS::has_address_control() { return FALSE; }
