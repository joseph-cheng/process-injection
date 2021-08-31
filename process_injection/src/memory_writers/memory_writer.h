#pragma once
#include <windows.h>

// abstract base class for memory writers
class MemoryWriter {
protected:
  HANDLE target_process;

public:
  virtual ~MemoryWriter(){};
  virtual DWORD_PTR write(LPVOID data_to_write, DWORD data_size,
                          DWORD_PTR preferred_addr, ULONG permissions) = 0;
  HANDLE get_target_process();
  virtual BOOL has_address_control() = 0;
};
