#pragma once
#include "memory_writers/memory_writer.h"
#include <windows.h>

class WPM : public MemoryWriter {
public:
  WPM(HANDLE target_process);
  ~WPM();
  DWORD_PTR write(LPVOID data_to_write, DWORD size, DWORD_PTR preferred_addr,
                  ULONG permissions);
  BOOL has_address_control();
};
