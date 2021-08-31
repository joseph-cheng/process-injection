#pragma once
#include "executors/executor.h"
#include "memory_writers/memory_writer.h"
#include <windows.h>

class LL : public Executor {
public:
  LL();
  ~LL();
  BOOL execute(MemoryWriter *mw, LPVOID data_to_write, DWORD data_size);
};
