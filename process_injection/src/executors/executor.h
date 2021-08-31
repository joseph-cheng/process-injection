#pragma once
#include "memory_writers/memory_writer.h"
#include <windows.h>

// Abstract base class for executors
class Executor {
public:
  virtual ~Executor(){};
  virtual BOOL execute(MemoryWriter *mw, LPVOID data_to_write,
                       DWORD data_size) = 0;
};
