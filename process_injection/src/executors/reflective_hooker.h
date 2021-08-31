#pragma once
#include "executors/executor.h"
#include "memory_writers/memory_writer.h"
#include <windows.h>

class ReflectiveHooker : public Executor {
private:
  const char *module_to_stomp;
  DWORD_PTR load_module(MemoryWriter *mw);

public:
  ReflectiveHooker(const char *module_to_stomp);
  ~ReflectiveHooker();
  BOOL execute(MemoryWriter *mw, LPVOID data_to_write, DWORD data_size);
};
