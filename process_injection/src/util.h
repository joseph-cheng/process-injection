#pragma once
#include <utility>
#include <windows.h>

struct func_with_module {
  const char *module_name;
  const char *func_name;
};

HMODULE get_remote_module(HANDLE proc, const char *target_module_name);

DWORD_PTR get_remote_proc_address(HANDLE proc, const char *target_module_name,
                                  const char *target_function_name);

std::pair<LPVOID, size_t> load_sections(DWORD_PTR dll_buffer, SIZE_T dll_size);

HANDLE open_process(LPCSTR procname, DWORD permissions, BOOL using_pid);

HANDLE find_alertable_thread(HANDLE proc, DWORD permissions);

BOOL thread_alertable(HANDLE thread, HANDLE proc);
