#pragma once
#include <Windows.h>

#define DLLEXPORT __declspec(dllexport)

typedef struct {
  DWORD PageAddress;
  DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct {
  WORD Offset : 12;
  WORD Type : 4;
} RELOCATION_TABLE_ENTRY, *PRELOCATION_TABLE_ENTRY;

DWORD_PTR ret_address_wrapper();

wchar_t wide_to_lower(wchar_t c);
char to_lower(char c);
DWORD widestr_hash(wchar_t *str);
DWORD str_hash(char *str, int index);
DWORD stri_hash(char *str, int index);
int find_char(const char *str, char char_to_find);

FARPROC get_module_export(DWORD_PTR dll_base, DWORD function_name_hash);
FARPROC get_function_pointer(DWORD defining_dll_hash, DWORD function_name_hash);

DWORD_PTR do_load();

void call_dll_main(DWORD_PTR base_addr);

DWORD_PTR unhook();

DLLEXPORT void reflective_load();

DLLEXPORT void reflective_load_unhook();
