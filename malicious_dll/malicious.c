#include "reflective_loader.h"
#include <stdlib.h>
#include <windows.h>
#include <winuser.h>
#pragma comment(lib, "user32.lib")

BOOLEAN WINAPI DllMain(IN HINSTANCE hDllHandle, IN DWORD nReason,
                       IN LPVOID Reserved) {

  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  BOOLEAN success = TRUE;

  switch (nReason) {
  case DLL_PROCESS_ATTACH:

    success = MessageBoxA(NULL, "DLL injected!", "Dll injected!", 0);
    break;
  }

  return success;
}
