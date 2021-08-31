#include <windows.h>
#include <winuser.h>
#pragma comment(lib, "user32.lib")
#define DLLEXPORT __declspec(dllexport)

BOOLEAN WINAPI DllMain(IN HINSTANCE hDllHandle, IN DWORD nReason,
                       IN LPVOID Reserved) {

  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  BOOLEAN success = TRUE;

  switch (nReason) {
  case DLL_PROCESS_ATTACH:

    success = 1;
    break;
  }

  return success;
}
