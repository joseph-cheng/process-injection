# gargoyle on x64


First, I really recommend reading the [original blogpost](https://lospi.net/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html) or else any of this won't make any sense.

I'll sum up the original x86 gargoyle procedure now so we have a reference:

  1. Get the payload into target process' memory somehow (e.g. `VirtualAllocEx()` + `WriteProcessMemory()`)
  2. Start the gargoyle setup code in the target process somehow (e.g. `CreateRemoteThread()`)
  3. Setup a timer that, when signalled, will trigger a ropchain to allow execution of our payload again
  4. Setup some tail calls of `WaitForSingleObjectEx()` to make our thread alertable so that the APC queued by the timer signalling will actually execute
  5. Call `VirtualProtectEx()` to mark our payload as RW

This x64 variant follows this same structure, but due to certain changes from x86 -> x64, the implementation of some of these things are different.

The biggest change that affected gargoyle for x64 was the removal of the `__stdcall` calling convention. In fact, there is only one calling convention for x64 now: what was originally `__fastcall`. These differ in that `__stdcall` pushed all of the arguments on to the stack, whereas `__fastcall` uses registers `rcx -> rdx -> r8 -> r9` and then spills onto the stack (there are also changes for floating point arguments, but these are not relevant here). Furthermore, in x64 the caller needs to allocate 'shadow space' for the callee. This shadow space should be 32 bytes, and is intended for use by functions to save their arguments to make debugging x64 easier (since the registers holding the parameters may be altered during the execution of the function).

For example, after a `call` into a function that takes 6 arguments, the stack should look like this:

```
------------- TOP OF STACK
return address (8 bytes)
shadow space (32 bytes)
arg5 (8 bytes)
arg6 (8 bytes)
...
```

Since the stack trampoline and tail calls are ROP chains that are intended to call functions, we need to do some extra work to obey the calling convention. We're also going to need some more ROP gadgets. In x64 I found:

  - `pop rcx; pop rsp; ret` in `ieframe.dll`
  - `pop rcx; ret` in `ieframe.dll`
  - `pop rdx; ret` in `ieframe.dll`
  - `pop r8; ret` in `ieframe.dll`
  - `pop r9; ret` in `AdmTmpl.dll`
  - `add rsp, 0x30; ret` in `MSMPEG2ENC.dll`

(Side note: the `pop rcx; pop rsp; ret` gadget in `ieframe.dll` currently faces some CFG issues and so this PoC uses its own DLL from `rop_dll` that has a 16-byte aligned `pop rcx; pop rsp; ret`, although this should be able to be circumvented by calling `SetProcessValidCallTargets()` to make the ROP gadget CFG valid)

For context, here is the stack trampoline used in the original gargoyle PoC:

```c
struct StackTrampoline {
  void* VirtualProtectEx;    // <-- ESP here; ROP gadget rets
  void* return_address;      // Tail-call to gargoyle
  void* current_process;     // First arg to VirtualProtectEx
  void* address;
  uint32_t size;
  uint32_t protections;
  void* old_protections_ptr;
  uint32_t old_protections;  // Last arg to VirtualProtectEx
  void* setup_config;        // First argument to gargoyle
};
```

And this is what the trampoline looks like for this PoC:
```c
struct Trampoline {
  DWORD_PTR pop_rcx_ret_ptr;  // <-- RSP here
  DWORD_PTR proc_handle;
  DWORD_PTR pop_rdx_ret_ptr;
  DWORD_PTR addr;
  DWORD_PTR pop_r8_ret_ptr;
  DWORD_PTR size;
  DWORD_PTR pop_r9_ret_ptr;
  DWORD_PTR new_protection;
  DWORD_PTR VirtualProtectEx_ptr;
  DWORD_PTR add_rsp_30_ret_ptr;
  DWORD_PTR shadow_space1;
  DWORD_PTR shadow_space2;
  DWORD_PTR shadow_space3;
  DWORD_PTR shadow_space4;
  DWORD_PTR old_protection_ptr;
  DWORD_PTR padding;
  DWORD_PTR pop_rcx_ret_ptr2;
  DWORD_PTR gargoyle_arg_ptr;
  DWORD_PTR gargoyle_addr;
  DWORD_PTR padding2;
};
```

When the timer is signalled and executes its ROP gadget (`pop rcx; pop rsp; ret`) `rsp` will point to the `pop_rcx_ret_ptr` attribute of this trampoline before the `ret`.

This ROP chain in this trampoline then pops the first four parameters of `VirtualProtectEx()` into the corresponding registers and `ret`s to `VirtualProtectEx()`

At this point, the stack looks like this:

```
------------- TOP OF STACK
'add rsp, 0x30; ret' ROP gadget address (8 bytes)
shadow space (32 bytes)
arg5 (8 bytes)
padding (8 bytes)
...
```

If you remember the structure of the stack for this calling convention from before, we can see that the stack is set up for a call into `VirtualProtectEx()` and a return to a ROP gadget that shrinks the stack by `0x30` bytes (the 8 bytes of padding are to ensure the stack stays 16-bytes aligned, another x64 invariant we need to uphold).

After `VirtualProtectEx()` returns, the ROP gadget calls `add rsp, 0x30; ret`, which essentially does our cleanup, and means we `ret` when the stack looks like the following:

```
------------- TOP OF STACK
'pop rcx; ret' ROP gadget address (8 bytes)
gargoyle_arg_ptr (8 bytes)
gargoyle_addr (8 bytes)
padding (8 bytes)
...
```

This puts our gargoyle argument into `rcx`, and then `ret`s to our gargoyle setup. We don't need any shadow space here because we have written the gargoyle setup in assembly ourselves and thus can just choose to not use any shadow space (and we also end up pointing the stack to another location).

Now we are in gargoyle, we do pretty much the same things as the original gargoyle PoC: setup our timers, restore the stack trampoline, and call our malicious code. One thing to note is that this code needs to be position independent, and we do this by calling into our `do_load()` function in `reflective_loader.c`, which performs all of the loading we need (doing relocations, resolving imports), and so we are able to actually execute arbitrary code inside our gargoyle PoC because we can use any imported functions we want. In our case, we call into `do_malicious_thing()` which just pops a message box.

After calling our malicious code, we need to back into hiding, meaning we need to setup some tail calls to `WaitForSingleObjectEx()` and then call `VirtualProtectEx()` to make us RW.

To do this, we want to make our stack look like this just before our `jmp` to `VirtualProtectEx` (the empty lines here are simply logical separations, they don't represent any actual stack space, and every non-empty line is 8 bytes unless otherwise specified).

```
------------- TOP OF STACK
'add rsp, 0x30; ret' ROP gadget address
shadow space (32 bytes)
5th param of VirtualProtectEx (lpflOldProtect)
padding

'pop rcx; ret' ROP gadget address
param1 of WaitForSingleObjectEx (timer handle)
'pop rdx; ret' ROP gadget address
param2 of WaitForSingleObjectEx (timer period)
'pop r8; ret' ROP gadget address
param3 of WaitForSingleObjectEx (alertable)
addr of WaitForSingleObjectEx
'add rsp, 0x30; ret' ROP gadget address
shadow space (32 bytes)
padding
padding

'pop rcx; ret' ROP gadget address
param1 of WaitForSingleObjectEx (timer handle)
'pop rdx; ret' ROP gadget address
param2 of WaitForSingleObjectEx (timer period)
'pop r8; ret' ROP gadget address
param3 of WaitForSingleObjectEx (alertable)
addr of WaitForSingleObjectEx
padding
shadow space (32 bytes)
...
```

Our call to `VirtualProtectEx()` works just like the one in our trampoline. Then, our calls to `WaitForSingleObjectEx()` use a ROP chain to get our arguments into our registers, and after we make the first call, our stack looks like this:

```
------------- TOP OF STACK
'add rsp, 0x30; ret' ROP gadget address
shadow space (32 bytes)
padding
padding
...
```

The only purpose the `padding` serves here is so that the `add rsp, 0x30` doesn't erase the first 16 bytes of our next tail call. Another option might be to find a rop gadget for `add rsp, 0x20; ret` and get rid of this padding.

Finally, we have our second call to `WaitForSingleObjectEx()`, which works just as our first call did, except we will never return from this call, we will just wait until an APC is queued (which the timer signalling will do), so the stack immediately after our call looks like this:

```
------------- TOP OF STACK
ret address placeholder
shadow space (32 bytes)
```

Since we never return, we don't have anything we want to return to, so we just have some placeholder bytes, and finally our shadow space in case `WaitForSingleObjectEx()` uses it.












