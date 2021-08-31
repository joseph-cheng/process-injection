This section of the project is used for creating a DLL that holds a rop gadget that gargoyle uses (namely `pop rbx; pop rsp; ret`)

This rop gadget actually does exist in other DLLs (like ieframe.dll and wmp.dll) but they are not valid CFG targets and thus when the APC tries to run the gadget, it fails. I tried to make the target CFG valid explicitly using `SetProcessValidCallTargets()` but ran into some issues and so was unable to get this working.

Injecting our own DLL for the purposes of a ROP gadget is obviously not very good for an offensive tool thats goal is to be stealthy, but this still works to demonstrate the PoC (gargoyle on x64).
