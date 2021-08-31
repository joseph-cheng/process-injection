global test_func
export test_func

section .text
test_func:
  pop rcx
  pop rsp
  ret
