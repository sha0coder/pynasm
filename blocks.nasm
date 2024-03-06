; python compiled with pynasm

BITS 64

call main
jmp end

do_something:
  push rbp
  mov rbp, rsp
  sub rsp, 32
  mov ecx, [rbp+16]
  mov rax, 1
  leave
  ret

main:
  push rbp
  mov rbp, rsp
  sub rsp, 32
  xor rax, rax
  xor rbx, rbx
  add ebx, 1
  cpuid

while1:
  mov rsi, rax
  mov rdi, 0
  cmp rsi, rdi
  je if2
  jmp else3

if2:
  mov rcx, 0
for5:
  push rcx
  call do_something
  add rsp, 8
  mov rax, rax
  add rcx, 1
  cmp rcx, rbx
  jle for5
  jmp endif4

else3:
  mov rcx, 3
for6:
  push rcx
  call do_something
  add rsp, 8
  mov rax, rax
  add rcx, 1
  cmp rcx, 10
  jle for6

endif4:
  jmp while1

end: