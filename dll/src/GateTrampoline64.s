;
; GateTrampoline64.s
;
; DoSyscall function implementation for 64-bit Windows to perform system calls with arguments passed as an array.
;  NTSTATUS DoSyscall(VOID *fn, DWORD dwSyscallNr, ULONG_PTR *lpArgs, DWORD dwNumberOfArgs);
;
; Authors:
;  Christophe De La Fuente <christophe_delafuente[at]rapid7[dot]com>  - Original implementation
;  Muzaffer Umut ŞAHİN <mailatmayinlutfen[at]gmail[dot]com>           - Argument as array modification
;  Diego Ledda <diego_ledda[at]rapid7[dot]com>                        - Argument as array porting and cleanup
;
    .intel_syntax noprefix

    .global DoSyscall

    .text
DoSyscall:
  push r11                     # store r11 on stack to be able to restore it later
  push r12                     # store r12 on stack to be able to restore it later
  push r13                     # store r13 on stack to be able to restore it later
  push r14                     # store r14 on stack to be able to restore it later
  push r15                     # store r15 on stack to be able to restore it later
  mov r15, rsp                 # save the current stack pointer in r15
  mov r11, rcx                 # move the function pointer (first argument) into r11
  mov r14, rdx                 # move the syscall number (second argument) into r14
  mov r12, r8                  # move the pointer to the arguments (third argument) into r12
  mov r13, r9                  # move the number of arguments (fourth argument) into r13               # if no arguments, jump to no_args
  lea r12, [r12 + r13 * 8 - 8] # point r12 to the last argument
  cmp r13, 4
  jle _setup_registers        # if there are 4 or fewer arguments, jump to setup_4_registers
_setup_stack:
  push [r12]                   # push the last argument onto the stack
  dec r13
  sub r12, 8
  cmp r13, 4
  jne _setup_stack             # repeat until all arguments are pushed onto the stack
_setup_registers:
  cmp r13, 4
  je _setup_4_registers          # if there are exactly 4 arguments, jump to setup_4_registers
  cmp r13, 3
  je _setup_3_registers          # if there are exactly 3 arguments, jump
  cmp r13, 2
  je _setup_2_registers          # if there are exactly 2 arguments, jump
  cmp r13, 1
  je _setup_1_register           # if there is exactly 1 argument, jump
  jmp _no_args                   # if there are no arguments, jump to no_args
_setup_4_registers:
  mov r9, [r12]
  sub r12, 8
_setup_3_registers:
  mov r8, [r12]
  sub r12, 8
_setup_2_registers:
  mov rdx, [r12]
  sub r12, 8
_setup_1_register:
  mov rcx, [r12]               # move the first argument into rcx for the syscall
_no_args:
  push r9                      # push r9 shadow stack
  push r8                      # push r8 shadow stack
  push rdx                     # push rdx shadow stack
  push rcx                     # push rcx shadow stack
  mov r10, rcx
  mov rax, r14                 # move the syscall number into rax for the syscall
  call r11                     # call the syscall function pointer in r11
  mov rsp, r15                 # restore the original stack pointer from r15
  pop r15                      # restore r15 from stack
  pop r14                      # restore r14 from stack
  pop r13                      # restore r13 from stack
  pop r12                      # restore r12 from stack
  pop r11                      # restore r11 from stack
  ret