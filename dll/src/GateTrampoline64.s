    .intel_syntax noprefix

    .global DoSyscall

    .text
DoSyscall:

  push r11                     # store r11 on stack to be able to restore it later
  push r12                     # store r12 on stack to be able to restore it later
  push r13                     # store r13 on stack to be able to restore it later

  add rsp, 0x40                # restore the stack pointer to the previous stack frame
  mov r11, [rsp+0x10]          # get the pointer to the Syscall structure that has been stored in the shadow space

  mov r10, [r11+0x10]          # store the syscall stub in r10. Note that the `.pStub` field is padded with 4 null bytes on x64.
  mov [rsp], r10               # place the stub address on the stack, which will be used as return address

  mov rcx, rdx                 # Arg1 is the pointer to the Syscall structure and we don't need it.
  mov rdx, r8                  #   We need to shift all the arguments to have the correct arguments for the syscall.
  mov r8, r9                   #   This meens, rdx move to rcx, r8 to rdx, r9 to r8 and first argument on the stack
  mov r9, [rsp+0x30]           #   to r9.

  # Now, if the syscall needs more than 4 arguments, we need to deal with arguments stored on the stack
  xor r12, r12
  mov r12d, dword ptr [r11+4]  # store the number of arguments in r12, which will be our counter
  cmp r12, 4                   # we already processed 4 arguments, so, check if we have more
  jle _end                     # we have less than 4 arguments, jump directly to _end
  sub r12, 4                   # adjust the argument counter
  xor r13, r13                 # zero out r13, this will be the index

_loop:
  mov r10, [rsp+0x38+8*r13]    # get the argument
  mov [rsp+0x30+8*r13], r10    # store it to the correct location
  inc r13                      # increment the index
  cmp r13, r12                 # check if we have more arguments to process
  jl _loop                     # loop back to process the next argument

_end:
  mov r10, rcx                 # store the first argument to r10, like the original syscall do
  xor rax, rax                 # zero out rax
  mov eax, dword ptr [r11+8]   # store the syscall number to eax

  mov r13, [rsp-0x40]          # restore r13
  mov r12, [rsp-0x38]          # restore r12
  mov r11, [rsp-0x30]          # restore r11
  ret                          # return to the stub

