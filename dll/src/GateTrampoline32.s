#
# GateTrampoline32.s
#
# DoSyscall function implementation for 32-bit Windows to perform system calls with arguments passed as an array.
#  NTSTATUS DoSyscall(VOID *fn, DWORD dwSyscallNr, ULONG_PTR *lpArgs, DWORD dwNumberOfArgs);
#
# Authors:
#  Christophe De La Fuente <christophe_delafuente[at]rapid7[dot]com>  - Original implementation
#  Muzaffer Umut ŞAHİN <mailatmayinlutfen[at]gmail[dot]com>           - Argument as array modification
#  Diego Ledda <diego_ledda[at]rapid7[dot]com>                        - Argument as array porting and cleanup
#
    .intel_syntax noprefix

    .global _DoSyscall

    .text
_DoSyscall:
  push ebx                     # store ebx on stack to be able to restore it later
  push esi                     # store esi on stack to be able to restore it later
  push edi                     # store edi on stack to be able to restore it later
  push ebp                     # store ebp on stack to be able to restore it later
  mov ebp, esp                 # save the current stack pointer in ebp
  mov edi, [ebp + 0x14]        # move the function pointer (first argument) into edi
  mov esi, [ebp + 0x18]        # move the syscall number (second argument) into esi
  mov ebx, [ebp + 0x1C]        # move the pointer to the arguments (third argument) into ebx
  mov ecx, [ebp + 0x20]        # move the number of arguments (fourth argument) into ecx
  test ecx, ecx                # if no arguments, jump to _no_args
  je _no_args
  lea ebx, [ebx + ecx * 4 - 4] # point ebx to the last argument
_push_args:
  push [ebx]                   # push the argument onto the stack
  sub ebx, 4
  dec ecx
  jnz _push_args               # repeat until all arguments are pushed onto the stack
_no_args:
  mov eax, esi                 # move the syscall number into eax for the syscall
  call edi                     # call the syscall function pointer in edi
  mov esp, ebp                 # restore the original stack pointer from ebp
  pop ebp                      # restore ebp from stack
  pop edi                      # restore edi from stack
  pop esi                      # restore esi from stack
  pop ebx                      # restore ebx from stack
  ret

