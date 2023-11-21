    .intel_syntax noprefix

    .global _DoSyscall

    .text
_DoSyscall:

  mov eax, [esp+0x14]              # get the pointer to Syscall
  mov eax, [eax+4]                 # get the number of arguments
  lea eax, [4*eax]                 # calculate the number of bytes needed to store the arguments
  sub esp, eax                     # make room on the stack for the arguments

  push edi                         # store edi on stack to be able to restore it later
  push ebx                         # store ebx on stack to be able to restore it later
  push ecx                         # store ecx on stack to be able to restore it later

  mov edi, [esp+0x0C+eax]          # save the return address
  mov ebx, [esp+0x20+eax]          # get the pointer to the Syscall structure
  mov ecx, [ebx+4]                 # get the number of arguments (.dwNumberOfArgs)

  mov [esp+0x0C], edi              # place the return address on the stack

  test ecx, ecx                    # check if we have arguments
  jz _end                          # we don't, jump directly to _end
  xor eax, eax                     # zero out eax, this will be the index
  lea edi, [esp+0x0C+4*ecx]        # set the base pointer that will be used in loop

_loop:
  mov edx, [edi+0x18+4*eax]        # get the argument
  mov [esp+0x10+4*eax], edx        # store it to the correct location
  inc eax                          # increment the index
  cmp eax, ecx                     # check if we have more arguments to process
  jl _loop                         # loop back to process the next argument

_end:
  mov eax, ebx                     # save the pointer to the Syscall structure to eax

  pop ecx                          # restore ecx
  pop ebx                          # restore ebx
  pop edi                          # restore edi

  push [eax+0x10]                  # push the syscall stub on the stack
  mov eax, [eax+8]                 # store the syscall number to eax
  ret                              # return to the stub

