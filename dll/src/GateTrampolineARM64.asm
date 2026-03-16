;
; ARM64 Syscall Trampoline for Reflective DLL Injection
; Microsoft ARM64 Assembler (armasm64.exe) syntax.
;
    AREA    |.text|, CODE, READONLY, ALIGN=3
    EXPORT  DoSyscall

; DoSyscall(x0=function_pointer, x1=syscall_number, x2=args_pointer, x3=arg_count)
DoSyscall
    ; Save callee-saved registers and link register
    STP     x19, x20, [sp, #-16]!
    STP     x21, x22, [sp, #-16]!
    STP     x23, x30, [sp, #-16]!
    MOV     x19, sp                ; save the current stack pointer in x19

    MOV     x20, x0                ; save function pointer in x20
    MOV     x21, x1                ; save syscall number in x21
    MOV     x22, x2                ; save args pointer in x22
    MOV     x23, x3                ; save arg count in x23

    ; Handle stack arguments (arguments beyond the first 8)
    CMP     x23, #8
    B.LE    _setup_registers
    SUB     x9, x23, #8           ; number of stack arguments
    ADD     x10, x9, #1
    BIC     x10, x10, #1          ; round up to even for 16-byte stack alignment
    SUB     sp, sp, x10, LSL #3   ; allocate stack space
    MOV     x11, #0               ; index = 0
_copy_stack
    ADD     x12, x11, #8          ; offset into args array (skip first 8 reg args)
    LDR     x13, [x22, x12, LSL #3]
    STR     x13, [sp, x11, LSL #3]
    ADD     x11, x11, #1
    CMP     x11, x9
    B.LT    _copy_stack

_setup_registers
    ; Load arguments from array into registers x0-x7 based on arg count
    CMP     x23, #8
    B.LT    _check7
    LDR     x7, [x22, #56]
_check7
    CMP     x23, #7
    B.LT    _check6
    LDR     x6, [x22, #48]
_check6
    CMP     x23, #6
    B.LT    _check5
    LDR     x5, [x22, #40]
_check5
    CMP     x23, #5
    B.LT    _check4
    LDR     x4, [x22, #32]
_check4
    CMP     x23, #4
    B.LT    _check3
    LDR     x3, [x22, #24]
_check3
    CMP     x23, #3
    B.LT    _check2
    LDR     x2, [x22, #16]
_check2
    CMP     x23, #2
    B.LT    _check1
    LDR     x1, [x22, #8]
_check1
    CMP     x23, #1
    B.LT    _do_call
    LDR     x0, [x22]

_do_call
    MOV     x8, x21               ; move the syscall number into x8
    BLR     x20                    ; call the function pointer

    MOV     sp, x19                ; restore the original stack pointer from x19
    LDP     x23, x30, [sp], #16   ; restore x23 and link register
    LDP     x21, x22, [sp], #16   ; restore x21, x22
    LDP     x19, x20, [sp], #16   ; restore x19, x20
    RET

    ALIGN
    END