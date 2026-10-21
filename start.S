// Entry point, syscall gadget and the jump into the guest.

    .text

    .globl _start
    .type _start, %function
_start:
    mov x0, sp
    mov x29, xzr
    mov x30, xzr
    bl burrow_main
    brk #0

// The only syscall instruction Burrow's filter lets through untrapped.
    .balign 16
    .globl burrow_gadget
    .type burrow_gadget, %function
burrow_gadget:
    svc #0
    ret

// burrow_jump(entry, sp): starts the guest on the stack the kernel built.
    .globl burrow_jump
    .type burrow_jump, %function
burrow_jump:
    mov sp, x1
    mov x16, x0
    mov x0, xzr // no rtld_fini
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x29, xzr
    mov x30, xzr
    br x16

    .section .note.GNU-stack, "", %progbits
