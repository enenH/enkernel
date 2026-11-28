/* SPDX-License-Identifier: GPL-2.0-only */
/* Relocation-free fixture copied to the child's private RX page.
 * x0 = value, x1 = vector input, x2 = vector output.
 * Preserve the caller's ABI-saved D8-D15 and FP control/status. */
.text
.balign 16
.global dfm_pte_vector_begin
.global dfm_pte_vector_point
.global dfm_pte_vector_end
.type dfm_pte_vector_begin, %function
dfm_pte_vector_begin:
    sub sp, sp, #80
    stp d8, d9, [sp, #0]
    stp d10, d11, [sp, #16]
    stp d12, d13, [sp, #32]
    stp d14, d15, [sp, #48]
    mrs x3, fpcr
    str x3, [sp, #64]
    mrs x3, fpsr
    str x3, [sp, #72]
.macro LOAD_PAIR lo, hi, offset
    ldp q\lo, q\hi, [x1, #\offset]
.endm
    LOAD_PAIR 0, 1, 0
    LOAD_PAIR 2, 3, 32
    LOAD_PAIR 4, 5, 64
    LOAD_PAIR 6, 7, 96
    LOAD_PAIR 8, 9, 128
    LOAD_PAIR 10, 11, 160
    LOAD_PAIR 12, 13, 192
    LOAD_PAIR 14, 15, 224
    LOAD_PAIR 16, 17, 256
    LOAD_PAIR 18, 19, 288
    LOAD_PAIR 20, 21, 320
    LOAD_PAIR 22, 23, 352
    LOAD_PAIR 24, 25, 384
    LOAD_PAIR 26, 27, 416
    LOAD_PAIR 28, 29, 448
    LOAD_PAIR 30, 31, 480
    ldr w3, [x1, #512]
    msr fpcr, x3
    ldr w3, [x1, #516]
    msr fpsr, x3
dfm_pte_vector_point:
    add x0, x0, #1
.macro STORE_PAIR lo, hi, offset
    stp q\lo, q\hi, [x2, #\offset]
.endm
    STORE_PAIR 0, 1, 0
    STORE_PAIR 2, 3, 32
    STORE_PAIR 4, 5, 64
    STORE_PAIR 6, 7, 96
    STORE_PAIR 8, 9, 128
    STORE_PAIR 10, 11, 160
    STORE_PAIR 12, 13, 192
    STORE_PAIR 14, 15, 224
    STORE_PAIR 16, 17, 256
    STORE_PAIR 18, 19, 288
    STORE_PAIR 20, 21, 320
    STORE_PAIR 22, 23, 352
    STORE_PAIR 24, 25, 384
    STORE_PAIR 26, 27, 416
    STORE_PAIR 28, 29, 448
    STORE_PAIR 30, 31, 480
    mrs x3, fpcr
    str w3, [x2, #512]
    mrs x3, fpsr
    str w3, [x2, #516]
    ldr x3, [sp, #64]
    msr fpcr, x3
    ldr x3, [sp, #72]
    msr fpsr, x3
    ldp d8, d9, [sp, #0]
    ldp d10, d11, [sp, #16]
    ldp d12, d13, [sp, #32]
    ldp d14, d15, [sp, #48]
    add sp, sp, #80
    ret
dfm_pte_vector_end:
.size dfm_pte_vector_begin, .-dfm_pte_vector_begin
.section .note.GNU-stack,"",%progbits
