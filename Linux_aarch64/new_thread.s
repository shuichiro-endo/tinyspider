//
// Title:  new_thread.s
// Author: Shuichiro Endo
//

.global new_thread

new_thread:
    mov x1, x0
    movz x0, #0x50f
    lsl x0, x0, #0x8
    mov w8, #0xdc   // clone 220
    svc #0x0
    cbnz x0, new_thread_exit
    mov x1, sp
    ldr x30, [sp]

new_thread_exit:
    ret
