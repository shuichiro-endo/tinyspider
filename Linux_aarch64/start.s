//
// Title:  start.s
// Author: Shuichiro Endo
//

.global _start
.extern main

_start:
    ldr x0, [sp]
    mov x1, sp
    add x1, x1, #0x8
    add x2, x0, #0x2
    lsl x2, x2, #0x3
    mov x3, sp
    add x2, x2, x3
    bl main
    mov w8, #0x5e   // exit_group 94
    svc #0x0
