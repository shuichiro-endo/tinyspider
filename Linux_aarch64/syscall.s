//
// Title:  syscall.s
// Author: Shuichiro Endo
//

.global syscall

syscall:
    mov w8, w6
    svc #0x0
    ret
