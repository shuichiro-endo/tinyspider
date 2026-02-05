//
// Title:  signal_trampoline.s
// Author: Shuichiro Endo
//

.global signal_trampoline

signal_trampoline:
    mov w8, #0x8b    // rt_sigreturn 139
    svc #0x0
