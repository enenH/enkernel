#ifndef SYSCALL_H
#define SYSCALL_H

#include <linux/types.h>

struct pt_regs;

int  syscall_hook_init(void);
void syscall_hook_exit(void);
int  syscall_hook_nr(void);

int  syscall_cpu_clock_init(void);
void syscall_cpu_clock_exit(void);
long syscall_cpu_clock_set_target(void __user *arg);

#endif /* SYSCALL_H */
