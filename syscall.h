#ifndef SYSCALL_H
#define SYSCALL_H

#include <linux/types.h>

struct pt_regs;

int  syscall_hook_init(void);
void syscall_hook_exit(void);
int  syscall_hook_nr(void);

#endif /* SYSCALL_H */
