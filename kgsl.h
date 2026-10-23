#ifndef KGSL_H
#define KGSL_H

#include <linux/uaccess.h>

long kgsl_syncsource_peek(void __user *arg);
long kgsl_query(void __user *arg);
int  kgsl_hide_init(void);
void kgsl_hide_exit(void);

#endif /* KGSL_H */
