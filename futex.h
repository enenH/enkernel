/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DFM_FUTEX_H
#define DFM_FUTEX_H
#include <linux/types.h>
struct file;
long dfm_futex_waiters(struct file *owner, void __user *arg);
long dfm_futex_validate(struct file *owner, void __user *arg);
void dfm_futex_release(struct file *owner);
long dfm_capabilities(void __user *arg);
#endif
