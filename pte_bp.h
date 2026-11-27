/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DFM_PTE_BP_H
#define DFM_PTE_BP_H
#include <linux/types.h>
struct file;
long dfm_pte_info(void __user *arg);
long dfm_pte_set(struct file *owner, void __user *arg);
long dfm_pte_read(struct file *owner, void __user *arg);
long dfm_pte_clear(struct file *owner);
void dfm_pte_release(struct file *owner);
void dfm_pte_exit(void);
#endif
