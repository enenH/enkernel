/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DFM_FILE_OBSERVER_H
#define DFM_FILE_OBSERVER_H

#include <linux/types.h>

struct file;
long dfm_file_observer_open(struct file *owner, void __user *arg);

#endif
