#ifndef DFM_PROCESS_MEM_H
#define DFM_PROCESS_MEM_H

#include <linux/types.h>

struct file;
long mem_open_process_mem(struct file *driver_file, void __user *arg);

#endif
