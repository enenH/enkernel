#ifndef DFM_FILE_IO_H
#define DFM_FILE_IO_H

#include <linux/types.h>

int dfm_file_io_init(void);
void dfm_file_io_exit(void);

long dfm_file_read(void __user *arg);
long dfm_file_write(void __user *arg);

#endif /* DFM_FILE_IO_H */
