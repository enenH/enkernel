#ifndef DFM_HWB_H
#define DFM_HWB_H

#include <linux/types.h>

struct file;

long dfm_hwb_info(void __user *arg);
long dfm_hwb_slots(void __user *arg);
long dfm_hwb_set(struct file *owner, void __user *arg);
long dfm_hwb_read(void __user *arg);
long dfm_hwb_clear(void);
void dfm_hwb_release_owner(struct file *owner);
void dfm_hwb_exit(void);

#endif /* DFM_HWB_H */
