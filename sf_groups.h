#ifndef DFM_SF_GROUPS_H
#define DFM_SF_GROUPS_H

#include <linux/types.h>

long dfm_sf_groups_acquire(void __user *arg);
bool dfm_is_surfaceflinger_caller(void);

#endif /* DFM_SF_GROUPS_H */
