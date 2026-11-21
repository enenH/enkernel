#ifndef DFM_PROCESS_MEM_POLICY_H
#define DFM_PROCESS_MEM_POLICY_H

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/types.h>
#else
#include <stdbool.h>
#include <string.h>
#endif

#define DFM_SYSTEMUI_NAME "com.android.systemui"
#define DFM_APP_PROCESS64 "/system/bin/app_process64"

/* Root's explicit fd delegation is the authorization boundary. Process names
 * alone are mutable and must never authorize arbitrary driver-fd holders. */
static inline bool dfm_sensor_systemui_policy(bool initial_namespace,
        bool consistent_uids, unsigned int uid, bool root_opened_fd,
        bool trusted_executable, const char *name, const char *executable)
{
    return initial_namespace && consistent_uids && uid != 0 &&
           root_opened_fd && trusted_executable && name && executable &&
           !strcmp(name, DFM_SYSTEMUI_NAME) &&
           !strcmp(executable, DFM_APP_PROCESS64);
}

#endif
