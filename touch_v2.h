#ifndef TOUCH_V2_H
#define TOUCH_V2_H

#include <linux/uaccess.h>

long touch_v2_init(void);
long touch_v2_event(void __user *arg);
void touch_v2_release_all(void);
void touch_v2_exit(void);

#endif /* TOUCH_V2_H */
