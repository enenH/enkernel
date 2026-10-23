#ifndef TOUCH_H
#define TOUCH_H

#include <linux/uaccess.h>

long touch_init(void);
long touch_event(void __user *arg);
long touch_get_status(void __user *arg);
void touch_release_all(void);
void touch_exit(void);

#endif /* TOUCH_H */
