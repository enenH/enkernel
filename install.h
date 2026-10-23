#ifndef INSTALL_H
#define INSTALL_H

#include <linux/uaccess.h>

int install_fd_to_user(int __user *outp);

#endif /* INSTALL_H */
