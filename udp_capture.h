#ifndef DFM_UDP_CAPTURE_H
#define DFM_UDP_CAPTURE_H

void udp_capture_exit(void);
long udp_capture_init(void __user *arg);
long udp_capture_read(void __user *arg);
long udp_capture_stop(void);

#endif
