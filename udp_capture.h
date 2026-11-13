#ifndef DFM_UDP_CAPTURE_H
#define DFM_UDP_CAPTURE_H

void udp_capture_exit(void);
long udp_capture_init(void __user *arg);
/* Versioned, exact target socket binding. Never opens a target fd locally. */
long udp_capture_bind_fd(void __user *arg);
long udp_capture_read(void __user *arg);
long udp_capture_read_v2(void __user *arg);
long udp_capture_stop(void);

#endif
