#ifndef MEM_H
#define MEM_H

#include <linux/types.h>

struct mm_struct;
struct mem_query_access_req;

struct mem_read_ctx {
    pid_t pid;
    struct mm_struct *mm;
};

long mem_get_pid(void __user *arg);
long mem_get_pids(void __user *arg);
long mem_get_module_base(void __user *arg);
long mem_get_module_base2(void __user *arg);
long mem_get_module_path(void __user *arg);
long mem_read(void __user *arg);
long mem_read_cache(void __user *arg);
long mem_query_mapping(void __user *arg);
long mem_query_access(void __user *arg);
int mem_query_access_mm(struct mm_struct *mm, unsigned long addr,
                        struct mem_query_access_req *req);
long mem_query_signal(void __user *arg);
int  mem_read_ctx_init_pid(struct mem_read_ctx *ctx, pid_t pid);
int  mem_read_ctx_init_current(struct mem_read_ctx *ctx, pid_t expected_tgid);
long mem_read_ctx_read(struct mem_read_ctx *ctx, uint64_t addr,
                       void *buf, size_t size);
void mem_read_ctx_release(struct mem_read_ctx *ctx);
long mem_read_kernel(pid_t pid, uint64_t addr, void *buf, size_t size);
long mem_get_tls(void __user *arg);
long mem_get_thread_tid(void __user *arg);
long mem_get_thread_tids(void __user *arg);
long mem_get_thread_stack(void __user *arg);
long mem_execute_pacga(void __user *arg);

int  mem_core_init(void);
void mem_core_exit(void);

#endif /* MEM_H */
