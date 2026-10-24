#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/memblock.h>
#include <linux/rwsem.h>
#include <linux/kallsyms.h>
#include <asm/barrier.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <asm/processor.h>
#include <asm/cache.h>
#ifdef CONFIG_ARM64_PTR_AUTH
#include <asm/pointer_auth.h>
#include <asm/sysreg.h>
#include <asm/cpufeature.h>
#endif

#include "abi.h"
#include "mem.h"

/* ---- pid / module base ---- */

long mem_get_pid(void __user *arg)
{
    struct mem_get_pid_req req;
    struct task_struct *task;
    int found = 0;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    req.name[sizeof(req.name) - 1] = '\0';
    req.out_pid = -1;

    rcu_read_lock();
    for_each_process(task) {
        if (strncmp(task->comm, req.name, TASK_COMM_LEN) == 0) {
            req.out_pid = task->pid;
            found = 1;
            break;
        }
    }
    rcu_read_unlock();

    if (!found)
        return -ESRCH;

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

long mem_get_pids(void __user *arg)
{
    struct mem_get_pids_req req;
    struct task_struct *task;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    req.name[sizeof(req.name) - 1] = '\0';
    req.out_count = 0;
    req.out_total = 0;
    memset(req.out_pids, 0, sizeof(req.out_pids));
    if (req.name[0] == '\0')
        return -EINVAL;

    rcu_read_lock();
    for_each_process(task) {
        if (strncmp(task->comm, req.name, TASK_COMM_LEN) != 0)
            continue;

        if (req.out_count < MEM_GET_PIDS_MAX)
            req.out_pids[req.out_count++] = task->pid;
        ++req.out_total;
    }
    rcu_read_unlock();

    if (req.out_total == 0)
        return -ESRCH;

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

long mem_get_module_base(void __user *arg)
{
    struct mem_get_module_base_req req;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int found = 0;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    req.name[sizeof(req.name) - 1] = '\0';
    req.out_base = 0;
    req.out_size = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    {
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
            if (vma->vm_file) {
                const char *name = vma->vm_file->f_path.dentry->d_name.name;
                if (strstr(name, req.name)) {
                    if (!found) {
                        req.out_base = vma->vm_start;   /* 首个匹配 = 模块基址 */
                        found = 1;
                    }
                    req.out_size = vma->vm_end - req.out_base;  /* 最后一次匹配的 end 决定 size */
                }
            }
        }
    }
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file) {
            const char *name = vma->vm_file->f_path.dentry->d_name.name;
            if (strstr(name, req.name)) {
                if (!found) {
                    req.out_base = vma->vm_start;   /* 首个匹配 = 模块基址 */
                    found = 1;
                }
                req.out_size = vma->vm_end - req.out_base;  /* 最后一次匹配的 end 决定 size */
            }
        }
    }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif

    mmput(mm);
    put_task_struct(task);

    if (!found)
        return -ENOENT;

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

long mem_get_module_base2(void __user *arg)
{
    struct mem_get_module_base2_req req;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int found = 0;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    req.name[sizeof(req.name) - 1] = '\0';
    req.out_base = 0;
    req.out_size = 0;
    if (req.name[0] == '\0')
        return -EINVAL;

    rcu_read_lock();
    task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    {
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
            uint64_t vma_size;
            const char *name;

            if (!vma->vm_file)
                continue;
            name = vma->vm_file->f_path.dentry->d_name.name;
            if (!strstr(name, req.name))
                continue;

            vma_size = (uint64_t)(vma->vm_end - vma->vm_start);
            if (req.max_vma_size && vma_size > req.max_vma_size)
                continue;

            if (!found) {
                req.out_base = vma->vm_start;
                found = 1;
            }
            req.out_size = vma->vm_end - req.out_base;
        }
    }
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        uint64_t vma_size;
        const char *name;

        if (!vma->vm_file)
            continue;
        name = vma->vm_file->f_path.dentry->d_name.name;
        if (!strstr(name, req.name))
            continue;

        vma_size = (uint64_t)(vma->vm_end - vma->vm_start);
        if (req.max_vma_size && vma_size > req.max_vma_size)
            continue;

        if (!found) {
            req.out_base = vma->vm_start;
            found = 1;
        }
        req.out_size = vma->vm_end - req.out_base;
    }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif

    mmput(mm);
    put_task_struct(task);

    if (!found)
        return -ENOENT;
    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

/* Resolve the full d_path of the first mapped module whose backing filename
 * contains req.name.  Unlike mem_get_module_base (which matches on the bare
 * dentry d_name and returns an address), this returns the directory path so
 * user space can read the embedded package name and tell DFM China/Taiwan/Global
 * apart.  Same first-match-wins VMA scan as mem_get_module_base. */
long mem_get_module_path(void __user *arg)
{
    struct mem_get_module_path_req req;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    /* d_path scratch. req.out_path is 256B (all we ship back), so anything
     * larger just feeds strscpy's truncation.  512B leaves headroom for the
     * full app path (Android Zygote paths measure ~130 chars in practice) yet
     * stays well under arm64's 16 KiB kernel stack.  Same pattern as
     * touch_read_probe in touch.c. */
    char pathbuf[512];
    int found = 0;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    req.name[sizeof(req.name) - 1] = '\0';
    req.out_path[0] = '\0';

    rcu_read_lock();
    task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    {
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
            if (vma->vm_file) {
                const char *name = vma->vm_file->f_path.dentry->d_name.name;
                if (strstr(name, req.name)) {
                    char *p = d_path(&vma->vm_file->f_path, pathbuf, sizeof(pathbuf));
                    if (!IS_ERR(p))
                        strscpy(req.out_path, p, sizeof(req.out_path));
                    found = 1;   /* first filename match wins, like get_module_base */
                    break;
                }
            }
        }
    }
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file) {
            const char *name = vma->vm_file->f_path.dentry->d_name.name;
            if (strstr(name, req.name)) {
                char *p = d_path(&vma->vm_file->f_path, pathbuf, sizeof(pathbuf));
                if (!IS_ERR(p))
                    strscpy(req.out_path, p, sizeof(req.out_path));
                found = 1;
                break;
            }
        }
    }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif

    mmput(mm);
    put_task_struct(task);

    if (!found)
        return -ENOENT;

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

/* ---- simple vmap helpers ---- */

#ifndef PAGE_ALIGN_START
#define PAGE_ALIGN_START(x) ((x) & PAGE_MASK)
#endif

#ifndef PAGE_ALIGN_END
#define PAGE_ALIGN_END(x) PAGE_ALIGN(x)
#endif

#define MAX_STACK_U64_COUNT 16
#define MAX_KMALLOC_U64_COUNT (MAX_STACK_U64_COUNT * 32)

struct simple_vmap_pfn_ctx {
    unsigned long *pfns;
    pgprot_t prot;
    unsigned long idx;
};

static int noinline simple_vmap_pfn_apply_to(pte_t *pte, unsigned long addr, void *private)
{
    struct simple_vmap_pfn_ctx *data = private;

    *pte = pfn_pte(data->pfns[data->idx++], data->prot);
    return 0;
}

static void *simple_vmap_pfn(unsigned long *pfns, unsigned long count, pgprot_t prot)
{
    struct simple_vmap_pfn_ctx data = {
        .pfns = pfns,
        .prot = prot,
        .idx = 0
    };
    struct vm_struct *area;

    area = get_vm_area_caller(count * PAGE_SIZE, 0, __builtin_return_address(0));
    if (!area)
        return NULL;

    if (apply_to_page_range(&init_mm, (unsigned long)area->addr,
                            count * PAGE_SIZE, simple_vmap_pfn_apply_to, &data)) {
        free_vm_area(area);
        return NULL;
    }

    return area->addr;
}

static void *simple_mremap(unsigned long phys, size_t size, pgprot_t prot)
{
    unsigned long phys_start = PAGE_ALIGN_START(phys);
    unsigned long phys_end = PAGE_ALIGN_END(phys + size);
    unsigned long count = (phys_end - phys_start) >> PAGE_SHIFT;
    unsigned long offset = phys - phys_start;
    unsigned long *pfns;
    unsigned long stack_pfns[MAX_STACK_U64_COUNT];
    int use_vmalloc = 0;
    void *maped;

    if (count <= MAX_STACK_U64_COUNT) {
        pfns = stack_pfns;
    } else if (count <= MAX_KMALLOC_U64_COUNT) {
        pfns = kmalloc(sizeof(unsigned long) * count, GFP_KERNEL);
        if (!pfns)
            return NULL;
    } else {
        pfns = vmalloc(sizeof(unsigned long) * count);
        if (!pfns)
            return NULL;
        use_vmalloc = 1;
    }

    for (unsigned long i = 0; i < count; i++)
        pfns[i] = PHYS_PFN(phys_start) + i;

    maped = simple_vmap_pfn(pfns, count, prot);

    if (count > MAX_STACK_U64_COUNT) {
        if (use_vmalloc)
            vfree(pfns);
        else
            kfree(pfns);
    }

    if (!maped)
        return NULL;

    return (void *)((unsigned long)maped + offset);
}

static void simple_munmap(void *maped)
{
    unsigned long virt_start = PAGE_ALIGN_START((unsigned long)maped);

    vunmap((void *)virt_start);
}

/* ---- small helpers ---- */

static struct task_struct *mem_find_get_task(pid_t vpid)
{
    struct task_struct *task;

    rcu_read_lock();
    task = pid_task(find_vpid(vpid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();

    return task;
}

/* Local counterpart of __lock_task_sighand's Android 5.10/6.12 protocol.
 * Do not call its kallsyms address indirectly: that entry need not be a valid
 * CFI target. The caller must hold a task reference, not already hold siglock.
 * A non-NULL return holds siglock with IRQs saved; NULL holds no lock.
 * The returned pointer is borrowed only until spin_unlock_irqrestore(). */
static struct sighand_struct *mem_lock_task_sighand(struct task_struct *task,
                                                   unsigned long *irqflags)
{
    struct sighand_struct *sh;

    rcu_read_lock();
    for (;;) {
        sh = rcu_dereference(task->sighand);
        if (!sh) {
            /* Pair with __exit_signal()'s release store of NULL. */
            smp_acquire__after_ctrl_dep();
            rcu_read_unlock();
            return NULL;
        }

        /* SLAB_TYPESAFE_BY_RCU and sighand_ctor() keep this lock usable
         * during the RCU section, even if the object has been recycled.
         * The task association must still be checked AFTER taking it. */
        spin_lock_irqsave(&sh->siglock, *irqflags);
        if (sh == rcu_access_pointer(task->sighand)) {
            rcu_read_unlock();
            return sh;
        }
        spin_unlock_irqrestore(&sh->siglock, *irqflags);
    }
}

long mem_get_tls(void __user *arg)
{
    struct mem_get_tls_req req;
    struct task_struct *task;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    if (req.pid <= 0)
        return -EINVAL;

    req.out_tls = 0;

    task = mem_find_get_task(req.pid);
    if (!task)
        return -ESRCH;

    /* task_user_tls() returns a pointer to thread_struct's saved TPIDR_EL0
     * value, not the TLS value itself. */
    req.out_tls = (uint64_t)*task_user_tls(task);
    put_task_struct(task);

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

static u64 mem_thread_exec_ns(const struct task_struct *thread)
{
    return thread->se.sum_exec_runtime;
}

static u32 mem_thread_sched_flags(const struct task_struct *thread)
{
    u32 flags = 0;

#ifdef CONFIG_SMP
    if (READ_ONCE(thread->on_cpu))
        flags |= MEM_THREAD_TID_F_ON_CPU;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    if (READ_ONCE(thread->__state) == TASK_RUNNING)
        flags |= MEM_THREAD_TID_F_RUNNING;
#else
    if (READ_ONCE(thread->state) == TASK_RUNNING)
        flags |= MEM_THREAD_TID_F_RUNNING;
#endif
    return flags;
}

/* Prefer the thread that is on a CPU right now, then the one that has
 * accumulated the most CFS runtime. Never pick the minimum tid: several
 * UE4 workers share comm "GameThread" and the oldest/lowest tid is often
 * an idle namesake, not the decrypt thread. */
static bool mem_thread_sched_better(int tid, u32 flags, u64 exec_ns,
                                    int best_tid, u32 best_flags, u64 best_exec)
{
    bool on_cpu;
    bool best_on_cpu;

    if (best_tid < 0)
        return true;

    on_cpu = (flags & MEM_THREAD_TID_F_ON_CPU) != 0;
    best_on_cpu = (best_flags & MEM_THREAD_TID_F_ON_CPU) != 0;
    if (on_cpu != best_on_cpu)
        return on_cpu;
    if (exec_ns != best_exec)
        return exec_ns > best_exec;
    return tid > best_tid;
}

long mem_get_thread_tid(void __user *arg)
{
    struct mem_get_thread_tid_req req;
    struct task_struct *task;
    struct task_struct *leader;
    struct task_struct *thread;
    int best_tid = -1;
    u32 best_flags = 0;
    u64 best_exec = 0;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    if (req.pid <= 0)
        return -EINVAL;

    req.comm[sizeof(req.comm) - 1] = '\0';
    if (req.comm[0] == '\0')
        return -EINVAL;

    req.out_tid = -1;

    task = mem_find_get_task(req.pid);
    if (!task)
        return -ESRCH;

    rcu_read_lock();
    leader = task->group_leader;
    for_each_thread(leader, thread) {
        u32 flags;
        u64 exec_ns;

        if (thread == leader)
            continue;
        if (strncmp(thread->comm, req.comm, TASK_COMM_LEN) != 0)
            continue;
        flags = mem_thread_sched_flags(thread);
        exec_ns = mem_thread_exec_ns(thread);
        if (mem_thread_sched_better(thread->pid, flags, exec_ns,
                                    best_tid, best_flags, best_exec)) {
            best_tid = thread->pid;
            best_flags = flags;
            best_exec = exec_ns;
        }
    }
    rcu_read_unlock();

    put_task_struct(task);

    if (best_tid < 0)
        return -ESRCH;

    req.out_tid = best_tid;
    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

long mem_get_thread_tids(void __user *arg)
{
    struct mem_get_thread_tids_req req;
    struct task_struct *task;
    struct task_struct *leader;
    struct task_struct *thread;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    if (req.pid <= 0)
        return -EINVAL;

    req.comm[sizeof(req.comm) - 1] = '\0';
    if (req.comm[0] == '\0')
        return -EINVAL;

    req.out_count = 0;
    req.out_total = 0;
    req.reserved = 0;
    memset(req.out_threads, 0, sizeof(req.out_threads));

    task = mem_find_get_task(req.pid);
    if (!task)
        return -ESRCH;

    rcu_read_lock();
    leader = task->group_leader;
    for_each_thread(leader, thread) {
        if (thread == leader)
            continue;
        if (strncmp(thread->comm, req.comm, TASK_COMM_LEN) != 0)
            continue;

        if (req.out_count < MEM_GET_THREAD_TIDS_MAX) {
            struct mem_thread_tid_info *info =
                &req.out_threads[req.out_count];
            info->tid = thread->pid;
            info->flags = mem_thread_sched_flags(thread);
            info->exec_ns = mem_thread_exec_ns(thread);
            req.out_count++;
        }
        req.out_total++;
    }
    rcu_read_unlock();

    put_task_struct(task);

    if (req.out_total == 0)
        return -ESRCH;

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

#ifdef CONFIG_ANON_VMA_NAME
static bool mem_is_named_thread_stack_vma(struct vm_area_struct *vma,
                                          const char *expected_name)
{
    struct anon_vma_name *anon_name;

    if (vma->vm_file)
        return false;
    if ((vma->vm_flags & (VM_READ | VM_WRITE)) != (VM_READ | VM_WRITE))
        return false;

    /* The Android 15 DDK does not expose anon_vma_name() to external-module
     * headers. Direct access is valid here because the caller holds mmap_lock
     * and vm_file was checked above. */
    anon_name = vma->anon_name;
    return anon_name && strcmp(anon_name->name, expected_name) == 0;
}
#endif

long mem_get_thread_stack(void __user *arg)
{
    struct mem_get_thread_stack_req req;
#ifdef CONFIG_ANON_VMA_NAME
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long tls;
    unsigned long low = 0;
    unsigned long high = 0;
    char expected_name[32];
    bool found = false;
    bool contains_tls = false;
#endif

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.tid <= 0)
        return -EINVAL;

    req.out_named = 0;
    req.out_low = 0;
    req.out_high = 0;
    req.out_tls = 0;

#ifndef CONFIG_ANON_VMA_NAME
    return -EOPNOTSUPP;
#else
    task = mem_find_get_task(req.tid);
    if (!task)
        return -ESRCH;

    tls = (unsigned long)*task_user_tls(task);
    tls = untagged_addr(tls);
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    scnprintf(expected_name, sizeof(expected_name),
              "stack_and_tls:%d", req.tid);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    {
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
            if (!mem_is_named_thread_stack_vma(vma, expected_name))
                continue;
            if (!found) {
                low = vma->vm_start;
                high = vma->vm_end;
                found = true;
            } else if (vma->vm_start <= high) {
                if (vma->vm_end > high)
                    high = vma->vm_end;
            } else {
                /* A per-TID Bionic name must describe one contiguous area. */
                found = false;
                break;
            }
            if (tls >= vma->vm_start && tls < vma->vm_end)
                contains_tls = true;
        }
    }
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (!mem_is_named_thread_stack_vma(vma, expected_name))
            continue;
        if (!found) {
            low = vma->vm_start;
            high = vma->vm_end;
            found = true;
        } else if (vma->vm_start <= high) {
            if (vma->vm_end > high)
                high = vma->vm_end;
        } else {
            found = false;
            break;
        }
        if (tls >= vma->vm_start && tls < vma->vm_end)
            contains_tls = true;
    }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif

    mmput(mm);
    put_task_struct(task);

    if (!found || !contains_tls || low == 0 || high <= low)
        return -ENOENT;

    req.out_named = 1;
    req.out_low = (uint64_t)low;
    req.out_high = (uint64_t)high;
    req.out_tls = (uint64_t)tls;
    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
#endif
}

#ifdef CONFIG_ARM64_PTR_AUTH
/* Emit ARMv8.3 PACGA at the current EL: X8 = PACGA(X8, X9), keyed by
 * whatever APGAKey_EL1 currently holds. Register-pin x8/x9 with GCC's
 * register-asm variables so the compiler places the operands where the
 * encoded PACGA expects them — no shuffle movs, no memory clobber (PACGA
 * touches no memory). Raw .inst avoids a -march=armv8.3-a on the whole TU. */
static __always_inline u64 do_hw_pacga(u64 data, u64 modifier)
{
    register u64 x8 __asm__("x8") = data;
    register u64 x9 __asm__("x9") = modifier;

    /* 0x9AC93108 = pacga x8, x8, x9 */
    asm volatile(".inst 0x9AC93108" : "+r"(x8) : "r"(x9));
    return x8;
}
#endif

/* Run PACGA(data, modifier) with the target task's APGAKey installed on this
 * CPU, then restore. See struct mem_execute_pacga_req in abi.h for the
 * full rationale; the notable bits below are the atomicity and gate.
 *
 * Atomicity: `local_irq_save` keeps us running as `current` for the whole
 * sequence, so the restore key can come straight from `current->thread.
 * keys_user.apga` (the scheduler invariant it enforces on task switch) —
 * no read_sysreg round-trip needed. `isb()` bookends the sysreg writes so
 * the new key is in effect for the following PACGA and the restored key
 * is in effect before we unmask IRQs.
 *
 * Runtime gate: CONFIG_ARM64_PTR_AUTH can be on for address-auth only,
 * without generic-auth silicon; PACGA would UNDEF and take the kernel down.
 * `system_supports_generic_auth()` closes that hole — miss → 0 with
 * `out_supported=0` so user space can fall back cleanly. */
long mem_execute_pacga(void __user *arg)
{
    struct mem_execute_pacga_req req;
    struct task_struct *task;
#ifdef CONFIG_ARM64_PTR_AUTH
    struct ptrauth_key guest_apga = {};
    bool have_generic_auth = false;
#endif

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.pid <= 0)
        return -EINVAL;

    req.out_supported = 0;
    req.out_result = 0;

    task = mem_find_get_task(req.pid);
    if (!task)
        return -ESRCH;

#ifdef CONFIG_ARM64_PTR_AUTH
    have_generic_auth = system_supports_generic_auth();
    if (have_generic_auth)
        guest_apga = task->thread.keys_user.apga;
#endif

    put_task_struct(task);

#ifdef CONFIG_ARM64_PTR_AUTH
    if (have_generic_auth) {
        unsigned long flags;
        u64 result;

        local_irq_save(flags);
        __ptrauth_key_install_nosync(APGA, guest_apga);
        isb();
        result = do_hw_pacga(req.data, req.modifier);
        __ptrauth_key_install_nosync(APGA, current->thread.keys_user.apga);
        isb();
        local_irq_restore(flags);

        req.out_supported = 1;
        req.out_result = result;
    }
#endif

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

static inline size_t size_inside_page(unsigned long addr, size_t count)
{
    size_t remain = PAGE_SIZE - (addr & ~PAGE_MASK);

    return min(remain, count);
}

/* ---- linearmap (NC only) ---- */

struct __linearmap_info {
    unsigned long phys;
    unsigned long size;
    unsigned long virt_nc;
};

static struct __linearmap_info *__linearmap_info_arr = NULL;
static unsigned long __linearmap_info_cnt = 0;
static int __linearmap_info_ok = 0;
static struct rw_semaphore __linearmap_rwlock;
static struct memblock *memblock_ptr = NULL;

static int __map_regions(void)
{
    struct memblock_type *memtype = &memblock_ptr->memory;
    unsigned long curidx = 0;
    pgprot_t prot = __pgprot(PROT_DEFAULT | PTE_PXN | PTE_UXN | PTE_WRITE |
                             PTE_ATTRINDX(MT_NORMAL_NC));

    for (unsigned long i = 0; i < memtype->cnt; i++) {
        struct memblock_region *region = &memtype->regions[i];

        if (region->flags & MEMBLOCK_NOMAP)
            continue;

        if (__linearmap_info_arr[curidx].virt_nc) {
            curidx++;
            continue;
        }

        void *mapped = simple_mremap(region->base, region->size, prot);
        if (!mapped) {
            /* rollback */
            while (curidx > 0) {
                curidx--;
                if (__linearmap_info_arr[curidx].virt_nc) {
                    simple_munmap((void *)__linearmap_info_arr[curidx].virt_nc);
                    __linearmap_info_arr[curidx].virt_nc = 0;
                }
            }
            return -EAGAIN;
        }

        __linearmap_info_arr[curidx].virt_nc = (unsigned long)mapped;
        __linearmap_info_arr[curidx].phys = region->base;
        __linearmap_info_arr[curidx].size = region->size;
        curidx++;
    }

    return 0;
}

/* Caller must hold __linearmap_rwlock for writing */
static void __destroy_linearmap_locked(void)
{
    if (!__linearmap_info_arr)
        return;

    for (unsigned long i = 0; i < __linearmap_info_cnt; i++) {
        if (__linearmap_info_arr[i].virt_nc) {
            simple_munmap((void *)__linearmap_info_arr[i].virt_nc);
            __linearmap_info_arr[i].virt_nc = 0;
        }
    }

    __linearmap_info_ok = 0;

    kfree(__linearmap_info_arr);
    __linearmap_info_arr = NULL;
    __linearmap_info_cnt = 0;
}

static void destroy_linearmap(void)
{
    down_write(&__linearmap_rwlock);
    __destroy_linearmap_locked();
    up_write(&__linearmap_rwlock);
}

static int create_linearmap(void)
{
    struct memblock_type *memtype = &memblock_ptr->memory;
    int retval = 0;

    down_write(&__linearmap_rwlock);

    if (!__linearmap_info_cnt) {
        for (unsigned long i = 0; i < memtype->cnt; i++) {
            if (!(memtype->regions[i].flags & MEMBLOCK_NOMAP))
                __linearmap_info_cnt++;
        }
    }

    if (!__linearmap_info_arr) {
        __linearmap_info_arr = kzalloc(sizeof(*__linearmap_info_arr) * __linearmap_info_cnt, GFP_KERNEL);
        if (!__linearmap_info_arr) {
            up_write(&__linearmap_rwlock);
            return -ENOMEM;
        }
    }

    if (!__linearmap_info_ok) {
        retval = __map_regions();
        if (retval) {
            __destroy_linearmap_locked();
        } else {
            __linearmap_info_ok = 1;
        }
    }

    up_write(&__linearmap_rwlock);
    return retval;
}

static unsigned long ____phys_to_virt_nc(unsigned long pa)
{
    down_read(&__linearmap_rwlock);

    if (!__linearmap_info_arr || !__linearmap_info_ok) {
        up_read(&__linearmap_rwlock);
        return 0;
    }

    for (unsigned long i = 0; i < __linearmap_info_cnt; i++) {
        unsigned long phys = __linearmap_info_arr[i].phys;
        unsigned long size = __linearmap_info_arr[i].size;

        if (pa >= phys && pa < phys + size) {
            unsigned long offset = pa - phys;
            unsigned long base = __linearmap_info_arr[i].virt_nc;

            up_read(&__linearmap_rwlock);
            return base ? (base + offset) : 0;
        }
    }

    up_read(&__linearmap_rwlock);
    return 0;
}

/* ---- follow_phys_fast page table walker ---- */

#ifndef pmd_cont
#define pmd_cont(x) 0
#endif

#ifndef pmd_leaf_size
#define pmd_leaf_size(x) PMD_SIZE
#endif

#ifndef CONT_PMD_SIZE
#define CONT_PMD_SIZE PMD_SIZE
#endif

static unsigned long follow_phys_fast(struct mm_struct *mm, unsigned long virt, size_t *sz)
{
    pgd_t *pgdp = pgd_offset(mm, virt);

    if (pgd_none(*pgdp) || pgd_bad(*pgdp))
        return ~0UL;

    p4d_t *p4dp = p4d_offset(pgdp, virt);
    if (p4d_none(*p4dp) || p4d_bad(*p4dp))
        return ~0UL;

    pud_t *pudp = pud_offset(p4dp, virt);
    if (pud_none(*pudp))
        return ~0UL;

    if (pud_leaf(*pudp)) {
        unsigned long pfn = pud_pfn(*pudp);
        if (!pfn)
            return ~0UL;
        if (sz)
            *sz = PUD_SIZE - (virt & ~PUD_MASK);
        return PFN_PHYS(pfn) | (virt & ~PUD_MASK);
    }

    pmd_t *pmdp = pmd_offset(pudp, virt);
    if (pmd_none(*pmdp))
        return ~0UL;

    if (pmd_leaf(*pmdp)) {
        unsigned long pfn = pmd_pfn(*pmdp);
        unsigned long offset;
        unsigned long grp_size;
        phys_addr_t phys;

        if (!pfn)
            return ~0UL;

        if (pmd_cont(*pmdp)) {
            unsigned long grp_mask = CONT_PMD_MASK;
            unsigned long base_va;
            pmd_t *first;

            grp_size = CONT_PMD_SIZE;
            offset = virt & ~grp_mask;
            base_va = virt & grp_mask;
            first = pmd_offset(pudp, base_va);
            phys = PFN_PHYS(pmd_pfn(*first)) + offset;
        } else {
            grp_size = pmd_leaf_size(*pmdp);
            offset = virt & ~PMD_MASK;
            phys = PFN_PHYS(pfn) | offset;
        }

        if (sz)
            *sz = grp_size - offset;
        return phys;
    }

    pte_t *ptep = pte_offset_kernel(pmdp, virt);
    if (!pte_present(*ptep) || !pte_pfn(*ptep))
        return ~0UL;

    {
        unsigned long pfn = pte_pfn(*ptep);
        unsigned long offset;
        unsigned long grp_size;
        phys_addr_t phys;

        if (pte_cont(*ptep)) {
            unsigned long grp_mask = CONT_PTE_MASK;
            unsigned long base_va;
            pte_t *first;

            grp_size = CONT_PTE_SIZE;
            offset = virt & ~grp_mask;
            base_va = virt & grp_mask;
            first = pte_offset_kernel(pmdp, base_va);
            phys = PFN_PHYS(pte_pfn(*first)) + offset;
        } else {
            grp_size = PAGE_SIZE;
            offset = virt & ~PAGE_MASK;
            phys = PFN_PHYS(pfn) | offset;
        }

        if (sz)
            *sz = grp_size - offset;
        return phys;
    }
}

/* ---- nc_memrw + access_remote_vm_nc ---- */

static ssize_t nc_memrw(struct mm_struct *mm, unsigned long addr, char __user *buf,
                        size_t count, int write)
{
    ssize_t copied = 0;

    while (count > 0) {
        size_t this_len = size_inside_page(addr, count);
        unsigned long phys = follow_phys_fast(mm, addr, &this_len);
        unsigned long virt;
        size_t failed_len;

        if (phys == ~0UL)
            break;

        this_len = min(this_len, count);
        virt = ____phys_to_virt_nc(phys);
        if (!virt)
            break;

        if (!write) {
            failed_len = copy_to_user(buf, (void *)virt, this_len);
            if (failed_len) {
                copied += this_len - failed_len;
                break;
            }
        } else {
            failed_len = copy_from_user((void *)virt, buf, this_len);
            if (failed_len) {
                copied += this_len - failed_len;
                break;
            }
        }

        buf += this_len;
        addr += this_len;
        copied += this_len;
        count -= this_len;
    }

    return copied;
}

/* DminLine: CTR_EL0[19:16]，最小 D/统一 cache 行长(log2 字数)。
 * DC CVAC 一次只清包含该 VA 的那一条 line，by-VA 循环步长必须用最小行长，
 * 否则在 cache_line_size()(最大行长/CWG) > DminLine 的 SoC 上会跳过中间行漏刷。 */
static inline unsigned long dcache_min_line(void)
{
    unsigned long ctr;
    asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
    return 4UL << ((ctr >> 16) & 0xf);
}

static ssize_t nc_memrw_cache(struct mm_struct *mm, unsigned long addr, char __user *buf,
                              size_t count, int write)
{
    ssize_t copied = 0;

    while (count > 0) {
        size_t this_len = size_inside_page(addr, count);
        unsigned long phys = follow_phys_fast(mm, addr, &this_len);
        unsigned long virt;
        size_t failed_len;

        if (phys == ~0UL)
            break;

        this_len = min(this_len, count);
        virt = ____phys_to_virt_nc(phys);
        if (!virt)
            break;

        {
            unsigned long line = dcache_min_line();
            unsigned long c_va = (unsigned long)phys_to_virt(phys);
            unsigned long s = c_va & ~(line - 1);
            unsigned long e = (c_va + this_len + line - 1) & ~(line - 1);
            unsigned long va;

            for (va = s; va < e; va += line)
                asm volatile("dc cvac, %0" : : "r"(va) : "memory");
            asm volatile("dsb sy" : : : "memory");
        }

        if (!write) {
            failed_len = copy_to_user(buf, (void *)virt, this_len);
            if (failed_len) {
                copied += this_len - failed_len;
                break;
            }
        } else {
            failed_len = copy_from_user((void *)virt, buf, this_len);
            if (failed_len) {
                copied += this_len - failed_len;
                break;
            }
        }

        buf += this_len;
        addr += this_len;
        copied += this_len;
        count -= this_len;
    }

    return copied;
}

static ssize_t nc_memread_kernel(struct mm_struct *mm, unsigned long addr, char *buf,
                                 size_t count)
{
    ssize_t copied = 0;

    while (count > 0) {
        size_t this_len = size_inside_page(addr, count);
        unsigned long phys = follow_phys_fast(mm, addr, &this_len);
        unsigned long virt;

        if (phys == ~0UL)
            break;

        this_len = min(this_len, count);
        virt = ____phys_to_virt_nc(phys);
        if (!virt)
            break;

        memcpy(buf, (void *)virt, this_len);

        buf += this_len;
        addr += this_len;
        copied += this_len;
        count -= this_len;
    }

    return copied;
}

static ssize_t access_remote_vm_nc(pid_t vpid, unsigned long target, char __user *buffer,
                                   size_t count, int write)
{
    ssize_t result = -ESRCH;
    struct task_struct *task;
    struct mm_struct *mm;

    task = mem_find_get_task(vpid);
    if (!task)
        return result;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    result = nc_memrw(mm, target, buffer, count, write);

    mmput(mm);
    put_task_struct(task);
    return result;
}

static ssize_t access_remote_vm_nc_cache(pid_t vpid, unsigned long target, char __user *buffer,
                                         size_t count, int write)
{
    ssize_t result = -ESRCH;
    struct task_struct *task;
    struct mm_struct *mm;

    task = mem_find_get_task(vpid);
    if (!task)
        return result;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    result = nc_memrw_cache(mm, target, buffer, count, write);

    mmput(mm);
    put_task_struct(task);
    return result;
}

int mem_read_ctx_init_pid(struct mem_read_ctx *ctx, pid_t pid)
{
    struct task_struct *task;
    struct mm_struct *mm;

    if (!ctx || pid <= 0)
        return -EINVAL;

    ctx->pid = 0;
    ctx->mm = NULL;

    task = mem_find_get_task(pid);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -EINVAL;

    ctx->pid = pid;
    ctx->mm = mm;
    return 0;
}

int mem_read_ctx_init_current(struct mem_read_ctx *ctx, pid_t expected_tgid)
{
    struct mm_struct *mm;

    if (!ctx || expected_tgid <= 0)
        return -EINVAL;

    ctx->pid = 0;
    ctx->mm = NULL;

    if (current->tgid != expected_tgid)
        return -ESRCH;

    mm = get_task_mm(current);
    if (!mm)
        return -EINVAL;

    ctx->pid = expected_tgid;
    ctx->mm = mm;
    return 0;
}

long mem_read_ctx_read(struct mem_read_ctx *ctx, uint64_t addr,
                           void *buf, size_t size)
{
    ssize_t ret;

    if (!ctx || !ctx->mm || !buf)
        return -EINVAL;
    if (size == 0 || size > (4 * 1024 * 1024))
        return -EINVAL;

    ret = nc_memread_kernel(ctx->mm, (unsigned long)addr, buf, size);
    if (ret < 0)
        return ret;
    if ((uint64_t)ret != size)
        return -EFAULT;

    return 0;
}

void mem_read_ctx_release(struct mem_read_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->mm)
        mmput(ctx->mm);
    ctx->pid = 0;
    ctx->mm = NULL;
}

/* ---- read-only mapping identity ---- */

/* Unlike the legacy read walker, mapping identities must be sampled with
 * mmap + leaf-table locks. Do not GUP/fault pages: resolving a COW fault here
 * would change precisely the identity the caller is trying to inspect. */
static int mem_mapping_leaf(struct mem_query_mapping_req *req,
                            struct vm_area_struct *vma, pte_t entry,
                            uint64_t phys, uint64_t granule)
{
    uint64_t attr = pte_val(entry) & PTE_ATTRINDX_MASK;

    /* pte_user() is unavailable on arm64 5.10/5.15. */
    if (!pte_valid(entry) || !(pte_val(entry) & PTE_USER))
        return -ENODATA;
    if (attr != PTE_ATTRINDX(MT_NORMAL) &&
        attr != PTE_ATTRINDX(MT_NORMAL_NC)
#ifdef MT_NORMAL_TAGGED
        && attr != PTE_ATTRINDX(MT_NORMAL_TAGGED)
#endif
        )
        return -EOPNOTSUPP;

    req->out_phys_addr = phys;
    req->out_page_size = granule;
    req->out_flags = 0;
    if (vma->vm_flags & VM_READ) req->out_flags |= MEM_MAPPING_F_READ;
    if (vma->vm_flags & VM_WRITE) req->out_flags |= MEM_MAPPING_F_WRITE;
    if (vma->vm_flags & VM_EXEC) req->out_flags |= MEM_MAPPING_F_EXEC;
    /* A read-only MAP_SHARED file can clear VM_SHARED but retains MAYSHARE. */
    if (vma->vm_flags & VM_MAYSHARE) req->out_flags |= MEM_MAPPING_F_SHARED;
    return 0;
}

static int mem_mapping_locked(struct mm_struct *mm, unsigned long addr,
                              struct mem_query_mapping_req *req)
{
    struct vm_area_struct *vma;
    pgd_t *pgdp;
    p4d_t *p4dp;
    pud_t *pudp, pud;
    pmd_t *pmdp, pmd;
    pte_t *ptep, pte;
    spinlock_t *ptl;
    int ret;

    vma = find_vma(mm, addr);
    if (!vma || addr < vma->vm_start)
        return -ENOENT;
    /* hugetlb has a different locking protocol; device memory is not RAM. */
    if (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP | VM_HUGETLB))
        return -EOPNOTSUPP;

    pgdp = pgd_offset(mm, addr);
    if (pgd_none(READ_ONCE(*pgdp)) || pgd_bad(READ_ONCE(*pgdp)))
        return -ENODATA;
    p4dp = p4d_offset(pgdp, addr);
    if (p4d_none(READ_ONCE(*p4dp)) || p4d_bad(READ_ONCE(*p4dp)))
        return -ENODATA;
    pudp = pud_offset(p4dp, addr);
    ptl = pud_lock(mm, pudp);
    pud = READ_ONCE(*pudp);
    if (pud_leaf(pud)) {
        ret = mem_mapping_leaf(req, vma, __pte(pud_val(pud)),
                ((uint64_t)pud_pfn(pud) << PAGE_SHIFT) +
                    (addr & ~PUD_MASK), PUD_SIZE);
        spin_unlock(ptl);
        return ret;
    }
    ret = pud_none(pud) || pud_bad(pud);
    spin_unlock(ptl);
    if (ret)
        return -ENODATA;

    /* arm64 page tables are lowmem. Hold RCU from BEFORE sampling the PMD
     * until after releasing the PTE lock, then recheck the parent under that
     * lock. This is the lowmem pte_offset_map_lock protocol without depending
     * on __pte_offset_map_lock (not exported to modules on newer kernels).
     * On older kernels mmap_read_lock also prevents table removal. */
    rcu_read_lock();
    pmdp = pmd_offset(pudp, addr);
    ptl = pmd_lock(mm, pmdp);
    pmd = READ_ONCE(*pmdp);
    if (pmd_leaf(pmd)) {
        ret = mem_mapping_leaf(req, vma, __pte(pmd_val(pmd)),
                ((uint64_t)pmd_pfn(pmd) << PAGE_SHIFT) +
                    (addr & ~PMD_MASK), PMD_SIZE);
        spin_unlock(ptl);
        rcu_read_unlock();
        return ret;
    }
    ret = pmd_none(pmd) || pmd_bad(pmd);
    spin_unlock(ptl);
    if (ret) {
        rcu_read_unlock();
        return -ENODATA;
    }

    ptep = pte_offset_kernel(&pmd, addr);
    ptl = pte_lockptr(mm, &pmd);
    spin_lock(ptl);
    if (!pmd_same(pmd, READ_ONCE(*pmdp))) {
        ret = -EAGAIN;
    } else {
        pte = READ_ONCE(*ptep);
        ret = mem_mapping_leaf(req, vma, pte,
                ((uint64_t)pte_pfn(pte) << PAGE_SHIFT) + (addr & ~PAGE_MASK),
                PAGE_SIZE);
    }
    /* Each member of an arm64 contiguous group carries its own PFN. Using
     * that member avoids incorrectly treating a 16/64K native page or a
     * CONT_PTE/CONT_PMD group as a single emulator (4K) page. */
    spin_unlock(ptl);
    rcu_read_unlock();
    return ret;
}

long mem_query_mapping(void __user *arg)
{
    struct mem_query_mapping_req req;
    struct mem_read_ctx ctx;
    unsigned long addr;
    int ret;

    BUILD_BUG_ON(sizeof(req) != 40);
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.pid <= 0 || req.flags || req.reserved)
        return -EINVAL;
    addr = untagged_addr((unsigned long)req.addr);
    /* TASK_SIZE_MAX is unavailable on arm64 5.10. */
    if (addr >= TASK_SIZE_64)
        return -EINVAL;
    req.out_phys_addr = 0;
    req.out_page_size = 0;
    req.out_flags = 0;
    ret = mem_read_ctx_init_pid(&ctx, req.pid);
    if (ret)
        return ret;
    mmap_read_lock(ctx.mm);
    ret = mem_mapping_locked(ctx.mm, addr, &req);
    mmap_read_unlock(ctx.mm);
    mem_read_ctx_release(&ctx);
    if (ret)
        return ret;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

int mem_query_access_mm(struct mm_struct *mm, unsigned long addr,
                        struct mem_query_access_req *req)
{
    struct mem_query_mapping_req physical = {};
    struct vm_area_struct *vma;
    int ret = 0;

    req->out_start = req->out_end = 0;
    req->out_permissions = 0;
    req->out_state = MEM_ACCESS_UNMAPPED;
    mmap_read_lock(mm);
    vma = addr < TASK_SIZE_64 ? find_vma(mm, addr) : NULL;
    if (vma && addr >= vma->vm_start) {
        req->out_start = vma->vm_start;
        req->out_end = vma->vm_end;
        if (vma->vm_flags & VM_READ) req->out_permissions |= MEM_MAPPING_F_READ;
        if (vma->vm_flags & VM_WRITE) req->out_permissions |= MEM_MAPPING_F_WRITE;
        if (vma->vm_flags & VM_EXEC) req->out_permissions |= MEM_MAPPING_F_EXEC;
        if (vma->vm_flags & VM_MAYSHARE) req->out_permissions |= MEM_MAPPING_F_SHARED;
        ret = mem_mapping_locked(mm, addr, &physical);
        if (!ret) req->out_state = MEM_ACCESS_RESIDENT;
        else if (ret == -ENODATA) req->out_state = MEM_ACCESS_NONRESIDENT;
        else if (ret == -EOPNOTSUPP) req->out_state = MEM_ACCESS_UNSUPPORTED;
        else goto out;
        ret = 0;
    }
out:
    mmap_read_unlock(mm);
    return ret;
}

long mem_query_access(void __user *arg)
{
    struct mem_query_access_req req;
    struct mem_read_ctx ctx;
    int ret;

    BUILD_BUG_ON(sizeof(req) != 40);
    if (copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
    if (req.pid <= 0 || req.flags) return -EINVAL;
    ret = mem_read_ctx_init_pid(&ctx, req.pid);
    if (ret) return ret;
    ret = mem_query_access_mm(ctx.mm, untagged_addr((unsigned long)req.addr), &req);
    mem_read_ctx_release(&ctx);
    if (ret) return ret;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

long mem_query_signal(void __user *arg)
{
    struct mem_query_signal_req req;
    struct task_struct *task;
    struct sighand_struct *sighand;
    struct k_sigaction action;
    unsigned long irqflags;
    unsigned long alt_sp, alt_size;
    unsigned int alt_flags;
    int ret = 0;

    BUILD_BUG_ON(sizeof(req) != 72);
    BUILD_BUG_ON(sizeof(sigset_t) != sizeof(uint64_t));
    if (copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
    if (req.tid <= 0 || !req.signo || req.signo > _NSIG) return -EINVAL;
    task = mem_find_get_task(req.tid);
    if (!task) return -ESRCH;
    sighand = mem_lock_task_sighand(task, &irqflags);
    if (!sighand) { put_task_struct(task); return -ESRCH; }
    action = sighand->action[req.signo - 1];
    req.out_handler = (uint64_t)(unsigned long)action.sa.sa_handler;
    req.out_flags = action.sa.sa_flags;
    req.out_restorer = 0;
#ifdef __ARCH_HAS_SA_RESTORER
    req.out_restorer = (uint64_t)(unsigned long)action.sa.sa_restorer;
#endif
    req.out_action_mask = action.sa.sa_mask.sig[0];
    req.out_blocked = task->blocked.sig[0];
    req.out_tgid = task_tgid_vnr(task);
    alt_sp = READ_ONCE(task->sas_ss_sp);
    alt_size = READ_ONCE(task->sas_ss_size);
    alt_flags = READ_ONCE(task->sas_ss_flags);
    req.out_alt_sp = alt_sp;
    req.out_alt_size = alt_size;
    req.out_alt_flags = alt_flags | (alt_size ? 0 : SS_DISABLE);
    /* sigaltstack updates are thread-local, not serialized by siglock. */
    smp_rmb();
    if (alt_sp != READ_ONCE(task->sas_ss_sp) ||
        alt_size != READ_ONCE(task->sas_ss_size) ||
        alt_flags != READ_ONCE(task->sas_ss_flags)) ret = -EAGAIN;
    spin_unlock_irqrestore(&sighand->siglock, irqflags);
    put_task_struct(task);
    if (ret) return ret;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

/* ---- mem_read (linearmap NC) ---- */

long mem_read(void __user *arg)
{
    struct mem_rw_req req;
    ssize_t ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    if (req.size == 0 || req.size > (4 * 1024 * 1024))
        return -EINVAL;

    ret = access_remote_vm_nc(req.pid, req.addr, (char __user *)req.buf, req.size, 0);
    if (ret < 0)
        return ret;
    if ((uint64_t)ret != req.size)
        return -EFAULT;

    return 0;
}

long mem_read_cache(void __user *arg)
{
    struct mem_rw_req req;
    ssize_t ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    if (req.size == 0 || req.size > (4 * 1024 * 1024))
        return -EINVAL;

    ret = access_remote_vm_nc_cache(req.pid, req.addr, (char __user *)req.buf, req.size, 0);
    if (ret < 0)
        return ret;
    if ((uint64_t)ret != req.size)
        return -EFAULT;

    return 0;
}

long mem_read_kernel(pid_t pid, uint64_t addr, void *buf, size_t size)
{
    struct mem_read_ctx ctx;
    long ret;

    if (!buf)
        return -EINVAL;
    if (size == 0 || size > (4 * 1024 * 1024))
        return -EINVAL;

    ret = mem_read_ctx_init_pid(&ctx, pid);
    if (ret)
        return ret;

    ret = mem_read_ctx_read(&ctx, addr, buf, size);
    mem_read_ctx_release(&ctx);
    return ret;
}

/* ---- mem_core init/exit ---- */

int mem_core_init(void)
{
    memblock_ptr = (struct memblock *)kallsyms_lookup_name("memblock");
    if (!memblock_ptr)
        return -ENOENT;

    init_rwsem(&__linearmap_rwlock);

    return create_linearmap();
}

void mem_core_exit(void)
{
    destroy_linearmap();
}
