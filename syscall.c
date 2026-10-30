#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#ifndef __aarch64__
#error "DFM kernel module requires ARM64"
#endif

#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/srcu.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/time64.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/version.h>

#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>
#include <asm-generic/fixmap.h>

#include "abi.h"
#include "install.h"
#include "syscall.h"

#ifndef __nocfi
#define __nocfi
#endif

typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *regs);

static syscall_fn_t *g_sys_call_table;
static syscall_fn_t g_orig_syscall;
static int g_hooked_nr = -1;

static void *syscall_lookup_symbol(const char *symbol_name)
{
    char cfi_name[KSYM_NAME_LEN];
    void *addr;
    size_t symbol_len;
    static const char cfi_suffix[] = ".cfi_jt";
    size_t cfi_suffix_len = sizeof(cfi_suffix) - 1;

    if (!symbol_name || !symbol_name[0])
        return NULL;

    symbol_len = strlen(symbol_name);
    if ((symbol_len < cfi_suffix_len ||
         strcmp(symbol_name + symbol_len - cfi_suffix_len, cfi_suffix) != 0) &&
        strscpy(cfi_name, symbol_name, sizeof(cfi_name)) > 0 &&
        strlen(cfi_name) + cfi_suffix_len + 1 <= sizeof(cfi_name)) {
        /* Linux 6.12 removed strlcat; the prior length check guarantees room,
         * so append via strscpy on the tail (idiomatic post-strlcat). */
        size_t off = strlen(cfi_name);
        strscpy(cfi_name + off, cfi_suffix, sizeof(cfi_name) - off);
        addr = (void *)kallsyms_lookup_name(cfi_name);
        if (addr)
            return addr;
    }

    return (void *)kallsyms_lookup_name(symbol_name);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#define syscall_flush_dcache(start, sz)                         \
    do {                                                    \
        unsigned long __start = (unsigned long)(start);     \
        dcache_clean_inval_poc(__start, __start + (sz));    \
    } while (0)
#else
#define syscall_flush_dcache(start, sz) __flush_dcache_area((void *)(start), (sz))
#endif

struct syscall_patch_text_info {
    void *dst;
    const void *src;
    const void *expected;
    size_t len;
    atomic_t cpu_count;
};

static unsigned long syscall_phys_from_virt(unsigned long addr, int *err)
{
    struct mm_struct *mm = &init_mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    *err = 0;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto fail;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto fail;
#if defined(p4d_leaf)
    if (p4d_leaf(*p4d))
        return __p4d_to_phys(*p4d) + (addr & ~P4D_MASK);
#endif

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto fail;
#if defined(pud_leaf)
    if (pud_leaf(*pud))
        return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
#endif

    pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
    if (pmd_leaf(*pmd))
        return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto fail;

    pte = pte_offset_kernel(pmd, addr);
    if (!pte || !pte_present(*pte))
        goto fail;

    return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);

fail:
    *err = -ENOENT;
    return 0;
}

static int syscall_patch_text_nosync(void *dst, const void *src, size_t len)
{
    unsigned long phys;
    void *map;
    int err;
    int ret;

    phys = syscall_phys_from_virt((unsigned long)dst, &err);
    if (err)
        return err;

    map = (void *)set_fixmap_offset(FIX_TEXT_POKE0, phys);
    ret = (int)copy_to_kernel_nofault(map, src, len);
    clear_fixmap(FIX_TEXT_POKE0);

    if (!ret)
        syscall_flush_dcache(dst, len);

    return ret;
}

static int syscall_patch_text_cb(void *arg)
{
    struct syscall_patch_text_info *info = arg;
    int ret = 0;

    if (atomic_inc_return(&info->cpu_count) == num_online_cpus()) {
        if (info->expected && memcmp(info->dst, info->expected, info->len))
            ret = -EBUSY;
        else
            ret = syscall_patch_text_nosync(info->dst, info->src, info->len);
        atomic_inc(&info->cpu_count);
    } else {
        while (atomic_read(&info->cpu_count) <= num_online_cpus())
            cpu_relax();
        isb();
    }

    return ret;
}

static int syscall_patch_text_expected(void *dst, const void *src,
                                       const void *expected, size_t len)
{
    struct syscall_patch_text_info info = {
        .dst = dst,
        .src = src,
        .expected = expected,
        .len = len,
        .cpu_count = ATOMIC_INIT(0),
    };

    return stop_machine(syscall_patch_text_cb, &info, cpu_online_mask);
}

static int syscall_patch_text(void *dst, const void *src, size_t len)
{
    return syscall_patch_text_expected(dst, src, NULL, len);
}

static int syscall_patch_table(int nr, syscall_fn_t fn)
{
    if (!g_sys_call_table)
        return -ENOENT;
    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;

    return syscall_patch_text(&g_sys_call_table[nr], &fn, sizeof(fn));
}

static asmlinkage long __nocfi syscall_install_handler(const struct pt_regs *regs)
{
    int magic1;
    int magic2;
    int __user *outp;

    if (!regs || current_uid().val > 1000)
        return -ENOSYS;

    magic1 = (int)regs->regs[0];
    magic2 = (int)regs->regs[1];
    if (magic1 != INSTALL_MAGIC1 || magic2 != INSTALL_MAGIC2)
        return -ENOSYS;

    outp = (int __user *)(unsigned long)regs->regs[3];
    return install_fd_to_user(outp);
}

static syscall_fn_t syscall_lookup_ni(void)
{
    syscall_fn_t ni;

    ni = (syscall_fn_t)syscall_lookup_symbol("__arm64_sys_ni_syscall");
    if (ni)
        return ni;

    return (syscall_fn_t)syscall_lookup_symbol("sys_ni_syscall");
}

int syscall_hook_init(void)
{
    syscall_fn_t ni_syscall;
    int i;
    int ret;
    int install_ret = -ENOENT;

    if (g_hooked_nr >= 0)
        return 0;

    g_sys_call_table = (syscall_fn_t *)syscall_lookup_symbol("sys_call_table");
    if (!g_sys_call_table)
        return -ENOENT;

    ni_syscall = syscall_lookup_ni();
    if (!ni_syscall)
        return -ENOENT;

    for (i = 0; i < __NR_syscalls; i++) {
        if (READ_ONCE(g_sys_call_table[i]) != ni_syscall)
            continue;

        ret = syscall_patch_table(i, syscall_install_handler);
        if (ret) {
            install_ret = ret;
            continue;
        }

        g_orig_syscall = ni_syscall;
        g_hooked_nr = i;
        pr_info("syscall install hook registered at nr %d\n", g_hooked_nr);
        return 0;
    }

    return install_ret;
}

void syscall_hook_exit(void)
{
    int ret;

    if (!g_sys_call_table)
        return;

    if (g_hooked_nr >= 0 && g_orig_syscall) {
        ret = syscall_patch_table(g_hooked_nr, g_orig_syscall);
        if (ret)
            pr_err("failed to restore syscall nr %d: %d\n", g_hooked_nr, ret);
        else
            pr_info("syscall install hook restored nr %d\n", g_hooked_nr);
    }

    g_hooked_nr = -1;
    g_orig_syscall = NULL;
}

int syscall_hook_nr(void)
{
    return g_hooked_nr;
}

/* A syscall-table reader may have fetched our address before restoration,
 * and copy_to_user() can sleep. Both Tasks RCU and SRCU are required for
 * teardown; ordinary RCU alone does not protect this call path. */
#if defined(CONFIG_TASKS_RCU) && defined(CONFIG_SRCU)

typedef int (*cpu_clock_get_fn_t)(clockid_t clock, struct timespec64 *ts);

struct cpu_clock_hook {
    syscall_fn_t *slot;
    syscall_fn_t original;
    syscall_fn_t replacement;
    bool installed;
};

struct cpu_clock_identity {
    struct pid *encoded;
    struct pid *tgid;
};

static DEFINE_MUTEX(g_cpu_clock_mutex);
static struct srcu_struct g_cpu_clock_srcu;
static bool g_cpu_clock_srcu_ready;
static struct pid __rcu *g_cpu_clock_target;
static cpu_clock_get_fn_t g_cpu_clock_get;
static struct cpu_clock_hook g_cpu_clock_hooks[3];
static unsigned int g_cpu_clock_hook_count;
static int g_cpu_clock_status = -EOPNOTSUPP;

/* Exact floor(total_nanoseconds / 64), without forming sec * NSEC_PER_SEC.
 * The input is a normalized, nonnegative kernel CPU-clock sample. Scaling
 * the whole cumulative value has no sampling-rate dependence or shared
 * observer state. Enabling/disabling changes the clock's baseline: existing
 * observers must discard their previous sample at that boundary. This only
 * reduces the reported value; it does not remove workload correlations. */
static void cpu_clock_scale(struct timespec64 *ts)
{
    u64 seconds = (u64)ts->tv_sec;

    ts->tv_sec = seconds >> 6;
    ts->tv_nsec = (((seconds & 63U) * NSEC_PER_SEC) +
                   (u64)ts->tv_nsec) >> 6;
}

static bool cpu_clock_match(clockid_t clock, struct cpu_clock_identity *id)
{
    struct pid *target;
    struct pid *encoded;
    struct task_struct *task;
    pid_t nr;
    bool matched = false;

    /* PROF/VIRT/SCHED are 0/1/2. Low bits 3 include dynamic fd clocks and
     * invalid CPU clocks. Positive clocks and PID-zero self clocks pass. */
    if (clock >= 0 || ((u32)clock & 3U) >= 3U)
        return false;
    nr = (pid_t)(~(u32)clock >> 3);
    if (!nr)
        return false;

    rcu_read_lock();
    target = rcu_dereference(g_cpu_clock_target);
    if (!target || target == task_tgid(current))
        goto out;

    /* find_vpid uses the observer's namespace, not the configuring task's
     * namespace. The stored PID object identifies one process instance. */
    encoded = find_vpid(nr);
    task = pid_task(encoded, PIDTYPE_PID);
    if (task && task_tgid(task) == target) {
        id->encoded = get_pid(encoded);
        id->tgid = get_pid(target);
        matched = true;
    }
out:
    rcu_read_unlock();
    return matched;
}

static bool cpu_clock_identity_matches(clockid_t clock,
                                       const struct cpu_clock_identity *id)
{
    struct pid *encoded;
    struct task_struct *task;
    bool matched;

    rcu_read_lock();
    encoded = find_vpid((pid_t)(~(u32)clock >> 3));
    task = pid_task(encoded, PIDTYPE_PID);
    matched = encoded == id->encoded && task && task_tgid(task) == id->tgid;
    rcu_read_unlock();
    return matched;
}

static long cpu_clock_copy_sample(const struct timespec64 *ts,
                                  void __user *out, bool time32)
{
    if (time32) {
        /* ARM EABI clock_gettime32 layout and narrowing match the native
         * put_old_timespec32 implementation, including signed seconds. */
        struct {
            s32 tv_sec;
            s32 tv_nsec;
        } value = { (s32)ts->tv_sec, (s32)ts->tv_nsec };

        return copy_to_user(out, &value, sizeof(value)) ? -EFAULT : 0;
    } else {
        struct __kernel_timespec value = {
            .tv_sec = ts->tv_sec,
            .tv_nsec = ts->tv_nsec,
        };

        return copy_to_user(out, &value, sizeof(value)) ? -EFAULT : 0;
    }
}

static long __nocfi cpu_clock_dispatch(const struct pt_regs *regs,
                                       syscall_fn_t original,
                                       bool compat, bool time32)
{
    struct cpu_clock_identity id;
    struct timespec64 sample;
    void __user *out;
    clockid_t clock;
    long ret;
    int idx;

    idx = srcu_read_lock(&g_cpu_clock_srcu);
    if (!regs) {
        ret = -EINVAL;
        goto out_srcu;
    }
    clock = (clockid_t)regs->regs[0];
    if (!cpu_clock_match(clock, &id)) {
        ret = original(regs);
        goto out_srcu;
    }

    /* This is the kernel's original CPU-clock implementation, so invalid
     * process clocks and foreign-thread clock queries retain their native
     * errors. Never call the original syscall before adjustment: doing so
     * would expose a raw sample in userspace between two writes. */
    ret = g_cpu_clock_get(clock, &sample);
    if (ret)
        goto out_pid;
    /* Holding a PID reference does not reserve its numeric ID. The kernel
     * getter resolves the ID again; reject exit/reuse across that lookup. */
    if (!cpu_clock_identity_matches(clock, &id)) {
        ret = -EINVAL;
        goto out_pid;
    }
    if (sample.tv_sec < 0 || sample.tv_nsec < 0 ||
        sample.tv_nsec >= NSEC_PER_SEC) {
        ret = -EOVERFLOW;
        goto out_pid;
    }
    cpu_clock_scale(&sample);
    out = (void __user *)(unsigned long)regs->regs[1];
#ifdef CONFIG_COMPAT
    if (compat)
        out = compat_ptr((compat_uptr_t)regs->regs[1]);
#endif
    ret = cpu_clock_copy_sample(&sample, out, time32);
out_pid:
    put_pid(id.encoded);
    put_pid(id.tgid);
out_srcu:
    srcu_read_unlock(&g_cpu_clock_srcu, idx);
    return ret;
}

static asmlinkage long __nocfi cpu_clock_native(const struct pt_regs *regs)
{
    return cpu_clock_dispatch(regs, READ_ONCE(g_cpu_clock_hooks[0].original),
                              false, false);
}

#ifdef CONFIG_COMPAT
static asmlinkage long __nocfi cpu_clock_compat32(const struct pt_regs *regs)
{
    return cpu_clock_dispatch(regs, READ_ONCE(g_cpu_clock_hooks[1].original),
                              true, true);
}

static asmlinkage long __nocfi cpu_clock_compat64(const struct pt_regs *regs)
{
    return cpu_clock_dispatch(regs, READ_ONCE(g_cpu_clock_hooks[2].original),
                              true, false);
}
#endif

static void cpu_clock_drain(void)
{
    /* First catch calls that fetched the old table entry but have not yet
     * entered SRCU. Then wait for even sleeping handlers; finally cover
     * their instructions after srcu_read_unlock() and wrapper epilogues. */
    synchronize_rcu_tasks();
    synchronize_srcu(&g_cpu_clock_srcu);
    synchronize_rcu_tasks();
}

static void cpu_clock_remove_hooks(void)
{
    unsigned int i = g_cpu_clock_hook_count;
    bool drain = false;

    while (i) {
        struct cpu_clock_hook *hook = &g_cpu_clock_hooks[--i];
        int ret;

        if (!hook->installed)
            continue;
        drain = true;
        /* A void module-exit callback cannot reject unload. Never let it
         * free executable code while the table still references it. Retry
         * failed restores, without overwriting another owner's table hook. */
        for (;;) {
            if (READ_ONCE(*hook->slot) == hook->original)
                break;
            ret = syscall_patch_text_expected(hook->slot, &hook->original,
                                              &hook->replacement,
                                              sizeof(hook->original));
            if (!ret)
                break;
            pr_err_ratelimited("CPU clock hook restore failed: %d; waiting for safe detach\n",
                               ret);
            msleep(20);
        }
        hook->installed = false;
    }
    if (drain)
        cpu_clock_drain();
}

int syscall_cpu_clock_init(void)
{
    syscall_fn_t ni;
    unsigned int i;
    int ret;
#ifdef CONFIG_COMPAT
    syscall_fn_t *compat_table;
#endif

    mutex_lock(&g_cpu_clock_mutex);
    if (!g_cpu_clock_status) {
        mutex_unlock(&g_cpu_clock_mutex);
        return 0;
    }
    if (!g_sys_call_table)
        g_sys_call_table = syscall_lookup_symbol("sys_call_table");
    g_cpu_clock_get = syscall_lookup_symbol("posix_cpu_clock_get");
    ni = syscall_lookup_ni();
    if (!g_sys_call_table || !g_cpu_clock_get || !ni) {
        ret = -ENOENT;
        goto out_status;
    }

    g_cpu_clock_hooks[0].slot = &g_sys_call_table[__NR_clock_gettime];
    g_cpu_clock_hooks[0].replacement = cpu_clock_native;
    g_cpu_clock_hook_count = 1;
#ifdef CONFIG_COMPAT
    compat_table = syscall_lookup_symbol("compat_sys_call_table");
    if (!compat_table) {
        ret = -ENOENT;
        goto out_status;
    }
    /* These ARM EABI numbers are stable across the supported GKI kernels. */
#ifdef __NR_compat_syscalls
    BUILD_BUG_ON(__NR_compat_syscalls <= 403);
#endif
    g_cpu_clock_hooks[1].slot = &compat_table[263];
    g_cpu_clock_hooks[1].replacement = cpu_clock_compat32;
    g_cpu_clock_hooks[2].slot = &compat_table[403];
    g_cpu_clock_hooks[2].replacement = cpu_clock_compat64;
    g_cpu_clock_hook_count = 3;
#endif
    /* Publish every original pointer before any hook becomes reachable. */
    for (i = 0; i < g_cpu_clock_hook_count; ++i) {
        struct cpu_clock_hook *hook = &g_cpu_clock_hooks[i];

        WRITE_ONCE(hook->original, READ_ONCE(*hook->slot));
        if (!hook->original || hook->original == ni) {
            ret = -EOPNOTSUPP;
            goto out_status;
        }
    }
    ret = init_srcu_struct(&g_cpu_clock_srcu);
    if (ret)
        goto out_status;
    g_cpu_clock_srcu_ready = true;
    for (i = 0; i < g_cpu_clock_hook_count; ++i) {
        struct cpu_clock_hook *hook = &g_cpu_clock_hooks[i];

        ret = syscall_patch_text_expected(hook->slot, &hook->replacement,
                                          &hook->original,
                                          sizeof(hook->replacement));
        /* Track publication even if another hook has since replaced our
         * slot and may chain to us. Also cover a write completed before a
         * reported patching error. Current slot contents cannot disprove
         * that our handler has become reachable. */
        hook->installed = !ret || READ_ONCE(*hook->slot) == hook->replacement;
        if (ret) {
            cpu_clock_remove_hooks();
            cleanup_srcu_struct(&g_cpu_clock_srcu);
            g_cpu_clock_srcu_ready = false;
            goto out_status;
        }
    }
    ret = 0;
out_status:
    g_cpu_clock_status = ret;
    mutex_unlock(&g_cpu_clock_mutex);
    return ret;
}

long syscall_cpu_clock_set_target(void __user *arg)
{
    const struct cred *cred = current_cred();
    struct dfm_cpu_clock_target_req req;
    struct pid *next = NULL;
    struct pid *old;
    struct task_struct *task;
    long ret = 0;

    if (cred->user_ns != &init_user_ns ||
        (!(uid_eq(cred->uid, GLOBAL_ROOT_UID) &&
           uid_eq(cred->euid, GLOBAL_ROOT_UID)) &&
         !ns_capable(&init_user_ns, CAP_SYS_ADMIN)))
        return -EPERM;
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.pid < 0)
        return -EINVAL;

    mutex_lock(&g_cpu_clock_mutex);
    if (req.pid) {
        if (g_cpu_clock_status) {
            ret = g_cpu_clock_status;
            goto out;
        }
        rcu_read_lock();
        next = find_vpid(req.pid);
        task = pid_task(next, PIDTYPE_PID);
        if (!task)
            ret = -ESRCH;
        else if (task_pid(task) != task_tgid(task))
            ret = -EINVAL; /* Configuration accepts a process leader only. */
        else
            get_pid(next);
        rcu_read_unlock();
        if (ret)
            goto out;
    }
    old = rcu_dereference_protected(g_cpu_clock_target,
                                    lockdep_is_held(&g_cpu_clock_mutex));
    if (old == next) {
        put_pid(next);
        goto out;
    }
    rcu_assign_pointer(g_cpu_clock_target, next);
    synchronize_rcu();
    /* A sample already in flight may complete under the old policy: its
     * get_pid references protect both identities. Do not wait for SRCU
     * here: an observer's faulting user buffer could block configuration.
     * Observers must rebuild their baseline across configuration changes. */
    put_pid(old);
out:
    mutex_unlock(&g_cpu_clock_mutex);
    return ret;
}

void syscall_cpu_clock_exit(void)
{
    struct pid *old;

    mutex_lock(&g_cpu_clock_mutex);
    g_cpu_clock_status = -ESHUTDOWN;
    old = rcu_dereference_protected(g_cpu_clock_target,
                                    lockdep_is_held(&g_cpu_clock_mutex));
    rcu_assign_pointer(g_cpu_clock_target, NULL);
    cpu_clock_remove_hooks();
    synchronize_rcu();
    put_pid(old);
    if (g_cpu_clock_srcu_ready) {
        cleanup_srcu_struct(&g_cpu_clock_srcu);
        g_cpu_clock_srcu_ready = false;
    }
    g_cpu_clock_get = NULL;
    mutex_unlock(&g_cpu_clock_mutex);
}

#else

int syscall_cpu_clock_init(void)
{
    return -EOPNOTSUPP;
}

void syscall_cpu_clock_exit(void)
{
}

long syscall_cpu_clock_set_target(void __user *arg)
{
    return -EOPNOTSUPP;
}

#endif
