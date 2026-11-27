#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/anon_inodes.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/proc_fs.h>
#include <linux/task_work.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/workqueue.h>

#include "abi.h"
#include "install.h"
#include "kgsl.h"
#include "mem.h"
#include "process_mem.h"
#include "syscall.h"
#include "touch.h"
#include "touch_v2.h"
#include "dfm_hwb.h"
#include "udp_capture.h"
#include "file_io.h"
#include "sf_groups.h"
#include "sf_avc.h"
#include "futex.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DFM");
MODULE_DESCRIPTION("DFM lab debug module");

static DEFINE_SPINLOCK(g_install_lock);
static bool g_accept_installs;
static unsigned int g_install_users;
static atomic_t g_driver_files = ATOMIC_INIT(0);

static void set_install_admission(bool enabled)
{
    unsigned long flags;

    spin_lock_irqsave(&g_install_lock, flags);
    g_accept_installs = enabled;
    spin_unlock_irqrestore(&g_install_lock, flags);
}

static bool install_try_get(void)
{
    unsigned long flags;
    bool acquired;

    spin_lock_irqsave(&g_install_lock, flags);
    acquired = g_accept_installs &&
               READ_ONCE(THIS_MODULE->state) == MODULE_STATE_LIVE &&
               try_module_get(THIS_MODULE);
    if (acquired)
        g_install_users++;
    spin_unlock_irqrestore(&g_install_lock, flags);
    return acquired;
}

static void install_put(void)
{
    unsigned long flags;

    module_put(THIS_MODULE);
    spin_lock_irqsave(&g_install_lock, flags);
    g_install_users--;
    spin_unlock_irqrestore(&g_install_lock, flags);
}

/* ---- ioctl dispatcher ---- */

static long drv_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    void __user *argp = (void __user *)arg;

    switch (cmd) {
    case MEM_IOC_CAPABILITIES:
        return dfm_capabilities(argp);
    case MEM_IOC_FUTEX_WAITERS:
        return dfm_futex_waiters(filp, argp);
    case MEM_IOC_FUTEX_VALIDATE:
        return dfm_futex_validate(filp, argp);
    case UDP_IOC_BIND_FD:
        return udp_capture_bind_fd(argp);
    case UDP_IOC_READ_V2:
        return udp_capture_read_v2(argp);
    case MEM_IOC_OPEN_PROCESS_MEM:
        return mem_open_process_mem(argp);
    case MEM_IOC_READ:
        return mem_read(argp);
    case MEM_IOC_READ_CACHE:
        return mem_read_cache(argp);
    case MEM_IOC_GET_PID:
        return mem_get_pid(argp);
    case MEM_IOC_GET_PIDS:
        return mem_get_pids(argp);
    case MEM_IOC_GET_MODULE_BASE:
        return mem_get_module_base(argp);
    case MEM_IOC_GET_MODULE_BASE2:
        return mem_get_module_base2(argp);
    case MEM_IOC_GET_MODULE_PATH:
        return mem_get_module_path(argp);
    case MEM_IOC_QUERY_MAPPING:
        return mem_query_mapping(argp);
    case MEM_IOC_QUERY_ACCESS:
        return mem_query_access(argp);
    case MEM_IOC_QUERY_SIGNAL:
        return mem_query_signal(argp);
    case TOUCH_IOC_INIT:
        return touch_init();
    case TOUCH_IOC_EVENT:
        return touch_event(argp);
    case TOUCH_IOC_INIT_V2:
        return touch_v2_init();
    case TOUCH_IOC_EVENT_V2:
        return touch_v2_event(argp);
    case TOUCH_IOC_GET_STATUS:
        return touch_get_status(argp);
    case MEM_IOC_GET_TLS:
        return mem_get_tls(argp);
    case MEM_IOC_GET_THREAD_TID:
        return mem_get_thread_tid(argp);
    case MEM_IOC_GET_THREAD_TIDS:
        return mem_get_thread_tids(argp);
    case MEM_IOC_GET_THREAD_STACK:
        return mem_get_thread_stack(argp);
    case MEM_IOC_EXECUTE_PACGA:
        return mem_execute_pacga(argp);
    case DFM_IOCTL_HWB_INFO:
        return dfm_hwb_info(argp);
    case DFM_IOCTL_HWB_SLOTS:
        return dfm_hwb_slots(argp);
    case DFM_IOCTL_HWB_SET:
        return dfm_hwb_set(filp, argp);
    case DFM_IOCTL_HWB_READ:
        return dfm_hwb_read(argp);
    case DFM_IOCTL_HWB_CLEAR:
        return dfm_hwb_clear();
    case DFM_IOCTL_KGSL_SYNCSOURCE_PEEK:
        return kgsl_syncsource_peek(argp);
    case DFM_IOCTL_KGSL_QUERY:
        return kgsl_query(argp);
    case UDP_IOC_INIT:
        return udp_capture_init(argp);
    case UDP_IOC_READ:
        return udp_capture_read(argp);
    case UDP_IOC_STOP:
        return udp_capture_stop();
    case DFM_FILE_IOC_READ:
        return dfm_file_read(argp);
    case DFM_FILE_IOC_WRITE:
        return dfm_file_write(argp);
    case DFM_CRED_IOC_ACQUIRE_SF_GROUPS:
        return dfm_sf_groups_acquire(argp);
    case DFM_CPU_CLOCK_IOC_SET_TARGET:
        return syscall_cpu_clock_set_target(argp);
    default:
        return -ENOTTY;
    }
}

static int drv_release(struct inode *inode, struct file *filp)
{
    dfm_futex_release(filp);
    dfm_hwb_release_owner(filp);
    udp_capture_stop();
    touch_v2_release_all();
    touch_release_all();
    atomic_dec(&g_driver_files);
    return 0;
}

static const struct file_operations drv_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = drv_ioctl,
    .compat_ioctl   = drv_ioctl,
    .release        = drv_release,
};

static int g_reboot_kprobe_registered;

/* ---- fd installation ---- */

static int install_fd(void)
{
    struct file *filp;
    int fd;

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0)
        return fd;

    filp = anon_inode_getfile("[dfm]", &drv_fops, NULL,
                              O_RDWR | O_CLOEXEC);
    if (IS_ERR(filp)) {
        put_unused_fd(fd);
        return PTR_ERR(filp);
    }

    atomic_inc(&g_driver_files);
    fd_install(fd, filp);
    return fd;
}

int install_fd_to_user(int __user *outp)
{
    int fd;

    if (!outp)
        return -EFAULT;
    if (!install_try_get())
        return -ESHUTDOWN;

    fd = install_fd();
    if (copy_to_user(outp, &fd, sizeof(fd))) {
        pr_err("install fd copy_to_user failed\n");
        if (fd >= 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11, 0)
            close_fd(fd);
#else
            ksys_close(fd);
#endif
        }
        fd = -EFAULT;
    }

    install_put();
    return fd < 0 ? fd : 0;
}

/* ---- task_work callback to install fd from process context ---- */

struct install_tw {
    struct callback_head cb;
    int __user *outp;
};

static void install_fd_tw_func(struct callback_head *cb)
{
    struct install_tw *tw =
        container_of(cb, struct install_tw, cb);

    if (!(current->flags & PF_EXITING))
        install_fd_to_user(tw->outp);

    kfree(tw);
    install_put();
}

/* ---- reboot kprobe handler ---- */

static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs;
    int magic1, magic2;
    unsigned long arg4;
    struct install_tw *tw;

    /* ARM64 syscall wrapper: first arg is pointer to user pt_regs */
    real_regs = (struct pt_regs *)regs->regs[0];

    magic1 = (int)real_regs->regs[0];
    magic2 = (int)real_regs->regs[1];

    if (magic1 != INSTALL_MAGIC1 || magic2 != INSTALL_MAGIC2)
        return 0;

    arg4 = (unsigned long)real_regs->regs[3];

    if (!arg4 || !install_try_get())
        return 0;
    tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
    if (!tw) {
        install_put();
        return 0;
    }

    tw->outp = (int __user *)arg4;
    tw->cb.func = install_fd_tw_func;

    if (task_work_add(current, &tw->cb, TWA_RESUME)) {
        kfree(tw);
        install_put();
        pr_warn("task_work_add failed\n");
    }

    return 0;
}

static struct kprobe kp_reboot = {
    .symbol_name = "__arm64_sys_reboot",
    .pre_handler = reboot_handler_pre,
};

#if defined(CONFIG_MODULE_UNLOAD) && defined(CONFIG_SYSFS) && defined(CONFIG_TASKS_RCU)

static DEFINE_MUTEX(g_unload_lock);
static DECLARE_COMPLETION(g_unload_done);
static bool g_unload_work_queued;
static bool g_unload_started;
static bool g_unload_prepared;
static int g_unload_result;

static int stop_new_installs(void)
{
    unsigned long flags;
    bool was_accepting;

    spin_lock_irqsave(&g_install_lock, flags);
    if (g_install_users || atomic_read(&g_driver_files)) {
        spin_unlock_irqrestore(&g_install_lock, flags);
        return -EBUSY;
    }
    was_accepting = g_accept_installs;
    g_accept_installs = false;
    spin_unlock_irqrestore(&g_install_lock, flags);

    if (!process_mem_in_use() && !touch_v2_has_pending_events())
        return 0;

    /* An existing session or an input release still needs to finish. */
    set_install_admission(was_accepting);
    return -EBUSY;
}

static void prepare_unload_workfn(struct work_struct *work)
{
    int ret;

    ret = touch_quiesce_read_hook();
    if (ret)
        goto done;
    g_unload_started = true;
    ret = dfm_hwb_clear();
    if (!ret)
        ret = syscall_cpu_clock_exit();
    if (!ret)
        ret = syscall_hook_exit();
    if (!ret && g_reboot_kprobe_registered) {
        unregister_kprobe(&kp_reboot);
        g_reboot_kprobe_registered = 0;
        /* Pending task work pins the module. Drain the return instructions
         * of callbacks that just dropped their references. */
        synchronize_rcu_tasks();
    }
    if (!ret)
        dfm_sf_avc_exit();
done:
    if (ret)
        pr_warn("unload preparation failed: %d\n", ret);
    g_unload_result = ret;
    complete(&g_unload_done);
}

static DECLARE_WORK(g_unload_work, prepare_unload_workfn);

static int prepare_unload_set(const char *value, const struct kernel_param *param)
{
    const int *modules_disabled;
    bool requested;
    long waited;
    int ret;

    if (kstrtobool(value, &requested) || !requested)
        return -EINVAL;
    if (!capable(CAP_SYS_MODULE))
        return -EPERM;
    modules_disabled = (const int *)kallsyms_lookup_name("modules_disabled");
    if (modules_disabled && READ_ONCE(*modules_disabled))
        return -EPERM;
    if (READ_ONCE(THIS_MODULE->state) != MODULE_STATE_LIVE)
        return -EBUSY;

    mutex_lock(&g_unload_lock);
    ret = 0;
    if (g_unload_prepared)
        goto out;
    if (!g_unload_work_queued) {
        ret = stop_new_installs();
        if (ret)
            goto out;
        reinit_completion(&g_unload_done);
        g_unload_work_queued = true;
        queue_work(system_unbound_wq, &g_unload_work);
    }

    /* A sleeping hook can delay a grace period. If that happens, leave the
     * lifetime pin in place and let a later request collect the result. */
    waited = wait_for_completion_killable_timeout(&g_unload_done,
                                                  msecs_to_jiffies(10000));
    if (waited <= 0) {
        ret = waited ? (int)waited : -ETIMEDOUT;
        goto out;
    }
    flush_work(&g_unload_work);
    g_unload_work_queued = false;
    ret = g_unload_result;
    if (!ret) {
        g_unload_prepared = true;
        module_put(THIS_MODULE);
    } else if (!g_unload_started) {
        /* A still-open touch proxy can keep serving existing clients. */
        set_install_admission(true);
    }
out:
    mutex_unlock(&g_unload_lock);
    return ret;
}

static int prepare_unload_get(char *buf, const struct kernel_param *param)
{
    unsigned long flags;
    bool preparing;

    spin_lock_irqsave(&g_install_lock, flags);
    preparing = !g_accept_installs &&
                READ_ONCE(THIS_MODULE->state) == MODULE_STATE_LIVE;
    spin_unlock_irqrestore(&g_install_lock, flags);
    return sprintf(buf, "%c\n", preparing ? 'Y' : 'N');
}

static int unload_supported_get(char *buf, const struct kernel_param *param)
{
    return sprintf(buf, "Y\n");
}

static const struct kernel_param_ops prepare_unload_ops = {
    .set = prepare_unload_set,
    .get = prepare_unload_get,
};
static const struct kernel_param_ops unload_supported_ops = {
    .get = unload_supported_get,
};

module_param_cb(prepare_unload, &prepare_unload_ops, NULL, 0600);
module_param_cb(unload_supported, &unload_supported_ops, NULL, 0444);

#endif

/* ---- module init/exit ---- */

static bool __init proc_entry_exists(const char *name)
{
    struct path path;

    if (kern_path(name, 0, &path))
        return false;
    path_put(&path);
    return true;
}

static void __init remove_inte_proc_entries(void)
{
    /* Best-effort existence checks avoid removing already absent entries.
     * Checking existence only looks up the path; it does not open/read it. */
    if (proc_entry_exists("/proc/inte_ko"))
        remove_proc_entry("inte_ko", NULL);
    if (proc_entry_exists("/proc/inte_systbl"))
        remove_proc_entry("inte_systbl", NULL);
    if (proc_entry_exists("/proc/inte_status"))
        remove_proc_entry("inte_status", NULL);
}

static int __init mod_init(void)
{
    int ret;
    int syscall_ret;
    int reboot_ret;

    ret = mem_core_init();
    if (ret < 0) {
        pr_err("mem_core_init failed: %d\n", ret);
        return ret;
    }

    ret = dfm_file_io_init();
    if (ret < 0) {
        pr_err("dfm_file_io_init failed: %d\n", ret);
        mem_core_exit();
        return ret;
    }

    ret = dfm_sf_avc_init();
    if (ret < 0)
        /* Core clients remain usable; SF startup requires the active-probe
         * capability and reports the normal reboot-required message. */
        pr_warn("SurfaceFlinger AVC capability unavailable: %d\n", ret);

    syscall_ret = syscall_hook_init();
    if (syscall_ret < 0)
        pr_warn("syscall install hook unavailable: %d\n", syscall_ret);

    /* Queued install callbacks must have a Tasks RCU return grace period
     * on kernels that allow module removal. */
    reboot_ret = -EOPNOTSUPP;
    if (!IS_ENABLED(CONFIG_MODULE_UNLOAD) || IS_ENABLED(CONFIG_TASKS_RCU))
        reboot_ret = register_kprobe(&kp_reboot);
    if (reboot_ret < 0) {
        pr_warn("failed to register kprobe on reboot: %d\n", reboot_ret);
    } else {
        g_reboot_kprobe_registered = 1;
    }

    if (syscall_ret < 0 && reboot_ret < 0) {
        pr_err("no fd install entry registered\n");
        dfm_sf_avc_exit();
        dfm_file_io_exit();
        mem_core_exit();
        return reboot_ret;
    }

    ret = syscall_cpu_clock_init();
    if (ret < 0)
        pr_warn("CPU-clock mitigation unavailable: %d\n", ret);

    (void)kgsl_hide_init();

    remove_inte_proc_entries();

    /* Kernel-managed sysfs stays available for unload preparation. Hold a
     * reference until preparation has restored and drained external hooks. */
    __module_get(THIS_MODULE);
    set_install_admission(true);

    pr_info("module loaded, syscall_nr=%d reboot_fallback=%d\n",
            syscall_hook_nr(), g_reboot_kprobe_registered);
    return 0;
}

static void __exit mod_exit(void)
{
    /* The preparation pin permits entry only after all detachable hooks
     * that can fail to restore have been drained. */
    dfm_sf_avc_exit();
    kgsl_hide_exit();
    udp_capture_exit();
    dfm_hwb_exit();
    touch_v2_release_all();
    touch_exit();
    touch_v2_exit();
    dfm_file_io_exit();
    mem_core_exit();
    pr_info("module unloaded\n");
}

module_init(mod_init);
module_exit(mod_exit);
