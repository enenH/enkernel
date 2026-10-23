/* Restricted, COW-aware SensorService memory sessions. No procfs/cred bypass. */
#include <linux/anon_inodes.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/processor.h>

#include "abi.h"
#include "mem.h"
#include "process_mem.h"
#include "sf_groups.h"

#define SENSOR_LIBRARY "/system/lib64/libsensorservice.so"
#define SENSOR_CAVE_SIZE 64U

struct process_mem_session {
    struct task_struct *target;
    struct pid *owner;
    struct mm_struct *mm; /* mmgrab only: never keep a dead address space alive */
    struct file *library;
    struct mutex lock;
    struct work_struct cleanup;
    struct mem_process_mem_arm_req patch;
    bool armed;
};

static DEFINE_MUTEX(session_lock);
/* Both launch modes must serialize ownership of the system-wide GOT slot. */
static struct process_mem_session *active_session;

static bool caller_allowed(void)
{
    const struct cred *cred = current_cred();

    if (cred->user_ns == &init_user_ns &&
        uid_eq(cred->uid, GLOBAL_ROOT_UID) &&
        uid_eq(cred->euid, GLOBAL_ROOT_UID))
        return true;
    return dfm_is_surfaceflinger_caller();
}

static struct mm_struct *live_mm(struct process_mem_session *session)
{
    struct mm_struct *mm;

    if (!pid_alive(session->target) || READ_ONCE(session->target->exit_state))
        return ERR_PTR(-ESRCH);
    mm = get_task_mm(session->target);
    if (!mm)
        return ERR_PTR(-ESRCH);
    if (mm != session->mm) {
        mmput(mm);
        return ERR_PTR(-ESTALE);
    }
    return mm;
}

static bool same_library(struct process_mem_session *session,
                         struct vm_area_struct *vma)
{
    return vma->vm_file &&
           file_inode(vma->vm_file) == file_inode(session->library) &&
           vma->vm_file->f_path.mnt == session->library->f_path.mnt;
}

static int allowed_range(struct process_mem_session *session,
                          struct mm_struct *mm, unsigned long addr,
                          size_t size, bool writing)
{
    unsigned long end;

    if (!size || addr >= TASK_SIZE_64 || size > TASK_SIZE_64 - addr)
        return -EINVAL;
    end = addr + size;
    while (addr < end) {
        struct vm_area_struct *vma = find_vma(mm, addr);

        if (!vma || addr < vma->vm_start)
            return -EFAULT;
        if (!same_library(session, vma) ||
            (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP |
                              VM_HUGETLB | VM_MAYSHARE)))
            return -EACCES;
        if (!(vma->vm_flags & VM_READ) ||
            (writing && !(vma->vm_flags & VM_MAYWRITE)))
            return -EACCES;
        addr = min(end, vma->vm_end);
    }
    return 0;
}

/* Caller holds session->lock, or owns the fd's final-release worker. GUP and
 * validation share one mmap lock, so a
 * concurrent unmap cannot substitute an unrelated/shared mapping after checks.
 * The buffer is kernel memory. Never feed the NC physical read path a write. */
static ssize_t transfer(struct process_mem_session *session, struct mm_struct *mm,
                         unsigned long addr, void *buffer, size_t size, bool writing)
{
    size_t done = 0;
    int ret;

    if (writing && session->armed &&
        !((addr == session->patch.delta_addr || addr == session->patch.got_addr) &&
          size == sizeof(u64)))
        return -EPERM; /* Published code and its original-function pointer stay immutable. */
    mmap_read_lock(mm);
    ret = allowed_range(session, mm, addr, size, writing);
    if (ret)
        goto out;
    while (done < size) {
        struct vm_area_struct *vma = find_vma(mm, addr);
        struct page *page = NULL;
        unsigned int flags = writing ? FOLL_WRITE | FOLL_FORCE : 0;
        size_t bytes = min_t(size_t, size - done, PAGE_SIZE - offset_in_page(addr));
        void *mapped;
        void *at;

        /* NULL locked: GUP must not drop the mmap lock (and invalidate vma). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        ret = get_user_pages_remote(mm, addr, 1, flags, &page, NULL);
#else
        ret = get_user_pages_remote(mm, addr, 1, flags, &page, NULL, NULL);
#endif
        if (ret != 1) {
            if (ret >= 0) ret = -EFAULT;
            break;
        }
        mapped = kmap(page);
        at = (char *)mapped + offset_in_page(addr);
        if (writing) {
            if (bytes == sizeof(u64) && IS_ALIGNED(addr, sizeof(u64))) {
                u64 value;
                memcpy(&value, (char *)buffer + done, sizeof(value));
                if (session->armed && addr == session->patch.got_addr) {
                    u64 expected, previous;
                    if (value != session->patch.original &&
                        value != session->patch.replacement) {
                        ret = -EINVAL;
                        goto put;
                    }
                    expected = value == session->patch.original ?
                        session->patch.replacement : session->patch.original;
                    /* Publish only after the trampoline is complete; never
                     * overwrite another hook during cleanup. */
                    smp_wmb();
                    previous = cmpxchg((u64 *)at, expected, value);
                    if (previous != expected && previous != value) {
                        ret = -EAGAIN;
                        goto put;
                    }
                } else {
                    WRITE_ONCE(*(u64 *)at, value); /* coherent float pair / pointer */
                }
            } else {
                memcpy(at, (char *)buffer + done, bytes);
            }
            /* copy_to_user_page is not exported on all GKI builds. These
             * exported ARM64 helpers reach the same sync_icache_aliases path,
             * including aliasing I-caches; flush the whole page/folio. */
            flush_dcache_page(page);
            if (vma->vm_flags & VM_EXEC)
                __sync_icache_dcache(mk_pte(page, vma->vm_page_prot));
            set_page_dirty_lock(page);
        } else {
            memcpy((char *)buffer + done, at, bytes);
        }
        ret = 0;
put:
        kunmap(page);
        put_page(page);
        if (ret)
            break;
        done += bytes;
        addr += bytes;
    }
out:
    mmap_read_unlock(mm);
    return done ? (ssize_t)done : ret;
}

static ssize_t process_mem_rw(struct file *file, char __user *buf, size_t count,
                              loff_t *pos, bool writing)
{
    struct process_mem_session *session = file->private_data;
    struct mm_struct *mm;
    void *buffer;
    ssize_t ret;

    if (task_tgid(current) != session->owner)
        return -EACCES;
    if (!count)
        return 0;
    if (count > MEM_PROCESS_MEM_IO_MAX)
        return -E2BIG;
    if (*pos < 0 || (u64)*pos >= TASK_SIZE_64 || count > TASK_SIZE_64 - (u64)*pos)
        return -EINVAL;
    buffer = writing ? memdup_user(buf, count) : kmalloc(count, GFP_KERNEL);
    if (IS_ERR(buffer))
        return PTR_ERR(buffer);
    if (!buffer)
        return -ENOMEM;
    mutex_lock(&session->lock);
    mm = live_mm(session);
    if (IS_ERR(mm)) {
        ret = PTR_ERR(mm);
    } else {
        ret = transfer(session, mm, (unsigned long)*pos, buffer, count, writing);
        mmput(mm);
        if (ret > 0 && !writing && copy_to_user(buf, buffer, ret))
            ret = -EFAULT;
        if (ret > 0)
            *pos += ret;
    }
    mutex_unlock(&session->lock);
    kfree(buffer);
    return ret;
}

static ssize_t process_mem_read(struct file *file, char __user *buf,
                                size_t count, loff_t *pos)
{
    return process_mem_rw(file, buf, count, pos, false);
}

static ssize_t process_mem_write(struct file *file, const char __user *buf,
                                 size_t count, loff_t *pos)
{
    return process_mem_rw(file, (char __user *)buf, count, pos, true);
}

static int arm_patch(struct process_mem_session *session, struct mm_struct *mm,
                      void __user *arg)
{
    struct mem_process_mem_arm_req req;
    struct vm_area_struct *vma;
    u64 got, original;
    int ret;

    if (copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
    if (req.version != MEM_PROCESS_MEM_ABI_VERSION || req.reserved ||
        !IS_ALIGNED(req.got_addr, 8) || !IS_ALIGNED(req.delta_addr, 16) ||
        req.delta_addr >= TASK_SIZE_64 - SENSOR_CAVE_SIZE ||
        req.replacement != req.delta_addr + 16 || !req.original ||
        req.original >= TASK_SIZE_64 || !IS_ALIGNED(req.original, 4) ||
        (req.original >= req.delta_addr && req.original < req.delta_addr + SENSOR_CAVE_SIZE) ||
        (req.got_addr >= req.delta_addr && req.got_addr < req.delta_addr + SENSOR_CAVE_SIZE))
        return -EINVAL;
    if (session->armed) return -EBUSY;
    mmap_read_lock(mm);
    ret = allowed_range(session, mm, req.delta_addr, SENSOR_CAVE_SIZE, true);
    if (!ret) {
        vma = find_vma(mm, req.delta_addr);
        if (!(vma->vm_flags & VM_EXEC) || req.delta_addr + SENSOR_CAVE_SIZE > vma->vm_end)
            ret = -EINVAL;
    }
    if (!ret) ret = allowed_range(session, mm, req.got_addr, sizeof(u64), true);
    if (!ret && (find_vma(mm, req.got_addr)->vm_flags & VM_EXEC)) ret = -EINVAL;
    if (!ret) {
        vma = find_vma(mm, req.original);
        if (!vma || req.original < vma->vm_start || !(vma->vm_flags & VM_EXEC))
            ret = -EINVAL;
    }
    mmap_read_unlock(mm);
    if (ret) return ret;
    if (transfer(session, mm, req.got_addr, &got, sizeof(got), false) != sizeof(got) ||
        transfer(session, mm, req.delta_addr + 8, &original, sizeof(original), false) != sizeof(original))
        return -EFAULT;
    if (got != req.original || original != req.original)
        return -ESTALE;
    session->patch = req;
    session->armed = true;
    return 0;
}

static long process_mem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct process_mem_session *session = file->private_data;
    struct mm_struct *mm;
    long ret;

    if (task_tgid(current) != session->owner) return -EACCES;
    mutex_lock(&session->lock);
    mm = live_mm(session);
    if (IS_ERR(mm)) {
        ret = PTR_ERR(mm);
        goto out;
    }
    if (cmd == MEM_IOC_QUERY_ACCESS) {
        struct mem_query_access_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
            ret = -EFAULT;
        } else if (req.flags || req.pid != task_pid_vnr(session->target)) {
            ret = -EINVAL;
        } else {
            ret = mem_query_access_mm(mm, untagged_addr((unsigned long)req.addr), &req);
            if (!ret && copy_to_user((void __user *)arg, &req, sizeof(req))) ret = -EFAULT;
        }
    } else if (cmd == MEM_PROCESS_MEM_IOC_ARM) {
        ret = arm_patch(session, mm, (void __user *)arg);
    } else {
        ret = -ENOTTY;
    }
    mmput(mm);
out:
    mutex_unlock(&session->lock);
    return ret;
}

static void cleanup_patch(struct work_struct *work)
{
    struct process_mem_session *session = container_of(work, struct process_mem_session, cleanup);
    struct mm_struct *mm;
    u64 zero = 0;
    ssize_t delta_ret, got_ret;

    if (!session->armed) return;
    mm = live_mm(session);
    if (IS_ERR(mm)) return;
    delta_ret = transfer(session, mm, session->patch.delta_addr, &zero, sizeof(zero), true);
    got_ret = transfer(session, mm, session->patch.got_addr,
                       &session->patch.original, sizeof(u64), true);
    if (delta_ret != sizeof(u64) || got_ret != sizeof(u64))
        pr_warn("dfm: sensor session cleanup failed delta=%zd got=%zd\n", delta_ret, got_ret);
    mmput(mm);
}

static int process_mem_release(struct inode *inode, struct file *file)
{
    struct process_mem_session *session = file->private_data;

    /* GUP may reject an exiting task's pending SIGKILL. Run cleanup in a
     * worker without that signal and keep the fd/module alive until it ends. */
    schedule_work(&session->cleanup);
    flush_work(&session->cleanup);
    mutex_lock(&session_lock);
    if (active_session == session) active_session = NULL;
    mutex_unlock(&session_lock);
    fput(session->library);
    mmdrop(session->mm);
    put_task_struct(session->target);
    put_pid(session->owner);
    kfree(session);
    return 0;
}

static const struct file_operations process_mem_fops = {
    .owner = THIS_MODULE,
    .read = process_mem_read,
    .write = process_mem_write,
    .llseek = default_llseek,
    .unlocked_ioctl = process_mem_ioctl,
    .compat_ioctl = process_mem_ioctl,
    .release = process_mem_release,
};

long mem_open_process_mem(void __user *arg)
{
    struct mem_open_process_mem_req req;
    struct process_mem_session *session;
    struct mm_struct *mm = NULL;
    struct vm_area_struct *vma;
    const struct cred *cred;
    struct file *file;
    char comm[TASK_COMM_LEN];
    char *path_buf;
    int fd, ret;

    BUILD_BUG_ON(sizeof(req) != 40);
    BUILD_BUG_ON(sizeof(struct mem_process_mem_arm_req) != 40);
    if (copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
    if (req.version != MEM_PROCESS_MEM_ABI_VERSION || req.reserved || req.pid <= 0)
        return -EINVAL;
    if (!caller_allowed()) return -EACCES;
    session = kzalloc(sizeof(*session), GFP_KERNEL);
    path_buf = (char *)__get_free_page(GFP_KERNEL);
    if (!session || !path_buf) {
        kfree(session);
        if (path_buf) free_page((unsigned long)path_buf);
        return -ENOMEM;
    }
    mutex_init(&session->lock);
    INIT_WORK(&session->cleanup, cleanup_patch);
    session->owner = get_task_pid(current->group_leader, PIDTYPE_PID);
    mutex_lock(&session_lock);
    ret = -EBUSY;
    if (active_session) goto fail;
    rcu_read_lock();
    session->target = pid_task(find_vpid(req.pid), PIDTYPE_PID);
    if (session->target) get_task_struct(session->target);
    rcu_read_unlock();
    ret = -ESRCH;
    if (!session->target) goto fail;
    get_task_comm(comm, session->target);
    cred = get_task_cred(session->target);
    ret = strcmp(comm, "system_server") || !thread_group_leader(session->target) ||
          cred->user_ns != &init_user_ns || !uid_eq(cred->uid, KUIDT_INIT(1000)) ||
          !uid_eq(cred->euid, KUIDT_INIT(1000)) ? -EACCES : 0;
    put_cred(cred);
    if (ret) goto fail;
    mm = get_task_mm(session->target);
    ret = -ESRCH;
    if (!mm) goto fail;
    req.out_module_base = req.out_module_size = 0;
    mmap_read_lock(mm);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    {
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
#else
    {
        for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
            if (!vma->vm_file) continue;
            if (!session->library) {
                char *path;
                if (strcmp(vma->vm_file->f_path.dentry->d_name.name, "libsensorservice.so"))
                    continue;
                path = d_path(&vma->vm_file->f_path, path_buf, PAGE_SIZE);
                if (IS_ERR(path) || strcmp(path, SENSOR_LIBRARY) || vma->vm_pgoff)
                    continue;
                session->library = get_file(vma->vm_file);
                req.out_module_base = vma->vm_start;
            }
            if (same_library(session, vma))
                req.out_module_size = vma->vm_end - req.out_module_base;
        }
    }
    mmap_read_unlock(mm);
    ret = -ENOENT;
    if (!session->library) goto fail;
    session->mm = mm;
    mmgrab(mm);
    mmput(mm);
    mm = NULL;
    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) { ret = fd; goto fail; }
    file = anon_inode_getfile("[dfm-sensor-mem]", &process_mem_fops, session, O_RDWR | O_CLOEXEC);
    if (IS_ERR(file)) {
        put_unused_fd(fd);
        ret = PTR_ERR(file);
        goto fail;
    }
    /* anon_inode fds must explicitly support positional I/O. */
    file->f_mode |= FMODE_PREAD | FMODE_PWRITE | FMODE_LSEEK;
    req.out_fd = fd;
    req.out_uid = 1000;
    active_session = session;
    mutex_unlock(&session_lock);
    free_page((unsigned long)path_buf);
    if (copy_to_user(arg, &req, sizeof(req))) {
        put_unused_fd(fd);
        fput(file);
        return -EFAULT;
    }
    fd_install(fd, file);
    return 0;
fail:
    mutex_unlock(&session_lock);
    if (mm) mmput(mm);
    if (session->mm) mmdrop(session->mm);
    if (session->library) fput(session->library);
    if (session->target) put_task_struct(session->target);
    put_pid(session->owner);
    free_page((unsigned long)path_buf);
    kfree(session);
    return ret;
}
