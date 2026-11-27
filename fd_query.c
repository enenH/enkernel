#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "abi.h"
#include "fd_query.h"

static struct file *target_file(int pid, unsigned int fd)
{
    struct task_struct *task;
    struct file *file = NULL;
    struct files_struct *files;
    struct fdtable *table;
    int ret;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    if (!task)
        return ERR_PTR(-ESRCH);

    /* Match KGSL_QUERY's delegated driver-fd authorization and locked lookup.
     * Never refcount a file from a lockless, potentially recycled fdtable slot. */
    ret = mutex_lock_killable(&task->signal->cred_guard_mutex);
    if (ret)
        goto out;
    ret = -EBADF;
    task_lock(task);
    files = task->files;
    if (files) {
        spin_lock(&files->file_lock);
        table = files_fdtable(files);
        if (fd < table->max_fds) {
            file = rcu_dereference_raw(table->fd[fd]);
            if (file)
                get_file(file);
        }
        spin_unlock(&files->file_lock);
    } else {
        ret = -ESRCH;
    }
    task_unlock(task);
    mutex_unlock(&task->signal->cred_guard_mutex);
out:
    put_task_struct(task);
    return file ? file : ERR_PTR(ret);
}

static int validate_request(const struct dfm_file_query_req *req)
{
    if (req->abi_version != DFM_FILE_QUERY_ABI_VERSION || req->pid <= 0 ||
        req->target_fd > INT_MAX || req->flags ||
        req->reserved[0] || req->reserved[1])
        return -EINVAL;
    switch (req->op) {
    case DFM_FILE_QUERY_INFO:
        return req->offset || req->whence || req->buf || req->size ? -EINVAL : 0;
    case DFM_FILE_QUERY_PREAD:
        if (req->whence || req->offset < 0 || !req->size)
            return -EINVAL;
        if (req->size > DFM_FILE_QUERY_MAX_READ)
            return -E2BIG;
        if (req->size > (u64)LLONG_MAX - req->offset)
            return -EOVERFLOW;
        if (!req->buf || !access_ok(u64_to_user_ptr(req->buf), req->size))
            return -EFAULT;
        return 0;
    case DFM_FILE_QUERY_SEEK:
        return req->buf || req->size || req->whence > SEEK_HOLE ? -EINVAL : 0;
    default:
        return -EINVAL;
    }
}

static void clear_output(struct dfm_file_query_req *req)
{
    req->out_size = req->out_result = req->out_file_size = 0;
    req->out_position = req->out_inode = req->out_device = 0;
    req->out_mode = req->out_errno = 0;
}

/* A query computes a virtual cursor; it must never call ->llseek(), which can
 * change f_pos or filesystem-private state even if f_pos is later restored. */
static loff_t query_seek(struct file *target,
                        const struct dfm_file_query_req *req)
{
    loff_t base = 0, pos;

    if (!(target->f_mode & FMODE_LSEEK))
        return -ESPIPE;
    switch (req->whence) {
    case SEEK_SET:
        break;
    case SEEK_CUR:
        if (req->out_position > LLONG_MAX)
            return -EOVERFLOW;
        base = req->out_position;
        break;
    case SEEK_END:
        if (req->out_file_size > LLONG_MAX)
            return -EOVERFLOW;
        base = req->out_file_size;
        break;
    default:
        /* DATA/HOLE require filesystem-specific callbacks. Do not reopen the
         * file, clone struct file, or approximate sparse extent information. */
        return -EOPNOTSUPP;
    }
    if (check_add_overflow(base, req->offset, &pos))
        return -EOVERFLOW;
    if (pos < 0 || pos > file_inode(target)->i_sb->s_maxbytes)
        return -EINVAL;
    return pos;
}

long dfm_file_query_fd(void __user *arg)
{
    struct dfm_file_query_req req;
    struct file *target;
    struct inode *inode;
    const struct cred *saved;
    void *buffer = NULL;
    loff_t pos;
    ssize_t count;
    long ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    clear_output(&req);
    ret = validate_request(&req);
    if (ret)
        goto reply;
    target = target_file(req.pid, req.target_fd);
    if (IS_ERR(target)) {
        ret = PTR_ERR(target);
        if (ret == -EBADF) {
            req.out_errno = EBADF;
            ret = 0;
        }
        goto reply;
    }
    inode = file_inode(target);
    if (!S_ISREG(inode->i_mode)) {
        req.out_errno = EOPNOTSUPP;
        goto out_target;
    }
    /* O_PATH and write-only descriptors must not become readable capabilities. */
    if (req.op != DFM_FILE_QUERY_INFO && !(target->f_mode & FMODE_READ)) {
        req.out_errno = EBADF;
        goto out_target;
    }
    mutex_lock(&target->f_pos_lock);
    req.out_position = target->f_pos;
    mutex_unlock(&target->f_pos_lock);
    req.out_file_size = i_size_read(inode);
    req.out_inode = inode->i_ino;
    req.out_device = new_encode_dev(inode->i_sb->s_dev);
    req.out_mode = inode->i_mode;
    if (req.op == DFM_FILE_QUERY_INFO)
        goto out_target;
    if (req.op == DFM_FILE_QUERY_PREAD) {
        if (!(target->f_mode & FMODE_PREAD)) {
            req.out_errno = ESPIPE;
            goto out_target;
        }
        buffer = kvmalloc(req.size, GFP_KERNEL);
        if (!buffer) {
            ret = -ENOMEM;
            goto out_target;
        }
        /* Read the pinned open description itself, preserving its flags and
         * private state. A private position never changes the target cursor.
         * Keep the opening credentials and normal VFS/LSM read checks. */
        saved = override_creds(target->f_cred);
        pos = req.offset;
        count = kernel_read(target, buffer, req.size, &pos);
        revert_creds(saved);
        if (count < 0)
            req.out_errno = -count;
        else
            req.out_size = count;
    } else {
        pos = query_seek(target, &req);
        if (pos < 0)
            req.out_errno = -pos;
        else
            req.out_result = pos;
    }
    if (!req.out_errno && req.out_size &&
        copy_to_user(u64_to_user_ptr(req.buf), buffer, req.out_size))
        ret = -EFAULT;
out_target:
    fput(target);
    kvfree(buffer);
reply:
    if (ret || req.out_errno) {
        int error = req.out_errno;
        clear_output(&req);
        req.out_errno = error;
    }
    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;
    return ret;
}
