/* SPDX-License-Identifier: GPL-2.0-only */
/* Observations keep a target file reference without changing its position. */
#include <linux/anon_inodes.h>
#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if __has_include(<linux/fileattr.h>)
#include <linux/fileattr.h>
#define DFM_HAVE_FILEATTR_GET 1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
typedef struct file_kattr dfm_fileattr_t;
#else
typedef struct fileattr dfm_fileattr_t;
#endif
#endif

#include "abi.h"
#include "file_observer.h"

#define DFM_FILE_OBSERVER_MAX_FILES 256U

struct dfm_file_observer {
    struct task_struct *task;
    struct mm_struct *mm;
    struct file *owner;
    struct mutex lock;
    unsigned int count;
    struct file *files[DFM_FILE_OBSERVER_MAX_FILES];
};

struct observed_file {
    s64 initial_position, size, max_size;
    u32 kind;
};

struct iomap_ops;

enum file_seek_profile {
    SEEK_PROFILE_UNKNOWN,
    SEEK_PROFILE_GENERIC,
    SEEK_PROFILE_DEFAULT,
    SEEK_PROFILE_SHMEM,
    SEEK_PROFILE_EXT4,
    SEEK_PROFILE_F2FS,
};

static unsigned long callable_symbol(const char *name)
{
#if defined(CONFIG_CFI_CLANG) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
    char jump_name[KSYM_NAME_LEN];
    unsigned long jump_address;

    snprintf(jump_name, sizeof(jump_name), "%s.cfi_jt", name);
    jump_address = kallsyms_lookup_name(jump_name);
    if (jump_address)
        return jump_address;
#endif
    return kallsyms_lookup_name(name);
}

static bool seek_matches(const struct file *file, const char *name)
{
    unsigned long seek = (unsigned long)file->f_op->llseek;

    return seek && (seek == callable_symbol(name) ||
                    seek == kallsyms_lookup_name(name));
}

static enum file_seek_profile regular_profile(const struct file *file)
{
    if (seek_matches(file, "generic_file_llseek"))
        return SEEK_PROFILE_GENERIC;
    if (seek_matches(file, "default_llseek"))
        return SEEK_PROFILE_DEFAULT;
    if (seek_matches(file, "shmem_file_llseek"))
        return SEEK_PROFILE_SHMEM;
    if (seek_matches(file, "ext4_llseek"))
        return SEEK_PROFILE_EXT4;
    if (seek_matches(file, "f2fs_llseek"))
        return SEEK_PROFILE_F2FS;
    return SEEK_PROFILE_UNKNOWN;
}

static int regular_max_size(struct file *file, struct inode *inode,
                            enum file_seek_profile profile, s64 *maximum)
{
#ifdef DFM_HAVE_FILEATTR_GET
    dfm_fileattr_t attributes = {0};
    int error;
#endif

    if (profile == SEEK_PROFILE_DEFAULT || profile == SEEK_PROFILE_SHMEM) {
        *maximum = MAX_LFS_FILESIZE;
        return 0;
    }
    if (profile == SEEK_PROFILE_GENERIC) {
        *maximum = READ_ONCE(inode->i_sb->s_maxbytes);
        return 0;
    }
#ifdef DFM_HAVE_FILEATTR_GET
    /* Other ext4 and F2FS profiles use per-inode limits. */
    if (!inode->i_op || !inode->i_op->fileattr_get || !file->f_path.dentry)
        return -EOPNOTSUPP;
    error = inode->i_op->fileattr_get(file->f_path.dentry, &attributes);
    if (error)
        return error < 0 ? error : -EIO;
    if (!attributes.flags_valid ||
        (profile == SEEK_PROFILE_EXT4 && !(attributes.flags & FS_EXTENT_FL)) ||
        (profile == SEEK_PROFILE_F2FS && (attributes.flags & FS_COMPR_FL)))
        return -EOPNOTSUPP;
    *maximum = READ_ONCE(inode->i_sb->s_maxbytes);
    return 0;
#else
    return -EOPNOTSUPP;
#endif
}

/* The caller holds shmem's exclusive inode lock. */
static int shmem_seek_position(struct address_space *mapping, s64 size,
                               s64 offset, int whence, s64 *answer)
{
    s64 (*seek_bytes)(struct address_space *, s64, s64, int);
    pgoff_t (*seek_pages)(struct address_space *, pgoff_t, pgoff_t, int);
    pgoff_t start, end, page;

    seek_bytes = (void *)callable_symbol("mapping_seek_hole_data");
    if (seek_bytes) {
        *answer = seek_bytes(mapping, offset, size, whence);
        return 0;
    }

    /* Android 5.10 searches page indices. Restore the byte offset in the
     * first page and use the partial-page file size at EOF. */
    seek_pages = (void *)callable_symbol("shmem_seek_hole_data");
    if (!seek_pages)
        return -EOPNOTSUPP;
    start = (u64)offset >> PAGE_SHIFT;
    end = ((u64)size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    page = seek_pages(mapping, start, end, whence);
    if (page < start)
        return -EIO;
    if (page == start)
        *answer = offset;
    else if (page >= end)
        *answer = whence == SEEK_DATA ? -ENXIO : size;
    else
        *answer = (s64)((u64)page << PAGE_SHIFT);
    return 0;
}

/* Same report operations and shared inode lock as ext4_llseek. */
static int ext4_seek_position(struct inode *inode, s64 offset,
                              int whence, s64 *answer)
{
    const struct iomap_ops *report;
    s64 (*seek)(struct inode *, s64, const struct iomap_ops *);

    report = (void *)kallsyms_lookup_name("ext4_iomap_report_ops");
    seek = (void *)callable_symbol(whence == SEEK_DATA ?
                                  "iomap_seek_data" : "iomap_seek_hole");
    if (!report || !seek)
        return -EOPNOTSUPP;
    *answer = seek(inode, offset, report);
    return 0;
}

static int f2fs_seek_position(struct file *file, struct inode *inode,
                             s64 offset, int whence,
                             struct observed_file *state, s64 *answer)
{
    typeof(&dentry_open) open_path;
    struct file *cursor;
    int error = 0;

    /* F2FS applies its per-inode limit in llseek. The superblock gives
     * an upper bound for validating the result returned to userspace. */
    state->max_size = READ_ONCE(inode->i_sb->s_maxbytes);
    if (state->size > state->max_size ||
        !file->f_path.dentry || !file->f_path.mnt || !file->f_cred)
        return -EIO;
    if (!seek_matches(file, "f2fs_llseek"))
        return -EOPNOTSUPP;
    open_path = (void *)callable_symbol("dentry_open");
    if (!open_path)
        return -EOPNOTSUPP;

    /* O_PATH gives this query a separate cursor and skips F2FS ->open,
     * which can finish preallocation. It never installs a local fd. */
    cursor = open_path(&file->f_path, O_PATH, file->f_cred);
    if (IS_ERR(cursor))
        return PTR_ERR(cursor);
    if (!cursor)
        return -EIO;
    if (cursor == file || !(cursor->f_mode & FMODE_PATH) ||
        cursor->f_path.dentry != file->f_path.dentry ||
        cursor->f_path.mnt != file->f_path.mnt || file_inode(cursor) != inode ||
        cursor->f_mapping != file->f_mapping) {
        error = -ESTALE;
        goto put;
    }
    *answer = file->f_op->llseek(cursor, offset, whence);
    if (i_size_read(inode) != state->size)
        error = -EAGAIN;
put:
    fput(cursor);
    return error;
}

static int regular_seek_position(struct file *file, struct inode *inode,
                                 enum file_seek_profile profile,
                                 s64 offset, int whence,
                                 struct observed_file *state, s64 *answer)
{
    bool exclusive = profile == SEEK_PROFILE_DEFAULT || profile == SEEK_PROFILE_SHMEM;
    bool shared = profile == SEEK_PROFILE_EXT4;
    int error = 0;

    if (exclusive)
        inode_lock(inode);
    else if (shared)
        inode_lock_shared(inode);
    state->size = i_size_read(inode);
    if (state->size < 0) {
        error = -EIO;
        goto unlock;
    }
    /* default_llseek uses a signed EOF check, then validates negative DATA
     * offsets after selecting the HOLE fallback at EOF. */
    if (offset >= state->size || (offset < 0 && profile != SEEK_PROFILE_DEFAULT)) {
        *answer = -ENXIO;
        goto unlock;
    }
    if (profile == SEEK_PROFILE_F2FS) {
        error = f2fs_seek_position(file, inode, offset, whence, state, answer);
        goto unlock;
    }
    error = regular_max_size(file, inode, profile, &state->max_size);
    if (error)
        goto unlock;
    if (profile == SEEK_PROFILE_SHMEM)
        error = shmem_seek_position(file->f_mapping, state->size, offset,
                                    whence, answer);
    else if (profile == SEEK_PROFILE_EXT4)
        error = ext4_seek_position(inode, offset, whence, answer);
    else if (whence == SEEK_HOLE)
        *answer = state->size;
    else
        *answer = offset < 0 ? -EINVAL : offset;
unlock:
    if (exclusive)
        inode_unlock(inode);
    else if (shared)
        inode_unlock_shared(inode);
    return error;
}

static bool file_has_unsigned_offsets(const struct file *file)
{
#ifdef FOP_UNSIGNED_OFFSET
    return file->f_op->fop_flags & FOP_UNSIGNED_OFFSET;
#else
    return READ_ONCE(file->f_mode) & FMODE_UNSIGNED_OFFSET;
#endif
}

static int observe_file(struct file *file, u32 op, s64 offset,
                        struct observed_file *state, s64 *position, int *guest_errno)
{
    const struct file_operations *dma_fops;
    struct inode *inode;
    enum file_seek_profile profile = SEEK_PROFILE_UNKNOWN;
    bool sparse = op != DFM_FILE_OBSERVER_STAT;
    bool seekable;
    int whence = op == DFM_FILE_OBSERVER_SEEK_DATA ? SEEK_DATA : SEEK_HOLE;
    int error;

    if (READ_ONCE(file->f_mode) & FMODE_PATH) {
        *guest_errno = EBADF;
        return 0;
    }
    seekable = READ_ONCE(file->f_mode) & FMODE_LSEEK;
    if (seekable && !file->f_op)
        return -EOPNOTSUPP;
    seekable = seekable && file->f_op->llseek;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
    seekable = seekable && !seek_matches(file, "no_llseek");
#endif
    if (!seekable) {
        *guest_errno = ESPIPE;
        return 0;
    }
    state->initial_position = READ_ONCE(file->f_pos);
    dma_fops = (void *)kallsyms_lookup_name("dma_buf_fops");
    if (dma_fops && file->f_op == dma_fops && seek_matches(file, "dma_buf_llseek")) {
        const struct dma_buf *buffer = file->private_data;
        u64 size;

        if (sparse) {
            *guest_errno = EINVAL;
            return 0;
        }
        if (!buffer || READ_ONCE(buffer->file) != file)
            return -EIO;
        size = READ_ONCE(buffer->size);
        if (size > (u64)MAX_LFS_FILESIZE)
            return -EOVERFLOW;
        state->kind = DFM_FILE_OBSERVER_KIND_DMA_BUF;
        state->size = state->max_size = (s64)size;
    } else {
        inode = file_inode(file);
        if (!inode || !S_ISREG(inode->i_mode) || !inode->i_sb ||
            !file->f_mapping || file->f_mapping->host != inode ||
            file_has_unsigned_offsets(file))
            return -EOPNOTSUPP;
        profile = regular_profile(file);
        if (profile == SEEK_PROFILE_UNKNOWN)
            return -EOPNOTSUPP;
        state->kind = DFM_FILE_OBSERVER_KIND_REGULAR;
        if (sparse)
            error = regular_seek_position(file, inode, profile, offset, whence,
                                          state, position);
        else {
            error = regular_max_size(file, inode, profile, &state->max_size);
            state->size = i_size_read(inode);
        }
        if (error)
            return error;
    }
    if (sparse && *position < 0) {
        if (*position < -4095)
            return -EIO;
        *guest_errno = -(int)*position;
        return 0;
    }
    if (state->initial_position < 0 || state->size < 0 ||
        state->max_size < state->size)
        return -EIO;

    /* A F2FS data search starting before EOF can find a mapped block past it. */
    if (sparse && (*position < offset || *position > state->max_size ||
                   (whence == SEEK_HOLE && *position > state->size) ||
                   (whence == SEEK_DATA && profile != SEEK_PROFILE_F2FS &&
                    *position >= state->size)))
        return -EIO;
    return 0;
}

static int live_target(const struct dfm_file_observer *observer)
{
    struct mm_struct *current_mm = READ_ONCE(observer->task->mm);

    if (!pid_alive(observer->task) || READ_ONCE(observer->task->exit_state) || !current_mm)
        return -ESRCH;
    return current_mm == observer->mm ? 0 : -ESTALE;
}

static int observe_target(struct dfm_file_observer *observer,
                          struct dfm_file_observer_query_req *req)
{
    struct file *(*get_target)(struct task_struct *, unsigned int);
    struct observed_file state = {0};
    struct file *target;
    s64 position = 0;
    unsigned int index;
    int error, guest_errno = 0;

    error = live_target(observer);
    if (error)
        return error;
    if (req->target_fd > INT_MAX) {
        req->out_errno = EBADF;
        return 0;
    }
    get_target = (void *)callable_symbol("fget_task");
    if (!get_target)
        return -EOPNOTSUPP;
    target = get_target(observer->task, req->target_fd);
    if (!target) {
        error = live_target(observer);
        if (!error)
            req->out_errno = EBADF;
        return error;
    }
    error = observe_file(target, req->op, req->offset, &state, &position,
                         &guest_errno);
    if (error)
        goto put;
    error = live_target(observer);
    if (error)
        goto put;
    if (guest_errno) {
        req->out_errno = guest_errno;
        goto put;
    }

    /* Holding a reference prevents pointer reuse for the life of this
     * observer. Only the small, per-observer token leaves the kernel. */
    for (index = 0; index < observer->count; ++index)
        if (observer->files[index] == target)
            break;
    if (index == observer->count) {
        if (index == DFM_FILE_OBSERVER_MAX_FILES) {
            error = -E2BIG;
            goto put;
        }
        observer->files[observer->count++] = get_file(target);
    }
    req->out_identity = index + 1;
    req->out_initial_position = state.initial_position;
    req->out_size = state.size;
    req->out_max_size = state.max_size;
    req->out_position = position;
    req->out_kind = state.kind;
put:
    fput(target);
    return error;
}

static long observer_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
    struct dfm_file_observer *observer = file->private_data;
    struct dfm_file_observer_query_req req;
    void __user *user = (void __user *)arg;
    int error;

    BUILD_BUG_ON(sizeof(req) != 88U);
    BUILD_BUG_ON(offsetof(struct dfm_file_observer_query_req, out_identity) != 24U);
    BUILD_BUG_ON(offsetof(struct dfm_file_observer_query_req, out_errno) != 68U);
    if (command != DFM_FILE_OBSERVER_IOC_QUERY)
        return -ENOTTY;
    if (copy_from_user(&req, user, sizeof(req)))
        return -EFAULT;
    if (req.version != DFM_FILE_OBSERVER_ABI_VERSION || req.reserved0 ||
        req.reserved[0] || req.reserved[1] ||
        (req.op != DFM_FILE_OBSERVER_STAT &&
         req.op != DFM_FILE_OBSERVER_SEEK_DATA && req.op != DFM_FILE_OBSERVER_SEEK_HOLE) ||
        (req.op == DFM_FILE_OBSERVER_STAT && req.offset))
        return -EINVAL;
    req.out_identity = 0;
    req.out_initial_position = req.out_size = req.out_max_size = req.out_position = 0;
    req.out_kind = req.out_errno = 0;

    mutex_lock(&observer->lock);
    error = observe_target(observer, &req);
    mutex_unlock(&observer->lock);
    if (error)
        return error;
    return copy_to_user(user, &req, sizeof(req)) ? -EFAULT : 0;
}

static void free_observer(struct dfm_file_observer *observer)
{
    for (unsigned int index = 0; index < observer->count; ++index)
        fput(observer->files[index]);
    if (observer->mm)
        mmdrop(observer->mm);
    if (observer->task)
        put_task_struct(observer->task);
    if (observer->owner)
        fput(observer->owner);
    kfree(observer);
}

static int observer_release(struct inode *inode, struct file *file)
{
    free_observer(file->private_data);
    return 0;
}

static const struct file_operations observer_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = observer_ioctl,
    .compat_ioctl = observer_ioctl,
    .release = observer_release,
};

long dfm_file_observer_open(struct file *owner, void __user *arg)
{
    struct dfm_file_observer_open_req req;
    struct dfm_file_observer *observer;
    struct mm_struct *mm;
    struct file *file;
    struct pid *tid;
    int fd, error;

    BUILD_BUG_ON(sizeof(req) != 32U);
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.version != DFM_FILE_OBSERVER_ABI_VERSION || req.pid <= 0 ||
        req.tid <= 0 || req.reserved[0] || req.reserved[1])
        return -EINVAL;
    observer = kzalloc(sizeof(*observer), GFP_KERNEL);
    if (!observer)
        return -ENOMEM;
    mutex_init(&observer->lock);
    tid = find_get_pid(req.tid);
    observer->task = get_pid_task(tid, PIDTYPE_PID);
    put_pid(tid);
    error = -ESRCH;
    if (!observer->task || task_tgid_vnr(observer->task) != req.pid)
        goto free;
    mm = get_task_mm(observer->task);
    if (!mm)
        goto free;
    mmgrab(mm);
    observer->mm = mm;
    mmput(mm);
    error = live_target(observer);
    if (error)
        goto free;

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        error = fd;
        goto free;
    }
    /* Keep the DFM client alive until the last observer closes. */
    observer->owner = get_file(owner);
    file = anon_inode_getfile("[dfm-file-observer]", &observer_fops, observer,
                             O_RDONLY | O_CLOEXEC);
    if (IS_ERR(file)) {
        put_unused_fd(fd);
        error = PTR_ERR(file);
        goto free;
    }
    req.out_fd = fd;
    if (copy_to_user(arg, &req, sizeof(req))) {
        put_unused_fd(fd);
        fput(file);
        return -EFAULT;
    }
    fd_install(fd, file);
    return 0;
free:
    free_observer(observer);
    return error;
}
