#define pr_fmt(fmt) KBUILD_MODNAME ": file_io: " fmt

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "abi.h"
#include "file_io.h"

#define DFM_FILE_ROOT "/data/adb"
#define DFM_FILE_PREFIX DFM_FILE_ROOT "/"
#define DFM_MODEL_ROOT DFM_FILE_ROOT "/model"
#define DFM_MODEL_PREFIX DFM_MODEL_ROOT "/"
#define DFM_FILE_WRITE_FLAGS \
    (DFM_FILE_WRITE_CREATE | DFM_FILE_WRITE_TRUNCATE)

static struct cred *g_file_cred;
static DEFINE_MUTEX(g_file_io_lock);

static bool caller_allowed(void)
{
    uid_t uid = __kuid_val(current_uid());

    return uid == 0 || uid == 1000;
}

static bool valid_leaf_name(const char *name)
{
    return name[0] != '\0' && !strchr(name, '/') &&
           strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

/* Writes remain limited to direct /data/adb children. Reads additionally
 * accept exactly one fixed intermediate directory:
 * /data/adb/model/<leaf>. */
static int validate_path(struct dfm_file_io_req *req, bool writing,
                         bool *model_path)
{
    const char *path;
    const char *name;
    size_t prefix_len = sizeof(DFM_FILE_PREFIX) - 1;
    size_t model_prefix_len = sizeof(DFM_MODEL_PREFIX) - 1;

    if (model_path)
        *model_path = false;

    if (!memchr(req->path, '\0', sizeof(req->path)))
        return -ENAMETOOLONG;

    path = req->path;
    if (!writing && strncmp(path, DFM_MODEL_PREFIX, model_prefix_len) == 0) {
        name = path + model_prefix_len;
        if (!valid_leaf_name(name))
            return -EACCES;
        if (model_path)
            *model_path = true;
        return 0;
    }

    if (strncmp(path, DFM_FILE_PREFIX, prefix_len) != 0 ||
        path[prefix_len] == '\0')
        return -EACCES;

    name = path + prefix_len;
    if (!valid_leaf_name(name))
        return -EACCES;
    return 0;
}

static int validate_model_directory(void)
{
    struct file *directory;
    struct inode *inode;
    int ret = 0;

    directory = filp_open(DFM_MODEL_ROOT,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                          0);
    if (IS_ERR(directory))
        return PTR_ERR(directory);

    /* Model installers may use app-owned directories or 0777. Do not add
     * owner/mode gates; retain the fixed path, no-follow, and type checks. */
    inode = file_inode(directory);
    if (!S_ISDIR(inode->i_mode))
        ret = -EACCES;
    filp_close(directory, NULL);
    return ret;
}

static int validate_buffer(const struct dfm_file_io_req *req, bool writing)
{
    if (req->size > DFM_FILE_IO_MAX)
        return -E2BIG;
    if (!writing && req->size == 0)
        return -EINVAL;
    if (req->offset > LLONG_MAX ||
        req->size > (uint64_t)LLONG_MAX - req->offset)
        return -EOVERFLOW;
    if (req->size != 0 &&
        (req->buf == 0 ||
         !access_ok((void __user *)(unsigned long)req->buf,
                    (size_t)req->size)))
        return -EFAULT;
    return 0;
}

static struct file *open_config_file(const char *path, int flags)
{
    return filp_open(path, flags, 0600);
}

static long copy_result_to_user(void __user *arg,
                                struct dfm_file_io_req *req)
{
    if (copy_to_user(arg, req, sizeof(*req)))
        return -EFAULT;
    return 0;
}

long dfm_file_read(void __user *arg)
{
    struct dfm_file_io_req req;
    const struct cred *old_cred;
    struct file *file = NULL;
    char *buffer = NULL;
    loff_t pos;
    uint64_t done = 0;
    bool model_path = false;
    long ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    req.out_size = 0;
    req.out_file_size = 0;

    if (!caller_allowed())
        return -EACCES;
    if (req.flags != 0 || req.reserved != 0)
        return -EINVAL;
    ret = validate_path(&req, false, &model_path);
    if (ret)
        return ret;
    ret = validate_buffer(&req, false);
    if (ret)
        return ret;
    if (!g_file_cred)
        return -ENODEV;

    buffer = kmalloc(min_t(size_t, (size_t)req.size, PAGE_SIZE), GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    mutex_lock(&g_file_io_lock);
    old_cred = override_creds(g_file_cred);
    if (model_path) {
        ret = validate_model_directory();
        if (ret)
            goto out;
    }
    file = open_config_file(req.path,
                            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        file = NULL;
        goto out;
    }
    if (!S_ISREG(file_inode(file)->i_mode)) {
        ret = -EINVAL;
        goto out;
    }

    req.out_file_size = (uint64_t)i_size_read(file_inode(file));
    pos = (loff_t)req.offset;
    while (done < req.size) {
        size_t chunk = min_t(uint64_t, req.size - done, PAGE_SIZE);
        ssize_t count = kernel_read(file, buffer, chunk, &pos);

        if (count < 0) {
            ret = count;
            goto out;
        }
        if (count == 0)
            break;
        if (copy_to_user((char __user *)(unsigned long)(req.buf + done),
                         buffer, count)) {
            ret = -EFAULT;
            goto out;
        }
        done += count;
    }

    req.out_size = done;
    ret = 0;

out:
    if (file)
        filp_close(file, NULL);
    revert_creds(old_cred);
    mutex_unlock(&g_file_io_lock);
    kfree(buffer);
    if (ret)
        return ret;
    return copy_result_to_user(arg, &req);
}

long dfm_file_write(void __user *arg)
{
    struct dfm_file_io_req req;
    const struct cred *old_cred;
    struct file *file = NULL;
    char *buffer = NULL;
    loff_t pos;
    uint64_t done = 0;
    int open_flags = O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    long ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    req.out_size = 0;
    req.out_file_size = 0;

    if (!caller_allowed())
        return -EACCES;
    if ((req.flags & ~DFM_FILE_WRITE_FLAGS) != 0 || req.reserved != 0)
        return -EINVAL;
    if ((req.flags & DFM_FILE_WRITE_TRUNCATE) && req.offset != 0)
        return -EINVAL;
    ret = validate_path(&req, true, NULL);
    if (ret)
        return ret;
    ret = validate_buffer(&req, true);
    if (ret)
        return ret;
    if (!g_file_cred)
        return -ENODEV;

    if (req.flags & DFM_FILE_WRITE_CREATE)
        open_flags |= O_CREAT;
    if (req.flags & DFM_FILE_WRITE_TRUNCATE)
        open_flags |= O_TRUNC;

    if (req.size != 0) {
        buffer = kmalloc(min_t(size_t, (size_t)req.size, PAGE_SIZE),
                         GFP_KERNEL);
        if (!buffer)
            return -ENOMEM;
    }

    mutex_lock(&g_file_io_lock);
    old_cred = override_creds(g_file_cred);
    file = open_config_file(req.path, open_flags);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        file = NULL;
        goto out;
    }
    if (!S_ISREG(file_inode(file)->i_mode)) {
        ret = -EINVAL;
        goto out;
    }

    pos = (loff_t)req.offset;
    while (done < req.size) {
        size_t chunk = min_t(uint64_t, req.size - done, PAGE_SIZE);
        ssize_t count;

        if (copy_from_user(buffer,
                           (char __user *)(unsigned long)(req.buf + done),
                           chunk)) {
            ret = -EFAULT;
            goto out;
        }
        count = kernel_write(file, buffer, chunk, &pos);
        if (count < 0) {
            ret = count;
            goto out;
        }
        if (count == 0) {
            ret = -EIO;
            goto out;
        }
        done += count;
    }

    req.out_size = done;
    req.out_file_size = (uint64_t)i_size_read(file_inode(file));
    ret = 0;

out:
    if (file)
        filp_close(file, NULL);
    revert_creds(old_cred);
    mutex_unlock(&g_file_io_lock);
    kfree(buffer);
    if (ret)
        return ret;
    return copy_result_to_user(arg, &req);
}

int dfm_file_io_init(void)
{
    struct cred *cred;
    const char *secctx = "u:r:ksu:s0";
    int ret;

    cred = prepare_kernel_cred(&init_task);
    if (!cred)
        return -ENOMEM;

    /* Keep init_task's root identity, but use the root manager's SELinux
     * domain for file I/O. An unknown context returns -EINVAL; do not
     * treat allocation or permission failures as a missing KSU domain. */
    ret = set_security_override_from_ctx(cred, secctx);
    if (ret == -EINVAL) {
        secctx = "u:r:magisk:s0";
        ret = set_security_override_from_ctx(cred, secctx);
    }
    if (ret == -EINVAL) {
        secctx = "u:r:su:s0";
        ret = set_security_override_from_ctx(cred, secctx);
    }
    if (ret) {
        pr_err("failed to set file I/O context %s: %d\n", secctx, ret);
    }

    g_file_cred = cred;
    pr_info("file I/O context: %s\n", secctx);
    return 0;
}

void dfm_file_io_exit(void)
{
    if (g_file_cred) {
        put_cred(g_file_cred);
        g_file_cred = NULL;
    }
}
