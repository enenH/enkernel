/* Fault-injected file model; operation bodies come directly from fd_query.c. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t u64;
#define loff_t int64_t
#define ssize_t intptr_t
#define __user
#define GFP_KERNEL 0
#define FMODE_READ 1
#define FMODE_PREAD 2
#define FMODE_LSEEK 4
#define SEEK_DATA 3
#define SEEK_HOLE 4
#define S_ISREG(mode) (((mode) & 0170000) == 0100000)
#define check_add_overflow(a, b, out) __builtin_add_overflow(a, b, out)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define u64_to_user_ptr(p) ((void *)(uintptr_t)(p))
struct cred { int id; };
struct super_block { unsigned int s_dev; loff_t s_maxbytes; };
struct inode { unsigned int i_mode; u64 i_ino; loff_t size; struct super_block *i_sb; };
struct file {
    unsigned int f_mode, f_flags;
    loff_t f_pos;
    int f_pos_lock;
    struct inode *inode;
    const struct cred *f_cred;
    void *private_data;
};
static struct cred caller = {1}, opener = {2};
static const struct cred *active_cred = &caller;
static struct super_block sb;
static struct inode inode;
static struct file target;
static int refs, allocations, reads, lookup_error, read_error;
static bool fail_alloc, fail_input;
static void *fail_output;
static unsigned int expected_flags;
static int private_cookie;
static struct inode *file_inode(struct file *file) { return file->inode; }
static loff_t i_size_read(struct inode *node) { return node->size; }
static u64 new_encode_dev(unsigned int dev) { return dev; }
static void mutex_lock(int *lock) { assert(!*lock); *lock = 1; }
static void mutex_unlock(int *lock) { assert(*lock); *lock = 0; }
static struct file *target_file(int pid, unsigned int fd)
{
    assert(pid == 123 && fd == 7);
    if (lookup_error) return ERR_PTR(-lookup_error);
    ++refs;
    return &target;
}
static void fput(struct file *file) { assert(file == &target && refs == 1); --refs; }
static bool access_ok(void *ptr, u64 size) { return (uintptr_t)ptr > 4096 && size; }
static int copy_from_user(void *dst, const void *src, size_t size)
{
    if (fail_input) return 1;
    memcpy(dst, src, size);
    return 0;
}
static int copy_to_user(void *dst, const void *src, size_t size)
{
    if (dst == fail_output) return 1;
    memcpy(dst, src, size);
    return 0;
}
static void *kvmalloc(size_t size, int flags)
{
    void *buffer;
    (void)flags;
    if (fail_alloc) return NULL;
    buffer = malloc(size);
    assert(buffer);
    ++allocations;
    return buffer;
}
static void kvfree(void *ptr) { if (ptr) { --allocations; free(ptr); } }
static const struct cred *override_creds(const struct cred *cred)
{
    assert(active_cred == &caller && cred == &opener);
    active_cred = cred;
    return &caller;
}
static void revert_creds(const struct cred *cred)
{
    assert(active_cred == &opener && cred == &caller);
    active_cred = cred;
}
static ssize_t kernel_read(struct file *file, void *buffer, size_t size, loff_t *pos)
{
    static const char contents[] = "abcdef";
    size_t count;
    assert(file == &target && refs == 1);
    assert(file->f_flags == expected_flags && file->private_data == &private_cookie);
    assert(active_cred == &opener && !file->f_pos_lock);
    assert(pos != &file->f_pos && file->f_pos == 123);
    ++reads;
    if (read_error) return -read_error;
    if (*pos >= 6) return 0;
    count = 6 - *pos;
    if (count > size) count = size;
    memcpy(buffer, contents + *pos, count);
    *pos += count;
    return count;
}

#include "fd_query_under_test.h"

static char bytes[16];
static struct dfm_file_query_req request(unsigned int op)
{
    struct dfm_file_query_req req = {0};
    req.abi_version = DFM_FILE_QUERY_ABI_VERSION;
    req.op = op; req.pid = 123; req.target_fd = 7;
    if (op == DFM_FILE_QUERY_PREAD) { req.buf = (uintptr_t)bytes; req.size = 8; }
    return req;
}
static void reset(void)
{
    assert(!refs && !allocations && active_cred == &caller);
    sb = (struct super_block){17, LLONG_MAX};
    inode = (struct inode){0100600, 42, 6, &sb};
    target = (struct file){FMODE_READ | FMODE_PREAD | FMODE_LSEEK,
                           0x84000, 123, 0, &inode, &opener, &private_cookie};
    expected_flags = target.f_flags;
    reads = lookup_error = read_error = 0;
    fail_alloc = fail_input = false; fail_output = NULL;
    memset(bytes, 0x55, sizeof(bytes));
}
static void cleared(const struct dfm_file_query_req *req)
{
    assert(!req->out_size && !req->out_result && !req->out_file_size);
    assert(!req->out_position && !req->out_inode && !req->out_device && !req->out_mode);
}
static void run(struct dfm_file_query_req *req, long transport, int error)
{
    req->out_inode = UINT64_MAX;
    assert(dfm_file_query_fd(req) == transport);
    assert(req->out_errno == error);
    assert(!refs && !allocations && active_cred == &caller && !target.f_pos_lock);
    assert(target.f_pos == 123 && target.f_flags == expected_flags);
    if (transport || error) cleared(req);
    else assert(req->out_inode == 42 && req->out_position == 123);
}
int main(void)
{
    struct dfm_file_query_req req;
    unsigned int whence;
    reset();
    req = request(DFM_FILE_QUERY_INFO); run(&req, 0, 0);
    assert(req.out_file_size == 6 && req.out_device == 17 && !reads);
    req = request(DFM_FILE_QUERY_PREAD); req.offset = 3; run(&req, 0, 0);
    assert(req.out_size == 3 && !memcmp(bytes, "def", 3) && bytes[3] == 0x55);
    req.offset = 6; run(&req, 0, 0); assert(!req.out_size);
    req.offset = 20; run(&req, 0, 0); assert(!req.out_size);
    req.offset = 0; req.size = 2; run(&req, 0, 0);
    assert(req.out_size == 2 && !memcmp(bytes, "ab", 2) && reads == 4);

    reset();
    for (whence = SEEK_SET; whence <= SEEK_END; ++whence) {
        req = request(DFM_FILE_QUERY_SEEK); req.whence = whence; req.offset = 2;
        run(&req, 0, 0);
        assert(req.out_result == (whence == SEEK_SET ? 2 : whence == SEEK_CUR ? 125 : 8));
    }
    for (whence = SEEK_DATA; whence <= SEEK_HOLE; ++whence) {
        req = request(DFM_FILE_QUERY_SEEK); req.whence = whence; run(&req, 0, EOPNOTSUPP);
    }
    assert(!reads);
    req = request(DFM_FILE_QUERY_SEEK); req.offset = LLONG_MAX; run(&req, 0, 0);
    req.offset = -1; run(&req, 0, EINVAL);
    req.offset = LLONG_MIN; run(&req, 0, EINVAL);
    req.whence = SEEK_CUR; req.offset = -123; run(&req, 0, 0); assert(!req.out_result);
    req.offset = -124; run(&req, 0, EINVAL);
    req.offset = LLONG_MAX; run(&req, 0, EOVERFLOW);
    req.whence = SEEK_END; run(&req, 0, EOVERFLOW);
    req.offset = -7; run(&req, 0, EINVAL);
    req.offset = -6; run(&req, 0, 0); assert(!req.out_result);
    sb.s_maxbytes = 5; req.offset = 0; run(&req, 0, EINVAL);
    req.whence = SEEK_SET; req.offset = 5; run(&req, 0, 0);

    reset();
    target.f_mode &= ~FMODE_PREAD;
    req = request(DFM_FILE_QUERY_PREAD); run(&req, 0, ESPIPE); assert(!reads);
    target.f_mode &= ~FMODE_LSEEK;
    req = request(DFM_FILE_QUERY_SEEK); run(&req, 0, ESPIPE);
    target.f_mode = 0;
    req = request(DFM_FILE_QUERY_INFO); run(&req, 0, 0);
    req = request(DFM_FILE_QUERY_PREAD); run(&req, 0, EBADF);
    req = request(DFM_FILE_QUERY_SEEK); run(&req, 0, EBADF);
    inode.i_mode = 0140600;
    req = request(DFM_FILE_QUERY_INFO); run(&req, 0, EOPNOTSUPP);

    reset();
    req = request(DFM_FILE_QUERY_PREAD); read_error = EIO; run(&req, 0, EIO);
    assert(reads == 1 && bytes[0] == 0x55);
    read_error = EINVAL; run(&req, 0, EINVAL); /* e.g. original O_DIRECT restrictions */
    assert(reads == 2 && bytes[0] == 0x55);
    read_error = 0; fail_alloc = true; run(&req, -ENOMEM, 0); assert(reads == 2);
    fail_alloc = false; fail_output = bytes; run(&req, -EFAULT, 0);
    fail_output = &req; assert(dfm_file_query_fd(&req) == -EFAULT);
    assert(!refs && !allocations && active_cred == &caller);
    fail_output = NULL; fail_input = true; assert(dfm_file_query_fd(&req) == -EFAULT);
    fail_input = false; lookup_error = ESRCH; run(&req, -ESRCH, 0);
    lookup_error = EBADF; run(&req, 0, EBADF);

    reset();
    req = request(DFM_FILE_QUERY_PREAD); req.abi_version = 0; run(&req, -EINVAL, 0);
    req = request(DFM_FILE_QUERY_PREAD); req.size = DFM_FILE_QUERY_MAX_READ + 1; run(&req, -E2BIG, 0);
    req.size = 2; req.offset = LLONG_MAX; run(&req, -EOVERFLOW, 0);
    req.offset = 0; req.buf = 1; run(&req, -EFAULT, 0);
    req = request(DFM_FILE_QUERY_SEEK); req.whence = 5; run(&req, -EINVAL, 0);
    assert(!reads);
    puts("PASS: original file/flags/credentials, virtual seek, unchanged cursor, errors and cleanup");
    return 0;
}
