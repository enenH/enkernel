# Read-only target file queries

`DFM_FILE_IOC_QUERY_FD` / `dfm::query_file()` addresses a regular file by PID and
descriptor number, without exposing a kernel pointer or installing a local fd.
It follows the existing driver-fd authorization model used by `KGSL_QUERY`.
There are no package, pathname or filesystem-layout constants.

| Operation | Inputs | Result |
| --- | --- | --- |
| `INFO` | PID, fd | File size, position, inode, encoded device, mode |
| `PREAD` | PID, fd, offset, buffer, size (1..1 MiB) | Bytes read; zero at EOF |
| `SEEK` | PID, fd, signed offset, whence (0..2) | Virtual SET/CUR/END offset; no filesystem callback |

Initialize requests to zero. The SDK supplies ABI version 1. A negative return
is a request/transport/task failure; on zero return, check `out_errno` before
using outputs. Old modules return `-ENOTTY`. The optional capability is
`DFM_CAP_FILE_QUERY_FD`; it is not added to the existing required-feature mask.

```cpp
dfm_file_query_req request{};
request.op = DFM_FILE_QUERY_SEEK;
request.pid = target_pid;
request.target_fd = target_fd;
request.whence = 2; // SEEK_END
request.offset = 0;
long transport = dfm::query_file(request);
if (transport == 0 && request.out_errno == 0) {
    // request.out_result is the sampled file size plus request.offset.
}
```

Each request acquires a refcounted target file under the task/fdtable locks.
`INFO` samples its position under `f_pos_lock`. `PREAD` calls `kernel_read()` on
that exact file with a separate position variable, the original opening
credentials and normal VFS/LSM read checks. It preserves the open description's
flags (including direct-I/O/alignment restrictions) and private state. There is
no `dentry_open()`, pathname/procfs fallback, or new open description, including
when a read fails or the target has been renamed/unlinked. The target position
is never changed or temporarily saved/restored.

`SEEK` computes a virtual offset from zero (`SET`), the sampled target position
(`CUR`), or the sampled file size (`END`). Overflow returns `EOVERFLOW`; negative
results or results above the filesystem's `s_maxbytes` return `EINVAL`. It never
calls `vfs_llseek()` or a filesystem `llseek` callback, so filesystem-private
cursor/validation rules are not emulated. `SEEK_DATA`/`SEEK_HOLE` explicitly
return `EOPNOTSUPP`: no extent or file-content approximation is made. An emulator
with its own cursor should use `SEEK_SET` rather than accumulate `SEEK_CUR` calls.
Missing `FMODE_PREAD`/`FMODE_LSEEK` returns `ESPIPE` for the respective operation.
Sockets, pipes, devices and directories are rejected. Write-only and
`O_PATH` descriptors do not grant PREAD/SEEK. This interface cannot write,
truncate, close or change the target descriptor's flags.

This is an observation, not a snapshot or fd reservation. Close/reuse can occur
between calls; callers can compare the returned identity where appropriate.
File contents and metadata can change concurrently. Reading may have ordinary
filesystem/LSM/atime effects and update read-related file-private state; only the
target cursor is guaranteed unchanged. The two metadata samples are not atomic.

Build the Android SDK with `-DENKERNEL_BUILD_TESTS=ON` to build
`tests/dfm_fd_query_check`. Run it on an authorized device with the new driver
already loaded. It exercises virtual seek comparisons, rejected DATA/HOLE, EOF,
offset preservation under a concurrent observer, remote PID reads, invalid
requests/types, and target exit. Exit 77 explicitly means the loaded module
does not support the new ABI; it is not a passing runtime test.

`python tests/run_fd_query_host.py` runs the production request/operation code
against an instrumented file model, checking original-file reads, preserved
flags/credentials/cursor, mode restrictions, seek boundaries, and error cleanup.
It does not replace kernel-module builds or device runtime validation.
