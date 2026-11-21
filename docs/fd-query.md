# Read-only target file queries

`DFM_FILE_IOC_QUERY_FD` / `dfm::query_file()` addresses a regular file by PID and
descriptor number, without exposing a kernel pointer or installing a local fd.
It follows the existing driver-fd authorization model used by `KGSL_QUERY`.
There are no package, pathname or filesystem-layout constants.

| Operation | Inputs | Result |
| --- | --- | --- |
| `INFO` | PID, fd | File size, position, inode, encoded device, mode |
| `PREAD` | PID, fd, offset, buffer, size (1..1 MiB) | Bytes read; zero at EOF |
| `SEEK` | PID, fd, signed offset, whence (0..4) | Filesystem seek result |

Initialize requests to zero. The SDK supplies ABI version 1. A negative return
is a request/transport/task failure; on zero return, check `out_errno` before
using outputs. Old modules return `-ENOTTY`. The optional capability is
`DFM_CAP_FILE_QUERY_FD`; it is not added to the existing required-feature mask.

```cpp
dfm_file_query_req request{};
request.op = DFM_FILE_QUERY_SEEK;
request.pid = target_pid;
request.target_fd = target_fd;
request.whence = 3; // SEEK_DATA
request.offset = 0;
long transport = dfm::query_file(request);
if (transport == 0 && request.out_errno == 0) {
    // request.out_result is the first data offset reported by the filesystem.
}
```

Each request acquires a refcounted target file under the task/fdtable locks.
`INFO` samples its position under `f_pos_lock`. I/O and seek use an independent
read-only open description of the same pinned path, with the original opening
credentials and normal VFS/LSM checks. The target position is never changed or
temporarily saved/restored. `SEEK_CUR` uses the sampled target position. An
emulator with its own virtual cursor should instead use `SEEK_SET`.

`SEEK_DATA`/`SEEK_HOLE` are delegated to the filesystem, including its native
`ENXIO`/unsupported behavior. The implementation does not infer data from file
contents. Sockets, pipes, devices and directories are rejected. Write-only and
`O_PATH` descriptors do not grant PREAD/SEEK. This interface cannot write,
truncate, close or change the target descriptor's flags.

This is an observation, not a snapshot or fd reservation. Close/reuse can occur
between calls; callers can compare the returned identity where appropriate.
File contents and metadata can change concurrently. Opening/reading may have
ordinary filesystem/LSM/atime effects, and a filesystem can refuse reopening.

Build the Android SDK with `-DENKERNEL_BUILD_TESTS=ON` to build
`tests/dfm_fd_query_check`. Run it on an authorized device with the new driver
already loaded. It exercises native seek comparisons, sparse data/holes, EOF,
offset preservation under a concurrent observer, remote PID reads, invalid
requests/types, and target exit. Exit 77 explicitly means the loaded module
does not support the new ABI; it is not a passing runtime test.
