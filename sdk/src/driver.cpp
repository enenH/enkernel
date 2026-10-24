#include <dfm/driver.h>
#include "log.h"
#include <dfm/abi.h>

#include <unistd.h>
#include <sys/syscall.h>
#include <cerrno>
#include <cstring>
#include <limits>

static_assert(sizeof(dfm_kgsl_syncsource_peek_req) == 32U);
static_assert(sizeof(dfm_kgsl_query_req) == 120U);
static_assert(offsetof(dfm_kgsl_query_req, excluded_ids) == 32U);
static_assert(offsetof(dfm_kgsl_query_req, out_info) == 56U);
static_assert(sizeof(dfm_kgsl_gpuobj_info) == 48U);
static_assert(sizeof(mem_thread_tid_info) == 16U);
static_assert(sizeof(mem_get_thread_tids_req) == 1296U);
static_assert(sizeof(udp_cap_packet) == 2088U);
static_assert(sizeof(udp_cap_init_req) == 16U);
static_assert(sizeof(udp_cap_read_req) == 40U);
static_assert(sizeof(mem_query_mapping_req) == 40U);
static_assert(sizeof(mem_query_access_req) == 40U);
static_assert(sizeof(mem_open_process_mem_req) == 40U);
static_assert(sizeof(mem_process_mem_arm_req) == 40U);
static_assert(sizeof(mem_query_signal_req) == 72U);
static_assert(offsetof(mem_query_signal_req, out_alt_sp) == 48U);
static_assert(offsetof(mem_query_mapping_req, out_phys_addr) == 16U);
static_assert(sizeof(dfm_file_io_req) == 304U);
static_assert(sizeof(dfm_sf_groups_req) == 32U);

namespace dfm {
    static int g_fd = -1;
    static thread_local long g_last_ioctl_result = 0;

    static long call_ioctl(int fd, unsigned long request, long argument) {
        const long result = syscall(__NR_ioctl, fd, request, argument);
        // Preserve the SDK's negative-errno result convention.
        g_last_ioctl_result = result == -1 ? -errno : result;
        return g_last_ioctl_result;
    }

    int native_handle() { return g_fd; }

    bool supports_process_mem() {
        if (g_fd < 0) return false;
        mem_open_process_mem_req req{}; // invalid version: no session or writes
        return call_ioctl(g_fd, MEM_IOC_OPEN_PROCESS_MEM, (long)&req) == -EINVAL;
    }

    long open_process_mem(int pid, mem_open_process_mem_req& out) {
        out = {};
        out.out_fd = -1;
        if (g_fd < 0) return -EBADF;
        if (pid <= 0) return -EINVAL;
        mem_open_process_mem_req req{};
        req.version = MEM_PROCESS_MEM_ABI_VERSION;
        req.pid = pid;
        req.out_fd = -1;
        const long ret = call_ioctl(g_fd, MEM_IOC_OPEN_PROCESS_MEM, (long)&req);
        if (ret == 0) out = req;
        return ret;
    }

    long query_process_mem_access(int fd, int pid, uint64_t addr,
                                  mem_query_access_req& out) {
        out = {};
        if (fd < 0) return -EBADF;
        mem_query_access_req req{};
        req.pid = pid;
        req.addr = addr;
        const long ret = call_ioctl(fd, MEM_IOC_QUERY_ACCESS, (long)&req);
        if (ret == 0) out = req;
        return ret;
    }

    long arm_process_mem_patch(int fd, uint64_t got, uint64_t original,
                               uint64_t replacement, uint64_t delta) {
        if (fd < 0) return -EBADF;
        mem_process_mem_arm_req req{};
        req.version = MEM_PROCESS_MEM_ABI_VERSION;
        req.got_addr = got;
        req.original = original;
        req.replacement = replacement;
        req.delta_addr = delta;
        return call_ioctl(fd, MEM_PROCESS_MEM_IOC_ARM, (long)&req);
    }

    long query_mapping(int pid, uint64_t addr, mem_query_mapping_req& out) {
        out = {};
        if (g_fd < 0) return -EBADF;
        if (pid <= 0) return -EINVAL;
        mem_query_mapping_req req{};
        req.pid = pid;
        req.addr = addr;
        const long result = call_ioctl(g_fd,
                                       MEM_IOC_QUERY_MAPPING, (long)&req);
        if (result == 0) out = req;
        return result;
    }

    long query_access(int pid, uint64_t addr, mem_query_access_req& out) {
        out = {};
        if (g_fd < 0) return -EBADF;
        if (pid <= 0) return -EINVAL;
        mem_query_access_req req{};
        req.pid = pid;
        req.addr = addr;
        const long result = call_ioctl(g_fd, MEM_IOC_QUERY_ACCESS, (long)&req);
        if (result == 0) out = req;
        return result;
    }

    long query_signal(int tid, uint32_t signo, mem_query_signal_req& out) {
        out = {};
        if (g_fd < 0) return -EBADF;
        if (tid <= 0 || signo == 0 || signo > 64) return -EINVAL;
        mem_query_signal_req req{};
        req.tid = tid;
        req.signo = signo;
        const long result = call_ioctl(g_fd, MEM_IOC_QUERY_SIGNAL, (long)&req);
        if (result == 0) out = req;
        return result;
    }

    static bool install_fd_via_syscall(long nr, int& fd) {
        fd = -1;
        syscall(nr, INSTALL_MAGIC1, INSTALL_MAGIC2, 0, &fd);
        return fd >= 0;
    }

    static bool install_fd_via_syscall_scan(int& fd) {
        static constexpr long kSingleCandidates[] = {
                18, 38, 42, 163, 164,
        };

        for (long nr : kSingleCandidates) {
            if (install_fd_via_syscall(nr, fd))
                return true;
        }

        for (long nr = 244; nr <= 259; ++nr) {
            if (install_fd_via_syscall(nr, fd))
                return true;
        }

        for (long nr = 295; nr <= 423; ++nr) {
            if (install_fd_via_syscall(nr, fd))
                return true;
        }

        return false;
    }

    bool init() {
        if (g_fd >= 0)
            return true;

        int fd = -1;
        if (install_fd_via_syscall_scan(fd)) {
            g_fd = fd;
            LOGD("dfm::init() success via syscall scan: fd=%d", g_fd);
            return true;
        }

        fd = -1;
        syscall(__NR_reboot, INSTALL_MAGIC1, INSTALL_MAGIC2, 0, &fd);

        if (fd < 0) {
            LOGE("dfm::init() failed: fd=%d (kernel module may not be loaded)", fd);
            return false;
        }

        g_fd = fd;
        LOGD("dfm::init() success via reboot fallback: fd=%d", g_fd);
        return true;
    }

    void close() {
        if (g_fd >= 0) {
            ::close(g_fd);
            g_fd = -1;
        }
    }

    int get_process_id(const char* name) {
        if (!name || !*name) return -1;
        mem_get_pid_req req{};
        strncpy(req.name, name, sizeof(req.name) - 1);

        if (call_ioctl(g_fd, MEM_IOC_GET_PID, (long)&req) < 0)
            return -1;

        return req.out_pid;
    }

    bool get_process_ids(const char* name, int* out_pids, size_t capacity,
                         size_t& out_count, bool& truncated) {
        out_count = 0;
        truncated = false;
        if (!name || !*name || !out_pids || capacity == 0)
            return false;

        mem_get_pids_req req{};
        strncpy(req.name, name, sizeof(req.name) - 1);
        const long result =
            call_ioctl(g_fd, MEM_IOC_GET_PIDS, (long)&req);
        if (result == -ENOTTY) {
            const int pid = get_process_id(name);
            if (pid <= 0)
                return false;
            out_pids[0] = pid;
            out_count = 1;
            truncated = true;
            return true;
        }
        if (result < 0)
            return false;

        size_t available = req.out_count;
        if (available > MEM_GET_PIDS_MAX)
            available = MEM_GET_PIDS_MAX;
        out_count = available < capacity ? available : capacity;
        for (size_t i = 0; i < out_count; ++i)
            out_pids[i] = req.out_pids[i];
        truncated = req.out_total > out_count;
        return out_count > 0;
    }

    bool get_module_base(int pid, const char* name, uint64_t& base, uint64_t& size) {
        base = size = 0;
        if (pid <= 0 || !name || !*name) return false;
        mem_get_module_base_req req{};
        req.pid = pid;
        strncpy(req.name, name, sizeof(req.name) - 1);

        if (call_ioctl(g_fd, MEM_IOC_GET_MODULE_BASE, (long)&req) < 0)
            return false;

        base = req.out_base;
        size = req.out_size;
        return base != 0;
    }

    bool get_module_base2(int pid, const char* name, uint64_t max_vma_size,
                          uint64_t& base, uint64_t& size) {
        base = 0;
        size = 0;
        if (!name || !*name)
            return false;

        mem_get_module_base2_req req{};
        req.pid = pid;
        req.max_vma_size = max_vma_size;
        strncpy(req.name, name, sizeof(req.name) - 1);

        if (call_ioctl(g_fd, MEM_IOC_GET_MODULE_BASE2,
                       (long)&req) < 0) {
            return false;
        }

        base = req.out_base;
        size = req.out_size;
        return base != 0;
    }

    bool get_module_path(int pid, const char* name, char* out, size_t out_size) {
        if (!out || out_size == 0)
            return false;
        out[0] = '\0';
        if (pid <= 0 || !name || !*name) return false;

        mem_get_module_path_req req{};
        req.pid = pid;
        strncpy(req.name, name, sizeof(req.name) - 1);

        if (call_ioctl(g_fd, MEM_IOC_GET_MODULE_PATH, (long)&req) < 0)
            return false;

        /* Kernel strscpy'd req.out_path — already NUL-terminated. */
        strncpy(out, req.out_path, out_size - 1);
        out[out_size - 1] = '\0';
        return out[0] != '\0';
    }

    bool get_tls(int pid, uint64_t& tls) {
        mem_get_tls_req req{};
        req.pid = pid;

        if (call_ioctl(g_fd, MEM_IOC_GET_TLS, (long)&req) < 0)
            return false;

        tls = req.out_tls;
        return true;
    }

    int get_thread_tid(int pid, const char* comm) {
        if (pid <= 0 || !comm || !*comm) return -1;
        mem_get_thread_tid_req req{};
        req.pid = pid;
        strncpy(req.comm, comm, sizeof(req.comm) - 1);

        if (call_ioctl(g_fd, MEM_IOC_GET_THREAD_TID, (long)&req) < 0)
            return -1;

        return req.out_tid;
    }

    bool get_thread_tids(int pid, const char* comm,
                         mem_thread_tid_info* out, size_t capacity,
                         size_t& out_count, bool& truncated) {
        out_count = 0;
        truncated = false;
        if (g_fd < 0 || pid <= 0 || !comm || !*comm || !out || capacity == 0)
            return false;

        mem_get_thread_tids_req req{};
        req.pid = pid;
        strncpy(req.comm, comm, sizeof(req.comm) - 1);
        const long result =
            call_ioctl(g_fd, MEM_IOC_GET_THREAD_TIDS, (long)&req);
        if (result < 0)
            return false;

        size_t available = req.out_count;
        if (available > MEM_GET_THREAD_TIDS_MAX)
            available = MEM_GET_THREAD_TIDS_MAX;
        out_count = available < capacity ? available : capacity;
        for (size_t i = 0; i < out_count; ++i)
            out[i] = req.out_threads[i];
        truncated = req.out_total > out_count;
        return out_count > 0;
    }

    bool get_thread_stack(int tid, uint64_t& low, uint64_t& high,
                          uint64_t* tls) {
        low = 0;
        high = 0;
        if (tls)
            *tls = 0;
        if (g_fd < 0 || tid <= 0)
            return false;

        mem_get_thread_stack_req req{};
        req.tid = tid;
        if (call_ioctl(g_fd, MEM_IOC_GET_THREAD_STACK,
                       (long)&req) < 0)
            return false;
        if (!req.out_named || req.out_low == 0 || req.out_high <= req.out_low)
            return false;

        low = req.out_low;
        high = req.out_high;
        if (tls)
            *tls = req.out_tls;
        return true;
    }

    bool execute_pacga(int pid, uint64_t data, uint64_t modifier,
                       uint64_t& out_result,
                       PacgaExecutionInfo* info) {
        out_result = 0;
        if (info)
            *info = {};
        if (g_fd < 0 || pid <= 0) {
            if (info)
                info->ioctlResult = -EINVAL;
            return false;
        }

        mem_execute_pacga_req req{};
        req.pid = pid;
        req.data = data;
        req.modifier = modifier;

        const long ioctlResult =
            call_ioctl(g_fd, MEM_IOC_EXECUTE_PACGA, (long)&req);
        if (info) {
            info->ioctlResult = ioctlResult;
            info->kernelSupported = ioctlResult == 0 && req.out_supported != 0;
        }
        if (ioctlResult < 0)
            return false;
        if (!req.out_supported)
            return false;

        out_result = req.out_result;
        return true;
    }

    long query_kgsl(dfm_kgsl_query_req& req) {
        const uint32_t op = req.op;
        const uint32_t minId = req.min_id;
        const uint32_t objectId = req.object_id;
        req.abi_version = DFM_KGSL_QUERY_ABI_VERSION;
        req.out_id = req.out_backend = req.out_fail_stage = 0;
        req.out_errno = 0;
        req.out_info = {};
        if (g_fd < 0)
            return -EBADF;
        if (req.pid <= 0 || op < DFM_KGSL_QUERY_VALIDATE_FD ||
            op > DFM_KGSL_QUERY_GPUOBJ_INFO)
            return -EINVAL;
        const long result = call_ioctl(g_fd,
                                       DFM_IOCTL_KGSL_QUERY, (long)&req);
        if (result < 0)
            return result;
        if (result != 0 || req.abi_version != DFM_KGSL_QUERY_ABI_VERSION ||
            req.op != op || req.out_errno < 0 || req.out_errno > 4095 ||
            req.out_fail_stage != 0)
            return -EPROTO;
        if (req.out_errno != 0)
            return 0;
        const uint32_t expectedBackend = op == DFM_KGSL_QUERY_VALIDATE_FD
            ? DFM_KGSL_QUERY_BACKEND_FILE
            : op == DFM_KGSL_QUERY_SYNCSOURCE_PEEK
                ? DFM_KGSL_QUERY_BACKEND_IDR_RCU
                : DFM_KGSL_QUERY_BACKEND_NATIVE_INFO;
        if (req.out_backend != expectedBackend)
            return -EPROTO;
        if (op == DFM_KGSL_QUERY_SYNCSOURCE_PEEK &&
            (req.out_id < minId || req.out_id == 0 ||
             req.out_id > static_cast<uint32_t>((std::numeric_limits<int>::max)())))
            return -EPROTO;
        if (op == DFM_KGSL_QUERY_GPUOBJ_INFO &&
            (req.out_info.id != objectId || objectId == 0 || req.out_info.padding))
            return -EPROTO;
        return 0;
    }

    bool hwb_info(dfm_hwb_info_req& out) {
        dfm_hwb_info_req req{};

        g_last_ioctl_result =
            call_ioctl(g_fd, DFM_IOCTL_HWB_INFO, (long)&req);
        if (g_last_ioctl_result < 0)
            return false;

        out = req;
        return true;
    }

    bool hwb_slots(int targetTid, dfm_hwb_slots_req& out) {
        dfm_hwb_slots_req req{};
        req.target_tid = targetTid;

        g_last_ioctl_result =
            call_ioctl(g_fd, DFM_IOCTL_HWB_SLOTS, (long)&req);
        if (g_last_ioctl_result < 0)
            return false;

        out = req;
        return true;
    }

    bool hwb_set(int targetTid, const dfm_hwb_point_req* points, size_t pointCount) {
        if (!points || pointCount == 0 || pointCount > DFM_HWB_MAX_POINTS)
            return false;

        dfm_hwb_set_req req{};
        req.target_tid = targetTid;
        req.point_count = static_cast<uint32_t>(pointCount);
        memcpy(req.points, points, sizeof(req.points[0]) * pointCount);

        g_last_ioctl_result =
            call_ioctl(g_fd, DFM_IOCTL_HWB_SET, (long)&req);
        return g_last_ioctl_result == 0;
    }

    bool hwb_read(dfm_hwb_snapshot& out) {
        dfm_hwb_read_req req{};
        req.buf = reinterpret_cast<uint64_t>(&out);
        req.buf_size = sizeof(out);

        g_last_ioctl_result =
            call_ioctl(g_fd, DFM_IOCTL_HWB_READ, (long)&req);
        return g_last_ioctl_result == 0;
    }

    bool hwb_clear() {
        g_last_ioctl_result =
            call_ioctl(g_fd, DFM_IOCTL_HWB_CLEAR, 0);
        return g_last_ioctl_result == 0;
    }

    bool udp_cap_init(int pid, uint16_t minPayload, uint16_t maxPayload) {
        udp_cap_init_req req{};
        req.pid = pid;
        req.min_payload = minPayload;
        req.max_payload = maxPayload;
        g_last_ioctl_result =
            call_ioctl(g_fd, UDP_IOC_INIT, (long)&req);
        return g_last_ioctl_result == 0;
    }

    bool udp_cap_read(udp_cap_packet* out, uint32_t maxCount, uint32_t& outCount,
                      uint64_t* overflow, uint64_t* captured) {
        outCount = 0;
        if (!out || !maxCount || maxCount > UDP_CAP_READ_MAX)
            return false;
        udp_cap_read_req req{};
        req.buf = reinterpret_cast<uint64_t>(out);
        req.max_count = maxCount;
        g_last_ioctl_result =
            call_ioctl(g_fd, UDP_IOC_READ, (long)&req);
        if (g_last_ioctl_result != 0)
            return false;
        outCount = req.out_count;
        if (overflow)
            *overflow = req.overflow;
        if (captured)
            *captured = req.captured;
        return true;
    }

    bool udp_cap_stop() {
        g_last_ioctl_result =
            call_ioctl(g_fd, UDP_IOC_STOP, 0);
        return g_last_ioctl_result == 0;
    }

    long last_ioctl_result() {
        return g_last_ioctl_result;
    }


    bool file_read(const char* path, void* buf, size_t size,
                   size_t& out_size, uint64_t offset,
                   uint64_t* out_file_size) {
        out_size = 0;
        if (out_file_size)
            *out_file_size = 0;
        if (g_fd < 0 || !path || !*path || !buf || size == 0 ||
            size > DFM_FILE_IO_MAX ||
            strnlen(path, DFM_FILE_PATH_MAX) >= DFM_FILE_PATH_MAX)
            return false;

        dfm_file_io_req req{};
        strncpy(req.path, path, sizeof(req.path) - 1);
        req.buf = reinterpret_cast<uint64_t>(buf);
        req.size = size;
        req.offset = offset;
        g_last_ioctl_result = call_ioctl(g_fd, DFM_FILE_IOC_READ, (long)&req);
        if (g_last_ioctl_result < 0 || req.out_size > size)
            return false;

        out_size = static_cast<size_t>(req.out_size);
        if (out_file_size)
            *out_file_size = req.out_file_size;
        return true;
    }

    bool file_write(const char* path, const void* buf, size_t size,
                    size_t& out_size, uint32_t flags, uint64_t offset,
                    uint64_t* out_file_size) {
        out_size = 0;
        if (out_file_size)
            *out_file_size = 0;
        if (g_fd < 0 || !path || !*path ||
            (size != 0 && !buf) || size > DFM_FILE_IO_MAX ||
            strnlen(path, DFM_FILE_PATH_MAX) >= DFM_FILE_PATH_MAX)
            return false;

        dfm_file_io_req req{};
        strncpy(req.path, path, sizeof(req.path) - 1);
        req.buf = reinterpret_cast<uint64_t>(buf);
        req.size = size;
        req.offset = offset;
        req.flags = flags;
        g_last_ioctl_result = call_ioctl(g_fd, DFM_FILE_IOC_WRITE, (long)&req);
        if (g_last_ioctl_result < 0 || req.out_size != size)
            return false;

        out_size = static_cast<size_t>(req.out_size);
        if (out_file_size)
            *out_file_size = req.out_file_size;
        return true;
    }

    bool supports_surfaceflinger_groups() {
        if (g_fd < 0)
            return false;
        dfm_sf_groups_req req{}; // version 0 must be rejected before mutation
        g_last_ioctl_result = call_ioctl(g_fd, DFM_CRED_IOC_ACQUIRE_SF_GROUPS, (long)&req);
        return g_last_ioctl_result == -EINVAL;
    }

    bool acquire_surfaceflinger_groups(SfGroupGrantInfo* info) {
        if (info)
            *info = {};
        if (g_fd < 0) {
            if (info)
                info->ioctlResult = -EBADF;
            return false;
        }

        dfm_sf_groups_req req{};
        req.abi_version = DFM_SF_GROUPS_ABI_VERSION;
        g_last_ioctl_result = call_ioctl(g_fd, DFM_CRED_IOC_ACQUIRE_SF_GROUPS, (long)&req);
        if (info) {
            info->ioctlResult = g_last_ioctl_result;
            info->present = req.out_present;
            info->added = req.out_added;
            info->groupCount = req.out_group_count;
        }
        return g_last_ioctl_result == 0 &&
               req.out_present == DFM_SF_GROUP_REQUIRED;
    }
    bool read_memory(int pid, uint64_t addr, void* buf, size_t sz) {
        if (g_fd < 0 || pid <= 0 || !buf || sz == 0) return false;

        mem_rw_req req{};
        req.pid = pid;
        req.addr = addr;
        req.size = sz;
        req.buf = (uint64_t)buf;

        return call_ioctl(g_fd, MEM_IOC_READ, (long)&req) == 0;
    }

    bool read_memory_cache(int pid, uint64_t addr, void* buf, size_t sz) {
        if (g_fd < 0 || pid <= 0 || !buf || sz == 0) return false;

        mem_rw_req req{};
        req.pid = pid;
        req.addr = addr;
        req.size = sz;
        req.buf = (uint64_t)buf;

        return call_ioctl(g_fd, MEM_IOC_READ_CACHE, (long)&req) == 0;
    }

    bool touch_init() {
        return call_ioctl(g_fd, TOUCH_IOC_INIT, 0) == 0;
    }

    bool touch_event(int slot, int x, int y, bool down) {
        touch_event_req req{};
        req.slot = slot;
        req.x = x;
        req.y = y;
        req.down = down ? 1 : 0;
        return call_ioctl(g_fd, TOUCH_IOC_EVENT, (long)&req) == 0;
    }

    bool touch_v2_init() {
        return call_ioctl(g_fd, TOUCH_IOC_INIT_V2, 0) == 0;
    }

    bool touch_v2_event(int slot, int x, int y, bool down) {
        touch_event_req req{};
        req.slot = slot;
        req.x = x;
        req.y = y;
        req.down = down ? 1 : 0;
        return call_ioctl(g_fd, TOUCH_IOC_EVENT_V2, (long)&req) == 0;
    }

    bool touch_get_status(struct touch_status* out) {
        if (!out) return false;
        memset(out, 0, sizeof(*out));
        if (g_fd < 0) return false;
        return call_ioctl(g_fd, TOUCH_IOC_GET_STATUS, (long)out) == 0;
    }
} // namespace dfm
