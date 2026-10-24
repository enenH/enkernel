#ifndef DFM_DRIVER_H
#define DFM_DRIVER_H

#include <cstdint>
#include <cstddef>

#include <dfm/abi.h>

namespace dfm {
    struct PacgaExecutionInfo {
        /* Raw return from the ioctl syscall: 0 means the command was handled;
         * a negative errno (notably -ENOTTY) means it never reached a usable
         * MEM_IOC_EXECUTE_PACGA implementation. */
        long ioctlResult = 0;
        /* Valid when ioctlResult==0. False means the active kernel/module
         * deliberately reported no system-wide generic-auth capability. */
        bool kernelSupported = false;
    };

    /* Android arm64, C++20. One process-wide connection. Initialize before workers
     * start and close after they stop; serialize init/close and stateful operations.
     * Obtain the kernel fd through the module install entry. Loading is separate. */
    bool init();

    /* Borrowed descriptor for raw ABI calls; never close it yourself. */
    int native_handle();

    /* Close the fd and trigger module cleanup, including shared UDP/touch state.
     * Coordinate stateful use across clients. Does not unload the module. */
    void close();

    int get_process_id(const char* name);
    /* Return every process leader with the exact task->comm.  `truncated` is
     * true when the kernel found more matches than either its fixed ABI array
     * or the caller's output capacity.  Against an older module without the
     * ioctl this falls back to GET_PID and reports truncated=true, because the
     * single returned PID is not proof that no same-comm peers exist. */
    bool get_process_ids(const char* name, int* out_pids, size_t capacity,
                         size_t& out_count, bool& truncated);
    bool get_module_base(int pid, const char* name, uint64_t& base, uint64_t& size);
    /* Ignore matching VMAs larger than max_vma_size bytes before selecting the
     * first mapping. max_vma_size=0 is unlimited. No fallback is possible on
     * old modules because it would defeat the filter. */
    bool get_module_base2(int pid, const char* name, uint64_t max_vma_size,
                          uint64_t& base, uint64_t& size);

    /* Resolve the full path of the first mapped file whose name contains `name`.
     * `out` is NUL-terminated. Returns false on failure, no match or old modules. */
    bool get_module_path(int pid, const char* name, char* out, size_t out_size);
    bool get_tls(int pid, uint64_t& tls);
    int get_thread_tid(int pid, const char* comm);
    /* List every thread in `pid` whose comm matches.  Returns false on an
     * old .ko (ENOTTY) or when no thread matches.  out_total may exceed
     * out_count when truncated. */
    bool get_thread_tids(int pid, const char* comm,
                         mem_thread_tid_info* out, size_t capacity,
                         size_t& out_count, bool& truncated);
    bool get_thread_stack(int tid, uint64_t& low, uint64_t& high,
                          uint64_t* tls = nullptr);

    /* Execute PACGA with the target task's APGAKey, then restore the original key.
     * Returns false if the ioctl fails or the kernel reports no PACGA capability.
     * `info` distinguishes unsupported hardware from missing module support. */
    bool execute_pacga(int pid, uint64_t data, uint64_t modifier,
                       uint64_t& out_result,
                       PacgaExecutionInfo* info = nullptr);

    /* Read-only target PID/FD query; never creates a local target fd. Set op,
     * pid, target_fd and op-specific inputs in a zero-initialized request.
     * Return 0 means completed: inspect out_errno for a guest syscall error.
     * Negative return means infrastructure failure (ENOTTY: old module).
     * No legacy caller-fd or userspace-system-call fallback. */
    long query_kgsl(dfm_kgsl_query_req& request);

    bool hwb_info(dfm_hwb_info_req& out);
    bool hwb_slots(int targetTid, dfm_hwb_slots_req& out);
    bool hwb_set(int targetTid, const dfm_hwb_point_req* points, size_t pointCount);
    bool hwb_read(dfm_hwb_snapshot& out);
    bool hwb_clear();
    /* Raw result of the most recent issued ioctl on this thread (negative errno).
     * Argument validation can fail before issuing an ioctl; do not rely on libc errno. */
    long last_ioctl_result();

    bool udp_cap_init(int pid, uint16_t minPayload = 16,
                      uint16_t maxPayload = UDP_CAP_MAX_PAYLOAD);
    bool udp_cap_read(udp_cap_packet* out, uint32_t maxCount, uint32_t& outCount,
                      uint64_t* overflow = nullptr, uint64_t* captured = nullptr);
    bool udp_cap_stop();

    /* Bounded /data/adb file proxy for confined SF workers. */
    bool file_read(const char* path, void* buf, size_t size, size_t& out_size,
                   uint64_t offset = 0, uint64_t* out_file_size = nullptr);
    bool file_write(const char* path, const void* buf, size_t size,
                    size_t& out_size,
                    uint32_t flags = DFM_FILE_WRITE_CREATE | DFM_FILE_WRITE_TRUNCATE,
                    uint64_t offset = 0, uint64_t* out_file_size = nullptr);
    struct SfGroupGrantInfo {
        long ioctlResult = 0;
        uint32_t present = 0;
        uint32_t added = 0;
        uint32_t groupCount = 0;
    };
    bool acquire_surfaceflinger_groups(SfGroupGrantInfo* info = nullptr);
    /* Invalid-version probe: no credentials are changed, including for root. */
    bool supports_surfaceflinger_groups();

    bool read_memory(int pid, uint64_t addr, void* buf, size_t size);
    bool read_memory_cache(int pid, uint64_t addr, void* buf, size_t size);
    // Returns 0 or a negative errno; no content-based/old-module fallback.
    // Output is zeroed on failure. See mem_query_mapping_req for lifetime.
    long query_mapping(int pid, uint64_t addr, mem_query_mapping_req& out);
    long query_access(int pid, uint64_t addr, mem_query_access_req& out);
    bool supports_process_mem();
    // Restricted system_server/libsensorservice session; caller owns out_fd.
    long open_process_mem(int pid, mem_open_process_mem_req& out);
    // Reuses QUERY_ACCESS on the session's bound mm, not a freshly resolved PID.
    long query_process_mem_access(int fd, int pid, uint64_t addr,
                                  mem_query_access_req& out);
    long arm_process_mem_patch(int fd, uint64_t got, uint64_t original,
                               uint64_t replacement, uint64_t delta);
    long query_signal(int tid, uint32_t signo, mem_query_signal_req& out);
    bool touch_init();
    bool touch_event(int slot, int x, int y, bool down);
    bool touch_v2_init();
    bool touch_v2_event(int slot, int x, int y, bool down);

    /* Query kernel touch proxy state; output is zeroed on failure. */
    bool touch_get_status(struct touch_status* out);
    /* Convenience read: returns a zero value on failure. Use read_memory for errors. */
    template <typename T>
    T read(int pid, uint64_t addr) {
        T val{};
        if (!read_memory(pid, addr, &val, sizeof(T)))
            return T{};
        return val;
    }
} // namespace dfm

#endif /* DFM_DRIVER_H */
