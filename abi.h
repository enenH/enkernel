#ifndef ABI_H
#define ABI_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

/* Magic numbers for hidden install entry to install fd */
#define INSTALL_MAGIC1  0x44464D50  /* "DFMP" */
#define INSTALL_MAGIC2  0x504D4644  /* "PMFD" */

/* IOCTL command definitions */
#define MEM_IOC_GET_PID          _IOWR('D', 1, struct mem_get_pid_req)
#define MEM_IOC_GET_MODULE_BASE  _IOWR('D', 2, struct mem_get_module_base_req)
#define MEM_IOC_READ             _IOWR('D', 3, struct mem_rw_req)
#define MEM_IOC_READ_CACHE       _IOWR('D', 5, struct mem_rw_req)
#define TOUCH_IOC_INIT           _IO('D', 6)
#define TOUCH_IOC_EVENT          _IOW('D', 7, struct touch_event_req)
#define MEM_IOC_GET_TLS          _IOWR('D', 8, struct mem_get_tls_req)
#define MEM_IOC_GET_THREAD_TID   _IOWR('D', 9, struct mem_get_thread_tid_req)
#define TOUCH_IOC_GET_STATUS     _IOR('D', 10, struct touch_status)
#define MEM_IOC_EXECUTE_PACGA    _IOWR('D', 12, struct mem_execute_pacga_req)
#define MEM_IOC_GET_MODULE_PATH  _IOWR('D', 13, struct mem_get_module_path_req)
#define DFM_IOCTL_HWB_INFO       _IOWR('D', 14, struct dfm_hwb_info_req)
#define DFM_IOCTL_HWB_SET        _IOW('D', 15, struct dfm_hwb_set_req)
#define DFM_IOCTL_HWB_READ       _IOWR('D', 16, struct dfm_hwb_read_req)
#define DFM_IOCTL_HWB_CLEAR      _IO('D', 17)
#define DFM_IOCTL_HWB_SLOTS      _IOWR('D', 22, struct dfm_hwb_slots_req)
#define MEM_IOC_GET_THREAD_STACK _IOWR('D', 18, struct mem_get_thread_stack_req)
#define MEM_IOC_GET_PIDS         _IOWR('D', 19, struct mem_get_pids_req)
#define TOUCH_IOC_INIT_V2        _IO('D', 20)
#define TOUCH_IOC_EVENT_V2       _IOW('D', 21, struct touch_event_req)
#define DFM_IOCTL_KGSL_SYNCSOURCE_PEEK \
    _IOWR('D', 23, struct dfm_kgsl_syncsource_peek_req)
#define MEM_IOC_GET_MODULE_BASE2 _IOWR('D', 24, struct mem_get_module_base2_req)
#define MEM_IOC_GET_THREAD_TIDS  _IOWR('D', 25, struct mem_get_thread_tids_req)
#define UDP_IOC_INIT             _IOW('D', 26, struct udp_cap_init_req)
#define UDP_IOC_READ             _IOWR('D', 27, struct udp_cap_read_req)
#define UDP_IOC_STOP             _IO('D', 28)
#define MEM_IOC_QUERY_MAPPING    _IOWR('D', 29, struct mem_query_mapping_req)
#define MEM_IOC_QUERY_ACCESS     _IOWR('D', 30, struct mem_query_access_req)
#define MEM_IOC_QUERY_SIGNAL     _IOWR('D', 31, struct mem_query_signal_req)
#define DFM_FILE_IOC_READ        _IOWR('D', 32, struct dfm_file_io_req)
#define DFM_FILE_IOC_WRITE       _IOWR('D', 33, struct dfm_file_io_req)
#define DFM_CRED_IOC_ACQUIRE_SF_GROUPS \
    _IOWR('D', 34, struct dfm_sf_groups_req)
#define DFM_IOCTL_KGSL_QUERY _IOWR('D', 35, struct dfm_kgsl_query_req)
#define MEM_IOC_OPEN_PROCESS_MEM _IOWR('D', 36, struct mem_open_process_mem_req)
/* This command is accepted only by the returned process-memory fd. */
#define MEM_PROCESS_MEM_IOC_ARM _IOW('D', 37, struct mem_process_mem_arm_req)

#define MEM_PROCESS_MEM_ABI_VERSION 1U
#define MEM_PROCESS_MEM_IO_MAX 4096U

/* Restricted lab session: system_server /system/lib64/libsensorservice.so only.
 * version=0 is a non-mutating capability probe, rejected with -EINVAL.
 * pread/pwrite offsets are target VAs; QUERY_ACCESS also works on this fd.
 * The fd is owner-TGID-bound, CLOEXEC, and rejects an exited/replaced mm.
 * No procfs permission or process credentials are changed. */
struct mem_open_process_mem_req {
    uint32_t version;
    int32_t pid;
    int32_t out_fd;
    uint32_t out_uid;
    uint64_t out_module_base;
    uint64_t out_module_size;
    uint64_t reserved;
};

/* Arm cleanup BEFORE publishing the GOT pointer. The fd's final release
 * zeroes the 8-byte delta and conditionally restores this GOT slot, including
 * after SIGKILL. It never erases code: a target thread may still execute it.
 * Layout: delta[8], original[8], immutable trampoline[48]. */
struct mem_process_mem_arm_req {
    uint32_t version;
    uint32_t reserved;
    uint64_t got_addr;
    uint64_t original;
    uint64_t replacement;
    uint64_t delta_addr;
};

#define DFM_FILE_PATH_MAX    256U
#define DFM_FILE_IO_MAX      (4U * 1024U * 1024U)
#define DFM_FILE_WRITE_CREATE   (1U << 0)
#define DFM_FILE_WRITE_TRUNCATE (1U << 1)
#define DFM_SF_GROUPS_ABI_VERSION 1U
#define DFM_SF_GROUP_INPUT        (1U << 0)
#define DFM_SF_GROUP_INET         (1U << 1)
#define DFM_SF_GROUP_REQUIRED     (DFM_SF_GROUP_INPUT | DFM_SF_GROUP_INET)

#define MEM_MAPPING_F_READ       (1U << 0)
#define MEM_MAPPING_F_WRITE      (1U << 1)
#define MEM_MAPPING_F_EXEC       (1U << 2)
#define MEM_MAPPING_F_SHARED     (1U << 3)

/* Read-only, non-faulting VA -> PA snapshot. addr may carry a top-byte tag.
 * out_phys_addr includes the byte offset; out_page_size is the leaf granule
 * (not a contiguous-PTE group). PA zero is valid. No page is pinned or faulted
 * in, and no target memory/PTE is modified. The result can become stale as
 * soon as the query returns: never persist identities across emulated calls.
 * Equal PA does NOT imply shared write semantics for private/COW mappings.
 * -ENOENT: no VMA; -ENODATA: nonresident/inaccessible PTE;
 * -EOPNOTSUPP: special/IO/hugetlb mapping; -ENOTTY: old module.
 * All input flags/reserved fields must be zero. ABI is identical in user/. */
struct mem_query_mapping_req {
    int32_t  pid;
    uint32_t flags;
    uint64_t addr;
    uint64_t out_phys_addr;
    uint64_t out_page_size;
    uint32_t out_flags;
    uint32_t reserved;
};

/* VMA permissions are returned even when no resident PTE/physical identity
 * exists. All successful queries return metadata, including UNMAPPED.
 * This is observational only: no page fault, GUP, target write or signal. */
#define MEM_ACCESS_UNMAPPED   0U
#define MEM_ACCESS_RESIDENT   1U
#define MEM_ACCESS_NONRESIDENT 2U
#define MEM_ACCESS_UNSUPPORTED 3U
struct mem_query_access_req {
    int32_t pid;
    uint32_t flags; /* input: zero */
    uint64_t addr;
    uint64_t out_start;
    uint64_t out_end;
    uint32_t out_permissions; /* MEM_MAPPING_F_{READ,WRITE,EXEC,SHARED} */
    uint32_t out_state;       /* MEM_ACCESS_* */
};

/* Actual thread signal disposition, not a userspace installation-code scan.
 * Native AArch64 Linux uses a 64-bit kernel signal set. The action/mask is
 * sampled under sighand->siglock; altstack is an optimistic stable sample.
 * out_tgid lets callers reject a TID belonging to another process.
 * Never changes the target's disposition, mask, altstack or pending signals. */
struct mem_query_signal_req {
    int32_t tid;
    uint32_t signo;
    uint64_t out_handler;
    uint64_t out_flags;
    uint64_t out_restorer;
    uint64_t out_action_mask;
    uint64_t out_blocked;
    uint64_t out_alt_sp;
    uint64_t out_alt_size;
    uint32_t out_alt_flags;
    int32_t out_tgid;
};

#define DFM_HWB_MAX_POINTS  16U
#define DFM_HWB_MAX_RECORDS 64U
#define MEM_GET_PIDS_MAX     64U
#define MEM_GET_THREAD_TIDS_MAX 64U
#define MEM_THREAD_TID_F_ON_CPU  (1U << 0)
#define MEM_THREAD_TID_F_RUNNING (1U << 1)

#define DFM_KGSL_SYNCSOURCE_PEEK_ABI_VERSION 1U
#define DFM_KGSL_SYNCSOURCE_BACKEND_IDR_RCU  1U

#define DFM_HWB_TYPE_R  1U
#define DFM_HWB_TYPE_W  2U
#define DFM_HWB_TYPE_RW (DFM_HWB_TYPE_R | DFM_HWB_TYPE_W)
#define DFM_HWB_TYPE_X  4U

#define DFM_HWB_SNAPSHOT_ACTIVE         (1U << 0)
#define DFM_HWB_SNAPSHOT_TARGET_MISSING (1U << 1)

#define DFM_HWB_MAX_HW_SLOTS 16U
#define DFM_HWB_MAX_SLOT_EVENTS (DFM_HWB_MAX_HW_SLOTS * 2U)

#define DFM_HWB_SLOTS_F_PERF_CONTEXT   (1U << 0)
#define DFM_HWB_SLOTS_F_REGS_VALID     (1U << 1)
#define DFM_HWB_SLOTS_F_TARGET_RUNNING (1U << 2)
#define DFM_HWB_SLOTS_F_TRUNCATED      (1U << 3)

#define DFM_HWB_SLOT_F_VALID    (1U << 0)
#define DFM_HWB_SLOT_F_OCCUPIED (1U << 1)
#define DFM_HWB_SLOT_F_ENABLED  (1U << 2)
#define DFM_HWB_SLOT_F_PERF     (1U << 3)
#define DFM_HWB_SLOT_F_PTRACE   (1U << 4)
#define DFM_HWB_SLOT_F_DFM      (1U << 5)

#define DFM_HWB_EVENT_F_ENABLED   (1U << 0)
#define DFM_HWB_EVENT_F_ACTIVE    (1U << 1)
#define DFM_HWB_EVENT_F_PINNED    (1U << 2)
#define DFM_HWB_EVENT_F_EXCLUSIVE (1U << 3)
#define DFM_HWB_EVENT_F_PTRACE    (1U << 4)
#define DFM_HWB_EVENT_F_INHERITED (1U << 5)

#define DFM_HWB_SLOT_NONE 0xFFFFFFFFU

struct mem_get_pid_req {
    char name[256];
    int  out_pid;
};

/* Enumerate process leaders whose task->comm exactly matches `name`.
 * out_total may exceed out_count when more than MEM_GET_PIDS_MAX processes
 * match; callers must treat that as a truncated result instead of silently
 * assuming the desired package was absent. */
struct mem_get_pids_req {
    char     name[256];
    uint32_t out_count;
    uint32_t out_total;
    int      out_pids[MEM_GET_PIDS_MAX];
};

struct mem_get_module_base_req {
    int      pid;
    char     name[256];
    uint64_t out_base;
    uint64_t out_size;
};

/* Like GET_MODULE_BASE, but ignores an individual matching VMA when its
 * vm_end-vm_start exceeds max_vma_size. max_vma_size=0 means unlimited.
 * out_size remains the span from the first accepted VMA to the last accepted
 * VMA, not the size of the first VMA. */
struct mem_get_module_base2_req {
    int      pid;
    uint32_t reserved;
    uint64_t max_vma_size;
    char     name[256];
    uint64_t out_base;
    uint64_t out_size;
};

/* Resolve the full filesystem path (d_path) of the first mapped VMA whose
 * backing file name contains `name`.  The path embeds the app's package name,
 * e.g.
 *   /data/app/~~<hash>==/com.tencent.tmgp.gtcn-<hash>==/lib/arm64/libUE4.so
 * which is how DFM China/Taiwan/Global variants are told apart: they share the same thread
 * comm ("MainThread-UE4") and the same libUE4.so filename, so only the
 * directory path distinguishes them.  get_module_base's d_name.name match is
 * filename-only and cannot see the package. */
struct mem_get_module_path_req {
    int  pid;
    char name[256];      /* module filename substring to match, e.g. "libUE4.so" */
    char out_path[256];  /* filled with the resolved d_path on success */
};

struct mem_rw_req {
    int      pid;
    uint64_t addr;
    uint64_t size;
    uint64_t buf;   /* userland buffer pointer */
};

struct touch_event_req {
    int slot;
    int x;
    int y;
    int down;
};

struct mem_get_tls_req {
    int      pid;
    uint64_t out_tls;
};

struct mem_get_thread_tid_req {
    int  pid;
    char comm[256];
    int  out_tid;
};

/* Enumerate threads in `pid`'s group whose task->comm matches `comm`.
 * exec_ns is se.sum_exec_runtime (ns). flags are a racy on_cpu/TASK_RUNNING
 * snapshot. out_total may exceed out_count when truncated.
 * MUST stay byte-identical to user/include/abi.h. */
struct mem_thread_tid_info {
    int32_t  tid;
    uint32_t flags;
    uint64_t exec_ns;
};

struct mem_get_thread_tids_req {
    int      pid;
    uint32_t out_count;
    uint32_t out_total;
    uint32_t reserved;
    char     comm[256];
    struct mem_thread_tid_info out_threads[MEM_GET_THREAD_TIDS_MAX];
};

/* Resolve the Bionic-owned stack_and_tls:<tid> anonymous VMA.  This is a
 * per-thread mapping (unlike mm->start_stack, which only describes the process
 * main thread).  out_low/out_high are VMA bounds; callers must keep a margin
 * from both ends because the upper part also contains static TLS. */
struct mem_get_thread_stack_req {
    int      tid;
    int      out_named;
    uint64_t out_low;
    uint64_t out_high;
    uint64_t out_tls;
};

/* Run the ARMv8.3 PACGA instruction inside the kernel with the target task's
 * APGAKey installed into APGAKey{Lo,Hi}_EL1, then restore. PAC keys are
 * per-task, initialised at exec (arch/arm64 ptrauth_keys_init_user) into
 * thread_struct.keys_user and stable across the task's lifetime unless the
 * task itself calls PR_PAC_RESET_KEYS (which the game does not).
 *
 * Rationale: a user-space software QARMA5 port only reproduces the game's PAC
 * on silicon whose PACGA cipher is architected QARMA5 — IMPDEF cores
 * (Qualcomm Oryon / Apple custom) diverge. Executing PACGA on the same SoC
 * the game runs on side-steps the cipher question entirely: whatever the
 * hardware does, both sides do the same when keyed with the same 128 bits.
 * The emulator's opcode handler for `pacga Xd,Xn,Xm` bounces (Xn,Xm) through
 * this ioctl and takes out_result verbatim.
 *
 * Atomicity: the sysreg swap runs with IRQs disabled so we can't be scheduled
 * out with the guest's key still in APGAKey_EL1 (that would leak a projection
 * of the guest key into whatever task's userspace PACGA runs next). Total
 * <20 cycles — spinning under irq-off is fine.
 *
 * `out_supported` is 1 iff the kernel was built with CONFIG_ARM64_PTR_AUTH
 * AND the silicon exposes generic-auth (PACGA-capable). Otherwise it's 0
 * with out_result=0 so the caller can distinguish "unsupported" from
 * "task missing" (-ESRCH) or "bad pid" (-EINVAL). */
struct mem_execute_pacga_req {
    int      pid;
    int      out_supported;
    uint64_t data;
    uint64_t modifier;
    uint64_t out_result;
};

/*
 * Read-only prediction of the ID that KGSL's
 * IOCTL_KGSL_SYNCSOURCE_CREATE would allocate for a target KGSL fd.
 *
 * The query never calls a KGSL ioctl and never inserts/removes an ID.  It
 * observes the caller-owned kgsl_fd's process-private syncsource IDR under RCU
 * and returns the lowest free ID >= min_id. This legacy command accepts only
 * a caller-owned fd. New clients use DFM_IOCTL_KGSL_QUERY with a target PID/FD.
 * min_id exists
 * so user space can overlay IDs that it simulated locally without modifying
 * the target IDR.  Passing min_id=1 asks the literal "what would CREATE choose
 * now?" question.
 *
 * The result is advisory, not a reservation: another target thread may change
 * the IDR immediately after the snapshot.  Fixed-width fields keep the ioctl
 * encoding identical for native and compat callers.  flags and reserved must
 * be zero on input.  On a failed peek, reserved[0] may return a
 * DFM_KGSL_SYNCSOURCE_PEEK_FAIL_* stage so user space can tell symbol
 * lookup apart from a CFI/PLT layout miss without guessing an ID.
 */
struct dfm_kgsl_syncsource_peek_req {
    int      kgsl_fd;
    uint32_t min_id;
    uint32_t flags;
    uint32_t abi_version;
    uint32_t out_id;
    uint32_t out_backend;
    uint32_t reserved[2];
};

#define DFM_KGSL_SYNCSOURCE_PEEK_FAIL_FILE_IDENTITY   1U
#define DFM_KGSL_SYNCSOURCE_PEEK_FAIL_NOT_KGSL_FILE   2U
#define DFM_KGSL_SYNCSOURCE_PEEK_FAIL_RUNTIME_SYMBOLS 3U
#define DFM_KGSL_SYNCSOURCE_PEEK_FAIL_CREATE_LAYOUT   4U
#define DFM_KGSL_SYNCSOURCE_PEEK_FAIL_DESTROY_LAYOUT  5U
#define DFM_KGSL_SYNCSOURCE_PEEK_FAIL_LAYOUT_MISMATCH 6U
#define DFM_KGSL_SYNCSOURCE_PEEK_FAIL_LAYOUT_OFFSETS  7U
#define DFM_KGSL_SYNCSOURCE_PEEK_FAIL_PROCESS_PRIV    8U
#define DFM_KGSL_SYNCSOURCE_PEEK_FAIL_LIVE_IDR        9U
#define DFM_KGSL_SYNCSOURCE_PEEK_FAIL_LOWEST_FREE     10U

/* Target queries never install/open a target fd in the caller. File/object
 * references are temporary; no KGSL CREATE/DESTROY/SET_INFO is dispatched.
 * The ioctl return describes infrastructure/ABI errors. On return 0,
 * out_errno is a positive guest errno (e.g. EBADF/EINVAL), or zero on success.
 * GPUOBJ_INFO uses only the native read-only INFO handler with a kernel buffer,
 * never the generic file ioctl dispatcher or caller-selected commands.
 * SYNCSOURCE_PEEK copies a sorted, unique array of positive excluded IDs from
 * the caller before acquiring the target file, then performs the entire search
 * with that one file reference. It observes an ID; it does not reserve it.
 * All unused inputs, flags and reserved fields must be zero. No fallback to
 * the legacy caller-fd command is permitted when this ABI is unavailable.
 */
#define DFM_KGSL_QUERY_ABI_VERSION 1U
#define DFM_KGSL_QUERY_VALIDATE_FD 1U
#define DFM_KGSL_QUERY_SYNCSOURCE_PEEK 2U
#define DFM_KGSL_QUERY_GPUOBJ_INFO 3U
#define DFM_KGSL_QUERY_MAX_EXCLUDED_IDS 4096U
#define DFM_KGSL_QUERY_BACKEND_FILE 1U
#define DFM_KGSL_QUERY_BACKEND_IDR_RCU 2U
#define DFM_KGSL_QUERY_BACKEND_NATIVE_INFO 3U
/* 1..10 retain the legacy syncsource layout diagnostic meanings. */
#define DFM_KGSL_QUERY_FAIL_TASK 101U
#define DFM_KGSL_QUERY_FAIL_ACCESS 102U
#define DFM_KGSL_QUERY_FAIL_FD 103U
#define DFM_KGSL_QUERY_FAIL_INFO_SYMBOL 104U
#define DFM_KGSL_QUERY_FAIL_INFO_RESULT 105U

struct dfm_kgsl_gpuobj_info {
    uint64_t gpuaddr;
    uint64_t flags;
    uint64_t size;
    uint64_t va_len;
    uint64_t va_addr;
    uint32_t id;
    uint32_t padding;
};

struct dfm_kgsl_query_req {
    uint32_t abi_version;
    uint32_t op;
    int32_t  pid;
    uint32_t target_fd;
    uint32_t min_id;
    uint32_t object_id;
    uint32_t excluded_count;
    uint32_t flags;
    uint64_t excluded_ids; /* caller user pointer; never a kernel pointer */
    uint32_t out_id;
    uint32_t out_backend;
    int32_t  out_errno;
    uint32_t out_fail_stage;
    struct dfm_kgsl_gpuobj_info out_info;
    uint64_t reserved[2];
};

struct dfm_hwb_info_req {
    uint32_t num_brps;
    uint32_t num_wrps;
    uint32_t max_points;
    uint32_t max_records;
};

/*
 * Read-only diagnostic view of a target's hardware-breakpoint resources.
 * The register arrays are valid only when DFM_HWB_SLOTS_F_REGS_VALID is set;
 * a sleeping or migrated target has no target-specific debug registers on a
 * CPU that can be sampled synchronously.  perf_events describes the target's
 * configured PERF_TYPE_BREAKPOINT events even in that case.
 */
struct dfm_hwb_slot_state {
    uint32_t flags;
    uint32_t type;
    uint64_t addr;
    uint64_t ctrl;
    uint64_t event_id;
};

struct dfm_hwb_perf_event_state {
    uint32_t flags;
    uint32_t type;
    uint32_t len;
    uint32_t slot;
    int      state;
    int      cpu;
    int      oncpu;
    uint32_t reserved;
    uint64_t addr;
    uint64_t hw_addr;
    uint64_t ctrl;
    uint64_t event_id;
};

struct dfm_hwb_slots_req {
    int      target_tid;
    int      task_cpu;
    int      observed_cpu;
    uint32_t flags;
    uint32_t num_brps;
    uint32_t num_wrps;
    uint32_t enabled_brp_mask;
    uint32_t enabled_wrp_mask;
    uint32_t occupied_brp_mask;
    uint32_t occupied_wrp_mask;
    uint32_t perf_event_count;
    uint32_t perf_event_total;
    uint32_t perf_brp_count;
    uint32_t perf_wrp_count;
    uint32_t active_perf_brp_count;
    uint32_t active_perf_wrp_count;
    uint32_t reserved[2];
    struct dfm_hwb_slot_state brps[DFM_HWB_MAX_HW_SLOTS];
    struct dfm_hwb_slot_state wrps[DFM_HWB_MAX_HW_SLOTS];
    struct dfm_hwb_perf_event_state perf_events[DFM_HWB_MAX_SLOT_EVENTS];
};

struct dfm_hwb_point_req {
    uint32_t type;
    uint32_t len;
    uint64_t addr;
};

struct dfm_hwb_set_req {
    int      target_tid;
    uint32_t point_count;
    uint32_t reserved;
    struct dfm_hwb_point_req points[DFM_HWB_MAX_POINTS];
};

struct dfm_hwb_record {
    uint32_t point_index;
    uint32_t type;
    uint64_t hit_count;
    uint64_t hit_addr;
    uint64_t fault_addr;
    uint64_t esr;
    uint64_t pc;
    uint64_t lr;
    uint64_t sp;
    uint64_t pstate;
    uint64_t x[31];
    uint32_t fpsr;
    uint32_t fpcr;
    uint64_t q[32][2];
};

struct dfm_hwb_point_snapshot {
    uint32_t type;
    uint32_t len;
    uint32_t record_count;
    uint32_t reserved;
    uint64_t addr;
    uint64_t overflow_count;
    struct dfm_hwb_record records[DFM_HWB_MAX_RECORDS];
};

struct dfm_hwb_snapshot {
    int      target_tid;
    uint32_t flags;
    uint32_t point_count;
    uint32_t reserved;
    uint64_t total_hits;
    struct dfm_hwb_point_snapshot points[DFM_HWB_MAX_POINTS];
};

struct dfm_hwb_read_req {
    uint64_t buf;
    uint64_t buf_size;
    uint64_t out_size;
};

/* Bounded kernel-side file proxy for data that a confined process (notably
 * SurfaceFlinger) cannot access directly. The kernel accepts root/system UID
 * callers and regular files directly below /data/adb. READ additionally
 * accepts /data/adb/model/<single-leaf>; WRITE never does. Final symlinks are
 * rejected, and the fixed model path must be a directory. Its owner and
 * permission bits (including 0777) are not additional proxy restrictions.
 * Each ioctl is capped at DFM_FILE_IO_MAX bytes; write-created files use 0600.
 *
 * READ returns short success at EOF.  WRITE succeeds only after the entire
 * buffer has been written.  out_file_size is sampled while the file is open. */
struct dfm_file_io_req {
    char     path[DFM_FILE_PATH_MAX];
    uint64_t buf;            /* userland buffer pointer */
    uint64_t size;           /* requested byte count */
    uint64_t offset;         /* absolute file offset */
    uint64_t out_size;       /* bytes transferred */
    uint64_t out_file_size;  /* regular-file size after the operation */
    uint32_t flags;          /* DFM_FILE_WRITE_*; must be zero for READ */
    uint32_t reserved;
};

/* Add the two fixed Android supplementary groups needed by the injected
 * SurfaceFlinger worker: AID_INPUT (1004) for opening the existing 0660
 * /dev/input/eventN nodes, and AID_INET (3003) for libc's 0660
 * /dev/socket/dnsproxyd endpoint.  There is deliberately no PID, GID or mask
 * input: the kernel may only update the calling thread and may only add this
 * fixed pair after verifying that the caller is the real
 * /system/bin/surfaceflinger running entirely as AID_SYSTEM in init's user
 * namespace.
 *
 * Linux credentials are per-thread. Threads subsequently created by this
 * caller inherit the updated group list; unrelated SurfaceFlinger threads are
 * untouched. The command is idempotent and reports which groups were already
 * present versus newly added. */
struct dfm_sf_groups_req {
    uint32_t abi_version;     /* must be DFM_SF_GROUPS_ABI_VERSION */
    uint32_t reserved;        /* must be zero */
    uint32_t out_present;     /* DFM_SF_GROUP_* after the operation */
    uint32_t out_added;       /* DFM_SF_GROUP_* added by this call */
    uint32_t out_group_count; /* caller's supplementary-group count after */
    uint32_t out_reserved[3];
};
/* Kernel touch proxy status snapshot (read-only from user).
 * 用于让 user 态验证 kernel 究竟把 read-hook 装到了哪个 /dev/input/eventX 上,
 * 以及它的 abs range/uid/进程. 三次修复"完全没有触摸点"未坐实的核心症结就是
 * user 态选的 Type-B 与 kernel 实际 patch 的 event 可能是两块不同的设备.
 *
 * last_reject_reason 编码(0=无近期拒绝, 1=uid≠1000, 2=文件名非 event,
 * 3=d_path 非 /dev/input/event, 4=缺 EV_ABS/ABS_MT_* caps, 5=已 installed
 * 后续路径进入). reject_*_count 是累计次数, 便于观察 hook 是否被高频路径
 * 反复驳回。 */
#define UDP_CAP_MAX_PAYLOAD 2048U
#define UDP_CAP_READ_MAX    32U
#define UDP_CAP_F_TRUNC     (1U << 0)

/* Downlink IPv4 UDP body captured at udp_queue_rcv_one_skb.
 * MUST stay byte-identical to user/include/abi.h. */
struct udp_cap_packet {
    uint64_t seq;
    uint64_t ts_ns;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t payload_len;
    uint16_t flags;
    uint32_t sock_uid;
    uint32_t reserved;
    uint8_t  payload[UDP_CAP_MAX_PAYLOAD];
};

struct udp_cap_init_req {
    int      pid;
    uint32_t reserved0;
    uint16_t min_payload;
    uint16_t max_payload;
    uint32_t reserved1;
};

struct udp_cap_read_req {
    uint64_t buf;
    uint32_t max_count;
    uint32_t out_count;
    uint64_t overflow;
    uint64_t captured;
    uint32_t reserved;
};

struct touch_status {
    int installed;                    /* 1 = touch_read_proxy 已装 */
    int patched_uid;                  /* 装 proxy 时的 current_uid */
    char patched_path[64];            /* 装 proxy 时的 /dev/input/eventN */
    char patched_comm[16];            /* 装 proxy 时的 current->comm */
    int abs_x_min, abs_x_max;
    int abs_y_min, abs_y_max;
    int has_mt_slot;
    int has_mt_tracking_id;
    int has_btn_touch;
    int last_reject_reason;
    unsigned int reject_uid_count;
    unsigned int reject_name_count;
    unsigned int reject_path_count;
    unsigned int reject_caps_count;
};

#endif /* ABI_H */
