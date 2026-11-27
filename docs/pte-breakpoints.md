# Persistent PTE execution breakpoints

The optional PTE ABI traces ARM64 execution using a page's UXN permission and
native EL0 single stepping. It records GPR state at the requested PC, runs the
original instruction, then rearms the page automatically. It needs no hardware
breakpoint slot. It does not modify instruction bytes or redirect execution
to an emulator/shadow page. Existing hardware breakpoint ioctls remain separate.

The design was informed by lsnbm/Linux-android-arm64 at
dc99e8dc7a228520f0dbd5cd288355dbbc17f433. That tree selects
arm64_ptedbg-20260822-000439.h from break_point.h; its alternate arm64_ptedbg.h
uses a different instruction-emulation path. Neither implementation or its
emulator/mprotect interception is imported. See third-party/LsLucky-NOTICE.md.

## API

Include dfm/driver.h and link enkernel::sdk. These methods return negative errno:

    dfm_pte_info_req info{};
    long rc = dfm::pte_info(info);
    // ENOTTY: older module. INFO_AVAILABLE: backend symbols/layout recognized.
    // Availability does not prove that SET or the device runtime test succeeds.
    uint64_t addresses[] = { executable_pc };
    rc = dfm::pte_set(target_pid, addresses, 1);
    dfm_pte_snapshot snapshot{};
    rc = dfm::pte_read(snapshot);
    rc = dfm::pte_clear();

Raw requests use ABI version 1. Reserved/unused fields and trailing point
addresses must be zero. PCs must be nonzero, untagged, four-byte aligned user
addresses. Up to 16 distinct PCs can share pages. A single session is owned by
the exact driver file description that created it; duplicate/delegated copies
of that description share ownership. Independent driver descriptions cannot
read or clear it. SET returns EALREADY for the same owner or EBUSY for another
owner until CLEAR/final close. CLEAR is idempotent; it never unloads the module.

SET requires CAP_SYS_PTRACE in the initial user namespace and the target's
normal ptrace access check, including LSM policy. A session holds the exact mm
identity, not the numeric PID. Fork/exec/PID reuse cannot retarget it. READ is
a non-destructive bounded snapshot with at most 64 records, ordered oldest to
newest. Ring overwrites increment dropped. last_error is negative errno;
armed_pages/open_pages index deduplicated pages in first-PC order. Only GPR,
PC/SP/PSTATE, PID/TID, sequence and monotonic time are recorded, not FP/SIMD.
The capability bit advertises the ABI, not backend availability or exact module
commit. INFO is read-only; it does not install fault hooks.

## Execution and lifetime

Only resident ordinary base pages in private executable, non-writable VMAs
with VM_MAYWRITE are accepted. Huge/contiguous/compound, device/PFN, shared,
swapped-out and non-executable mappings are rejected. There is no fault-in or
GUP fallback. The ordinary memory read backend is independent of this policy.

The backend verifies and replaces the ARM64 level 1/2/3 permission-fault
callbacks using the existing checked pointer-patch mechanism. Only EL0 ARM64
level-3 instruction permission faults for the exact managed mm/page are
consumed. Other faults call the retained original callback. No instruction
entry trampoline or syscall body is patched. Optional symbols, known fault
table layout, MMU notifiers, Tasks RCU/SRCU and syscall tracepoints are required;
unknown/absent support fails with EOPNOTSUPP.

PTE updates take the leaf lock, revalidate the PMD and expected PTE, preserve
live access/dirty bits, and broadcast TLB invalidation (including KPTI ASIDs).
Page references prevent PFN reuse. MMU invalidation disarms the affected page
before unmap/reclaim/protection changes. A private COW fork invalidates its
source range before copying PTEs, so the child cannot inherit an unmanaged
guard. Such pages remain disarmed; the controller must CLEAR/SET to trace a new
mapping. The mm notifier release handles exit/exec without retaining mm_users.

The step handler consumes only steps owned by this session. Signal delivery,
syscall entry and task exit cancel a pending owned step and rearm the page,
preserving normal signal/syscall handling. An existing ptrace/single-step
conflict disarms the page with EBUSY. Do not combine PTE tracing with another
debugger or the HWB backend on the same tasks. Exclusive/CAS/LSE instruction
classes disarm their page with EOPNOTSUPP before native execution: inserting
debug exceptions through an exclusive retry loop can otherwise prevent forward
progress. These failures are visible in last_error/DFM_PTE_INVALIDATED.

CLEAR/final close first stops new steps and restores managed permissions. A
stop-machine rendezvous clears owned saved stepping state before references
are freed; unrelated CPU debug controls are left untouched. Failed rendezvous
attempts retain the session references and retry. Module exit detaches the callbacks and
drains both fetched entries and sleeping original-fault calls with Tasks RCU
and SRCU before releasing callback text. Partial SET/hook installation rolls
back installed state. Stale unrelated PTE changes are never overwritten.

## Limits

Permissions are per page/mm, so any instruction on a managed page can fault.
Only the configured PCs produce records. Other threads sharing the mm can
execute while the page is temporarily executable for a native step. Those
passes are not observable or included in dropped; this is persistent tracing,
not a lossless all-thread instruction trace. Scheduling, signals and other
debug facilities can lengthen the window. Paging/permission changes and
unsupported instructions stop observation on that page. Instrumentation also
adds exceptions and affects timing. Standard OS visibility/security remains.

## Validation

    python3 tests/run_pte_host.py

The host model executes production fault, native-step completion, ring and MMU
notifier paths at O0/O2. It covers repeated rearming, AF/dirty preservation,
stale PFNs, invalidation during a step, wrong mm/fault type, existing stepping,
exclusive rejection, bounds and ring overflow. The Windows runner only shims
the unused sys/ioctl.h include; it does not emulate kernel/MMU correctness.

Build with ENKERNEL_BUILD_TESTS=ON and run dfm_pte_check as root on an authorized
device with the matching module already loaded. The fixture is a forked child's
own private ADD/RET page. It verifies two batches of exact persistent hits and
GPR snapshots on an otherwise isolated child, native results, unchanged code,
bounded ring behavior and clear/retry. Unsupported/old modules return exit 77
(skip), never a pass. This test never loads/unloads modules or changes SELinux.
Six-KMI CI must compile the native backend, not merely its unsupported stubs.

Host/SDK/CI build results and device kernel runtime results must be recorded
separately. No successful module runtime test is implied by source compilation.
