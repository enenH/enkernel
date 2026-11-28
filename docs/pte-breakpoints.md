# Persistent PTE execution breakpoints

The optional PTE ABI traces ARM64 execution using a page's UXN permission and
native EL0 single stepping. It records GPR and user FPSIMD state at the requested PC, runs the
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
    // Each record: fp_status == 0 validates q[0..31], fpcr and fpsr.
    // q[n][0] is the low 64 bits; q[n][1] is the high 64 bits.
    rc = dfm::pte_clear();

Raw requests use ABI version 2. The prior GPR-only ABI 1 is rejected with EINVAL;
old/new SDKs and modules must not reinterpret each other's snapshots. The ioctl
numbers remain unchanged. Reserved/unused fields and trailing point
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
armed_pages/open_pages index deduplicated pages in first-PC order. Records contain
GPR, PC/SP/PSTATE, PID/TID, sequence and monotonic time, plus Q0-Q31 (128 bits
each), FPCR and FPSR. A zero fp_status is required before using the vector fields;
negative errno means unavailable, with those output fields zeroed. INFO_FPSIMD
advertises the optional synchronized vector backend. Its absence does not disable
GPR tracing. These are snapshots before the original instruction executes.

The fault handler synchronizes current's user FP state outside the PTE/state
spinlock, using fpsimd_signal_preserve_current_state on legacy kernels or the
fpsimd_preserve_current_state + fpsimd_sync_from_effective_state pair on newer
kernels. This includes lazy CPU ownership and the low-128-bit view of saved
SVE/SME state; raw thread cache copies are not accepted as live vector snapshots.
If the synchronization helper(s) or hardware support are absent, fp_status is
EOPNOTSUPP. A session change during synchronization reports ESTALE for the vector
fields. The recorder is read-only unless persistent rules are configured. Full SVE/SME scalable
registers, predicates, ZA and FPMR are not part of this ABI.
The capability bit advertises the ABI, not backend availability or exact module
commit. INFO is read-only; it does not install fault hooks.

## Persistent register-write rules

RULES (ioctl 50, rules ABI 1) installs a bounded table in the existing owned
session. Configure once, then every observed matching PC hit applies the selected
constant register replacements inside the kernel before executing the original
instruction. There is no per-hit ioctl, userspace stop/reply or network exchange.
This avoids userspace round-trip latency; the page-fault, TLB and native-step
overhead and the other-thread pass window still exist. It does not make tracing
lossless or zero-cost.

    // SET first, then READ once to obtain the exact session generation.
    rc = dfm::pte_read(snapshot);
    dfm_pte_rule rule{};
    rule.address = executable_pc;
    rule.x_mask = 1U << 0;  // replace X0; all unselected inputs stay zero
    rule.x[0] = 123;
    rule.q_mask = 1U << 0;  // replace all 128 bits of Q0
    rule.q[0][0] = low_bits;
    rule.q[0][1] = high_bits;
    rc = dfm::pte_rules(snapshot.generation, &rule, 1);
    // Controller may now sleep/work elsewhere; no communication per hit.
    // Check record.patch_status: 0=no rule, 1=applied, negative errno=skipped.
    rc = dfm::pte_rules(snapshot.generation, nullptr, 0); // remove only rules
    rc = dfm::pte_clear(); // remove tracing and rules

At most one rule per configured PC, up to 16 rules. X masks select X0-X30;
Q masks select Q0-Q31 (whole 128-bit lanes). RULE_FPCR/RULE_FPSR select the two
32-bit control/status values. PC, SP, PSTATE, arbitrary memory, callbacks and
user bytecode are not writable through this API. Bits outside the masks, unused
values, duplicate PCs, unknown flags and non-session addresses are rejected.

INFO_MATCH_X0 advertises an optional exact input-X0 predicate without changing
the ABI layout. Set RULE_MATCH_X0, put the nonzero required input in x[0], and
leave x_mask bit 0 clear. X0 cannot also be replaced by that rule. Other selected
registers are replaced only on matching hits; mismatches keep every register
unchanged and report patch_status=0. This compares a register value, not object
lifetime or ownership: the controller must invalidate the rule when its object
changes, is freed, or the target context expires. A predicate alone with no
replacement is rejected. Old modules reject this new flag instead of treating
the predicate value as a replacement.

INFO_PROBABILITY advertises per-hit probabilistic rules. With RULE_PROBABILITY,
the former reserved word contains an integer percentage 0..100. Each matching
hit samples get_random_u32 in the driver and compares its multiply-high 0..99
bucket to that percentage. Zero never writes; 100 always writes. Skipped hits
retain every register and report patch_status=0; selected hits retain the usual
all-or-none write semantics. This is per observed function invocation (so
multiple projectile/pellet calls are independent), not per render frame.
Old modules reject the flag; clients must query INFO_PROBABILITY. Without the
flag the reserved word must still be zero. No ABI size/version changes.
The ioctl requires CAP_SYS_PTRACE in init_user_ns, the same file description
as SET, and the exact snapshot generation. A fresh process/PID reuse cannot
reuse old rules. A failed validation leaves the old configuration unchanged.

INFO_WRITE_GPR advertises rule support; INFO_WRITE_FPSIMD additionally requires
the capture backend and dynamically resolved fpsimd_flush_task_state and
fpsimd_update_current_state. Vector/control rules are rejected at configuration
time if those helpers/hardware are unavailable. On a later capture failure or
rule/session change, the complete rule is skipped (including X replacements),
and patch_status reports the negative errno. GPR-only rules still work without
FPSIMD. Records always describe the input state before replacements; the original
instruction can itself overwrite selected registers afterwards.

Vector writes use a synchronized, masked copy of the full user state. Outside
the state spinlock, bottom halves are excluded, CPU ownership is invalidated,
and the kernel update helper installs the saved/SVE-compatible replacement.
This supports both old immediate-load and newer saved-state-only helper behavior.
No stale CPU image is allowed to overwrite the new saved state on EL0 return.

Rule replacement first disables the old table, drains in-flight writes with a
dedicated SRCU domain, then publishes the new table. Tracing continues during
this short no-rule interval. CLEAR/final file release also drains pending writes
before freeing the session. Consequently no old-table write happens after the
replace/remove/CLEAR call returns. Configuration is persistent only for that live
session: it is not saved to disk, does not survive final FD close/exec/mm loss,
and does not run after reboot. Keep an owned FD open; a per-command process that
exits and closes its last FD will remove the session and rules.

## Execution and lifetime

Only resident ordinary base pages in private executable, non-writable VMAs
with VM_MAYWRITE are accepted. Huge/contiguous/compound, device/PFN, shared,
swapped-out and non-executable mappings are rejected. There is no fault-in or
GUP fallback. The ordinary memory read backend is independent of this policy.

The backend verifies and replaces the ARM64 level 1/2/3 permission-fault
callbacks using the existing checked pointer-patch mechanism. Only EL0 ARM64
level-3 instruction permission faults for the exact managed mm/page are
consumed. Other faults call the retained original callback. No instruction
custom entry trampoline or syscall body is patched. Optional symbols, known fault
table layout, MMU notifiers, Tasks RCU/SRCU and syscall tracepoints are required;
unknown/absent support fails with EOPNOTSUPP. Callback syndrome widths are
detected from the selected kernel source, including the 32-bit 5.10 ABI.
The changed sched_process_exit group_dead argument is detected independently,
and kernel trace headers type-check the exit/fork callbacks during compilation.
The native backend targets Android 5.10/5.15/6.1/6.6/6.12/6.18. On older kernels
it registers a user-step hook. When that API is absent, the build detector
accepts only the recognized void do_el0_softstep(unsigned long, pt_regs *) entry
and uses the standard Kprobes API there. The pre-handler validates the current
task's EL0 register frame and software-step syndrome, completes an owned step,
then skips the already-consumed void call by returning to its unmodified entry
LR. Unowned events execute the original instruction and normal uprobe/SIGTRAP
path. Kprobes owns kernel text changes, instruction slots and synchronization;
no custom relocation/trampoline or hardware breakpoint slot is used.
Unknown signatures, blacklisted entries, absent CONFIG_KPROBES, symbol absence
and registration conflicts fail explicitly before any PTE is armed. INFO does
not probe the function; successful SET is required to establish registration.

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
attempts retain the session references and retry. Module exit unregisters the
6.18 Kprobe (which drains pre-handlers), detaches the callbacks and
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
On the Kprobe backend, do not disable Kprobes globally while a session is
active; CLEAR all sessions first. External instrumentation that disables or
overwrites the probe is outside the session's ownership.

## Validation

    python3 tests/run_pte_host.py
    python3 tests/run_pte_backend_host.py

The host model executes production fault, native-step completion, ring and MMU
notifier paths at O0/O2. It covers repeated rearming, AF/dirty preservation,
stale PFNs, invalidation during a step, wrong mm/fault type, existing stepping,
exclusive rejection, bounds and ring overflow. Vector cases verify all Q halves,
FPCR/FPSR, live state synchronization instead of stale saved bytes, split SVE
conversion, missing helpers/hardware and no captures for unrequested PCs.
The same model executes the production RULES ioctl, validates owner/capability,
session generation, masks, reserved values and addresses, and runs 200 autonomous
masked replacements with one configuration for each old/new FP update model.
It checks pre-write snapshots, unselected-register preservation, whole-rule skip
on capture/configuration races, GPR-only operation without FP, rule removal,
and target exit during the replacement rendezvous.
Both legacy and 6.18 routing
run at O0/O2, including foreign frames, wrong syndrome/mode, unowned events,
entry-LR preservation, registration errors and cleanup. Source-tree detection
tests cover legacy callback widths, 6.18, blacklists, unknown ABI and CRLF.
The Windows runner only shims
the unused sys/ioctl.h include; it does not emulate kernel/MMU correctness.

Build with ENKERNEL_BUILD_TESTS=ON and run dfm_pte_check as root on an authorized
device with the matching module already loaded. The fixture is a forked child's
own private, relocation-free vector-load/ADD/vector-store page. It verifies two
batches of exact persistent hits and GPR/Q0-Q31/FPCR/FPSR snapshots on an otherwise
isolated child, native results, unchanged code, unchanged vector/control state
without rules, two 100-hit persistent-write batches separated by rule replacement,
and restored original behavior after rule removal,
bounded ring behavior and clear/retry. Unsupported/old modules return exit 77
(skip), never a pass. This test never loads/unloads modules or changes SELinux.
Six-KMI CI requires the native backend on every ABI and checks that 6.18 includes
the softstep pre-handler; an unexpected fallback fails the build.

Host/SDK/CI build results and device kernel runtime results must be recorded
separately. No successful module runtime test is implied by source compilation.
