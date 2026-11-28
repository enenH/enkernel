// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "abi.h"
#include "pte_bp_policy.h"
#ifndef ESTALE
#define ESTALE 116
#endif
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint64_t pte_t;
typedef uint64_t pteval_t;
typedef int spinlock_t;
#define PAGE_SIZE 4096UL
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PTE_AF (1ULL << 10)
#define PTE_DIRTY (1ULL << 55)
#define PTE_UXN (1ULL << 54)
#define TIF_SINGLESTEP 1
#define DBG_SPSR_SS (1U << 21)
#define DBG_HOOK_ERROR 1
#define DBG_HOOK_HANDLED 0
#define ESR_ELx_EC(esr) ((esr) >> 26)
#define ESR_ELx_EC_IABT_LOW 0x20
#define ESR_ELx_EC_SOFTSTP_LOW 0x32
#define __nocfi
#define NOKPROBE_SYMBOL(name)
#define ESR_ELx_FSC 0x3f
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define spin_lock_irqsave(lock, flags) ((void)(lock), (flags) = 0)
#define spin_unlock_irqrestore(lock, flags) ((void)(lock), (void)(flags))
#define container_of(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))
#define pte_val(x) (x)
#define __pte(x) (x)
#define pte_present(x) ((x) & 1)
#define untagged_addr(x) (x)
#define offset_in_page(x) ((x) & (PAGE_SIZE - 1))
struct mm_struct { pte_t entries[DFM_PTE_MAX_POINTS]; };
struct page { unsigned char data[PAGE_SIZE]; };
struct file { int id; };
struct mmu_notifier { int unused; };
struct mmu_notifier_range { unsigned long start, end; };
struct pt_regs { uint64_t regs[31], sp, pc, pstate; int kernel, compat; };
struct user_fpsimd_state { unsigned __int128 vregs[32]; uint32_t fpsr, fpcr, reserved[2]; };
struct task_struct {
    struct mm_struct *mm; int ptrace, step, refs, pid, tid;
    struct { struct { struct user_fpsimd_state fpsimd_state; } uw; } thread;
};
struct kernel_siginfo {};
struct k_sigaction {};
struct step_hook { int (*fn)(struct pt_regs *, unsigned long); };
typedef uint32_t kprobe_opcode_t;
struct kprobe { kprobe_opcode_t *addr; int (*pre_handler)(struct kprobe *, struct pt_regs *); };
static struct pt_regs regs;
static struct pt_regs *task_pt_regs(struct task_struct *task) { (void)task; return &regs; }
#define instruction_pointer_set(r, value) ((r)->pc = (value))
#ifdef DFM_PTE_USER_STEP_HOOK
static int registrations, unregistrations;
static void register_step(struct step_hook *hook) { assert(hook->fn); ++registrations; }
static void unregister_step(struct step_hook *hook) { assert(hook->fn); ++unregistrations; }
#else
static struct kprobe softstep_probe;
static uintptr_t softstep_address = 0x4000;
static int register_result, registrations, unregistrations, relocate_probe;
static int register_kprobe(struct kprobe *probe)
{
    assert((uintptr_t)probe->addr == softstep_address && probe->pre_handler);
    ++registrations;
    if (!register_result && relocate_probe) probe->addr++;
    return register_result;
}
static void unregister_kprobe(struct kprobe *probe) { assert(probe == &softstep_probe); ++unregistrations; }
#endif
static struct task_struct *current;
static struct user_fpsimd_state live_fp;
static bool supports_fp = true;
static int preserve_calls;
static bool system_supports_fpsimd(void) { return supports_fp; }
static void preserve_mock(void) {
    ++preserve_calls;
    current->thread.uw.fpsimd_state = live_fp;
}
static void (*preserve_user_fpsimd)(void) = preserve_mock;
static void (*sync_user_fpsimd)(struct task_struct *);
static struct user_fpsimd_state saved_sve;
static int sync_calls;
static void preserve_sve_mock(void) { ++preserve_calls; saved_sve = live_fp; }
static void sync_sve_mock(struct task_struct *t) { ++sync_calls; t->thread.uw.fpsimd_state = saved_sve; }
static spinlock_t state_lock;
static int tlbs;
static int inject_hardware_update;
static uint64_t compare_exchange(uint64_t *p, uint64_t old, uint64_t value)
{
    if (inject_hardware_update) {
        *p |= PTE_AF | PTE_DIRTY;
        inject_hardware_update = 0;
    }
    uint64_t observed = *p;
    if (observed == old) *p = value;
    return observed;
}
#define cmpxchg_relaxed(p, old, value) compare_exchange((p), (old), (value))
static bool user_mode(struct pt_regs *r) { return !r->kernel; }
static bool compat_user_mode(struct pt_regs *r) { return r->compat; }
static bool test_thread_flag(int f) { (void)f; return current->step; }
static void set_thread_flag(int f) { (void)f; current->step = 1; }
static void get_task_struct(struct task_struct *t) { ++t->refs; }
static void put_task_struct(struct task_struct *t) { assert(t->refs > 0); --t->refs; }
static void *page_address(struct page *p) { return p->data; }
static uint64_t ktime_get_ns(void) { static uint64_t tick; return ++tick; }
static int task_tgid_vnr(struct task_struct *t) { return t->pid; }
static int task_pid_vnr(struct task_struct *t) { return t->tid; }
static void invalidate_tlb(unsigned long a) { (void)a; ++tlbs; }
static pte_t *lock_pte(struct mm_struct *mm, unsigned long a, spinlock_t **lock)
{ static spinlock_t ptl; *lock = &ptl; return &mm->entries[a / PAGE_SIZE - 1]; }
static void unlock_pte(spinlock_t *lock) { (void)lock; }
static void disable_local_step(struct pt_regs *r)
{ current->step = 0; r->pstate &= ~DBG_SPSR_SS; }
#include "pte_under_test.h"
static void preserve_and_change_generation(void) {
    preserve_mock();
    ++session->snapshot.generation;
}

static struct pte_session state;
static struct mm_struct mm;
static struct task_struct task;
static struct page code;
static const unsigned long syndrome = (0x20UL << 26) | 15;
static void reset(void)
{
    memset(&state, 0, sizeof(state)); memset(&mm, 0, sizeof(mm));
    memset(&task, 0, sizeof(task)); memset(&regs, 0, sizeof(regs));
    memset(&code, 0, sizeof(code));
    task.mm = &mm; task.pid = 10; task.tid = 11;
    current = &task; session = &state; state.mm = &mm; state.active = true;
    state.pages = 1; state.page[0].address = PAGE_SIZE;
    state.page[0].original = 0x1001; state.page[0].valid = true;
    state.page[0].page = &code; mm.entries[0] = 0x1001;
    state.snapshot.point_count = 1; state.snapshot.addresses[0] = PAGE_SIZE;
    regs.pc = PAGE_SIZE; regs.sp = 0x1234; regs.regs[5] = 0x5566;
    preserve_calls = 0; supports_fp = true; preserve_user_fpsimd = preserve_mock;
    sync_user_fpsimd = NULL; sync_calls = 0;
    memset(&live_fp, 0, sizeof(live_fp));
    for (unsigned n = 0; n < 32; ++n)
        live_fp.vregs[n] = ((unsigned __int128)(0x123456789abcdef0ULL + n) << 64) |
                          (0xfedcba9876543210ULL - n);
    live_fp.fpcr = 0x00400000; live_fp.fpsr = 0x08000001;
    ((u32 *)code.data)[0] = 0xd503201f; // NOP
    assert(set_armed(&mm, &state.page[0], true) == 0);
}
int main(void)
{
    assert(step_register_call(true) == 0 && registrations == 1);
    assert(step_register_call(false) == 0 && unregistrations == 1);
#ifdef DFM_PTE_SOFTSTEP_KPROBE
    register_result = -EBUSY;
    assert(step_register_call(true) == -EBUSY && registrations == 2);
    assert(unregistrations == 1);
    register_result = 0;
    assert(step_register_call(true) == 0);
    assert(step_register_call(false) == 0 && unregistrations == 2);
    relocate_probe = 1;
    assert(step_register_call(true) == -EOPNOTSUPP && unregistrations == 3);
    relocate_probe = 0;
#endif
    _Static_assert(DFM_PTE_ABI_VERSION == 2, "PTE vector ABI is versioned");
    _Static_assert(offsetof(struct dfm_pte_record, q) == 304, "fixed vector ABI offset");
    _Static_assert(sizeof(struct dfm_pte_record) == 832, "fixed vector ABI size");
    struct dfm_pte_set_req request = { .abi_version = 1, .pid = 1, .point_count = 1,
                                     .addresses = {4096} };
    assert(dfm_pte_validate(&request, 1ULL << 48) == -EINVAL);
    request.abi_version = DFM_PTE_ABI_VERSION;
    assert(dfm_pte_validate(&request, 1ULL << 48) == 0);
    request.addresses[0] = UINT64_MAX; assert(dfm_pte_validate(&request, 1ULL << 48) == -EINVAL);
    request.addresses[0] = 4098; assert(dfm_pte_validate(&request, 1ULL << 48) == -EINVAL);
    request.addresses[0] = 4096; request.addresses[1] = 4096; request.point_count = 2;
    assert(dfm_pte_validate(&request, 1ULL << 48) == -EEXIST);
    request.point_count = 1; assert(dfm_pte_validate(&request, 1ULL << 48) == -EINVAL);
    request.addresses[1] = 0; request.flags = 1;
    assert(dfm_pte_validate(&request, 1ULL << 48) == -EINVAL);
    for (unsigned i = 0; i < 200; ++i) {
        if (!i) reset();
        assert(handle_fault(regs.pc, syndrome, &regs));
        assert(task.step && task.refs == 1 && !(mm.entries[0] & PTE_UXN));
        assert(state.snapshot.total_hits == i + 1 && !state.page[0].armed);
#ifdef DFM_PTE_SOFTSTEP_KPROBE
        struct pt_regs entry = { .pc = softstep_address };
        entry.regs[0] = (0x32ULL << 26);
        entry.regs[1] = (uintptr_t)&regs;
        entry.regs[30] = 0x8000;
        struct pt_regs unrelated_regs = {0};
        entry.regs[1] = (uintptr_t)&unrelated_regs;
        assert(softstep_pre(&softstep_probe, &entry) == 0 && task.step);
        entry.regs[1] = (uintptr_t)&regs;
        entry.regs[0] = syndrome;
        assert(softstep_pre(&softstep_probe, &entry) == 0 && task.step);
        entry.regs[0] = (0x32ULL << 26);
        regs.kernel = 1;
        assert(softstep_pre(&softstep_probe, &entry) == 0 && task.step);
        regs.kernel = 0; regs.compat = 1;
        assert(softstep_pre(&softstep_probe, &entry) == 0 && task.step);
        regs.compat = 0;
        assert(softstep_pre(&softstep_probe, &entry) == 1);
        assert(entry.pc == 0x8000 && entry.regs[30] == 0x8000);
        assert(entry.regs[0] == (0x32ULL << 26) && entry.regs[1] == (uintptr_t)&regs);
        entry.pc = softstep_address;
        assert(softstep_pre(&softstep_probe, &entry) == 0 && entry.pc == softstep_address);
#else
        assert(step_hook.fn(&regs, 0) == DBG_HOOK_HANDLED);
#endif
        assert(!task.step && task.refs == 0 && (mm.entries[0] & PTE_UXN));
    }
    assert(state.snapshot.record_count == 64 && state.snapshot.dropped == 136);
    assert(state.snapshot.records[199 % 64].x[5] == 0x5566);
    const struct dfm_pte_record *record = &state.snapshot.records[199 % 64];
    assert(preserve_calls == 200 && record->fp_status == 0);
    assert(!memcmp(record->q, live_fp.vregs, sizeof(record->q)));
    assert(record->fpcr == live_fp.fpcr && record->fpsr == live_fp.fpsr);
    assert(!memcmp(&current->thread.uw.fpsimd_state, &live_fp, sizeof(live_fp)));
    assert(state.snapshot.rearms == 200 && step_handler(&regs, 0) == DBG_HOOK_ERROR);
    reset();
    mm.entries[0] |= PTE_AF | PTE_DIRTY;
    assert(handle_fault(regs.pc, syndrome, &regs));
    cancel_current(&regs);
    assert(mm.entries[0] & PTE_AF); assert(mm.entries[0] & PTE_DIRTY);
    assert(!task.step && !task.refs && state.page[0].armed);
    reset(); preserve_user_fpsimd = NULL;
    memset(&current->thread.uw.fpsimd_state, 0xa5, sizeof(live_fp));
    assert(handle_fault(regs.pc, syndrome, &regs));
    record = &state.snapshot.records[0];
    assert(record->fp_status == -EOPNOTSUPP && !record->q[0][0] && !record->fpcr);
    assert(!preserve_calls); cancel_current(&regs);
    reset(); preserve_user_fpsimd = preserve_sve_mock; sync_user_fpsimd = sync_sve_mock;
    memset(&current->thread.uw.fpsimd_state, 0xa5, sizeof(live_fp));
    assert(handle_fault(regs.pc, syndrome, &regs));
    record = &state.snapshot.records[0];
    assert(!record->fp_status && !memcmp(record->q, live_fp.vregs, sizeof(record->q)));
    assert(preserve_calls == 1 && sync_calls == 1); cancel_current(&regs);
    reset(); preserve_user_fpsimd = preserve_and_change_generation;
    assert(handle_fault(regs.pc, syndrome, &regs));
    record = &state.snapshot.records[0];
    assert(record->fp_status == -ESTALE && !record->q[31][1] && !record->fpsr);
    cancel_current(&regs);
    reset(); supports_fp = false;
    assert(handle_fault(regs.pc, syndrome, &regs));
    assert(state.snapshot.records[0].fp_status == -EOPNOTSUPP && !preserve_calls);
    cancel_current(&regs);
    reset(); regs.pc += 4;
    assert(handle_fault(regs.pc, syndrome, &regs));
    assert(!preserve_calls && !state.snapshot.total_hits);
    cancel_current(&regs);
    reset();
    inject_hardware_update = 1;
    assert(handle_fault(regs.pc, syndrome, &regs));
    assert((mm.entries[0] & (PTE_AF | PTE_DIRTY)) == (PTE_AF | PTE_DIRTY));
    cancel_current(&regs);
    assert((mm.entries[0] & (PTE_AF | PTE_DIRTY)) == (PTE_AF | PTE_DIRTY));
    reset();
    regs.kernel = 1; assert(!handle_fault(regs.pc, syndrome, &regs)); regs.kernel = 0;
    assert(!handle_fault(regs.pc, (0x24UL << 26) | 15, &regs));
    assert(!handle_fault(regs.pc + 4, syndrome, &regs));
    struct mm_struct unrelated = {0}; task.mm = &unrelated;
    assert(!handle_fault(regs.pc, syndrome, &regs));
    reset(); task.step = 1;
    assert(handle_fault(regs.pc, syndrome, &regs));
    assert(!state.page[0].valid && task.step && !task.refs);
    reset(); ((u32 *)code.data)[0] = 0xc85f7c00; // LDXR
    assert(handle_fault(regs.pc, syndrome, &regs));
    assert(!state.page[0].valid && !task.step && state.snapshot.last_error == -EOPNOTSUPP);
    assert(!dfm_pte_instruction_safe(0xc8007c01)); // STXR
    assert(!dfm_pte_instruction_safe(0xf8200001)); // LDADD
    assert(dfm_pte_instruction_safe(0xd65f03c0)); // RET
    reset(); mm.entries[0] ^= 0x2000; // remapped PFN, never overwrite it
    pte_t changed = mm.entries[0];
    assert(!handle_fault(regs.pc, syndrome, &regs)); assert(mm.entries[0] == changed);
    reset(); assert(handle_fault(regs.pc, syndrome, &regs));
    struct mmu_notifier_range range = {4096, 8192};
    assert(invalidate_start(&state.notifier, &range) == 0);
    mm.entries[0] = 0x7771;
    assert(step_handler(&regs, 0) == DBG_HOOK_HANDLED);
    assert(mm.entries[0] == 0x7771 && !task.refs && !task.step);
    reset(); mm_release(&state.notifier, &mm);
    assert(!state.active && !(mm.entries[0] & PTE_UXN));
    assert(!handle_fault(regs.pc, syndrome, &regs));
    assert(tlbs > 0);
    reset(); assert(handle_fault(regs.pc, syndrome, &regs));
    sys_enter(NULL, &regs, 0);
    assert(!task.step && !task.refs && state.page[0].armed);
    reset(); assert(handle_fault(regs.pc, syndrome, &regs));
    signal_deliver(NULL, 0, NULL, NULL);
    assert(!task.step && !task.refs && state.page[0].armed);
    reset(); assert(handle_fault(regs.pc, syndrome, &regs));
#ifdef DFM_PTE_EXIT_GROUP_DEAD
    task_exit(NULL, &task, true);
#else
    task_exit(NULL, &task);
#endif
    assert(!task.step && !task.refs && state.page[0].armed);
    puts("PTE production fault/step/notifier and synchronized Q0-Q31/FPCR/FPSR model passed");
    return 0;
}
