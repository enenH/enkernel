// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
#define __user
#define TASK_SIZE (1ULL << 48)
#define GFP_KERNEL 0
#define CAP_SYS_PTRACE 19
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
static int patch_srcu, srcu_readers, syncs, bh_depth, flush_calls, update_calls;
static void (*on_sync)(void);
static int srcu_read_lock(int *s) { (void)s; ++srcu_readers; return 0; }
static void srcu_read_unlock(int *s, int index) { (void)s; (void)index; assert(srcu_readers); --srcu_readers; }
static void synchronize_srcu(int *s) { (void)s; assert(!srcu_readers); ++syncs; if(on_sync)on_sync(); }
static void local_bh_disable(void) { ++bh_depth; }
static void local_bh_enable(void) { assert(bh_depth==1); --bh_depth; }
static int control_lock, init_user_ns;
static bool ptrace_capable = true;
static bool ns_capable(int *ns, int cap) { (void)ns; (void)cap; return ptrace_capable; }
static void mutex_lock(int *lock) { assert(!*lock); ++*lock; }
static void mutex_unlock(int *lock) { assert(*lock==1); --*lock; }
static void *kvcalloc(size_t n, size_t size, int flags) { (void)flags; return calloc(n,size); }
static void kvfree(void *p) { free(p); }
static unsigned long copy_from_user(void *out, const void *in, size_t n) { if(!in)return n;memcpy(out,in,n);return 0; }
#define u64_to_user_ptr(p) ((void *)(uintptr_t)(p))
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
static bool fp_foreign;
static bool update_saved_only;
static void flush_fp_mock(struct task_struct *t) { (void)t; assert(bh_depth); fp_foreign=true; ++flush_calls; }
static void update_fp_mock(const struct user_fpsimd_state *fp) {
    assert(bh_depth && fp_foreign);
    current->thread.uw.fpsimd_state=*fp;
    if (!update_saved_only) { live_fp=*fp; fp_foreign=false; }
    ++update_calls;
}
static void el0_restore_mock(void) {
    if(fp_foreign){live_fp=current->thread.uw.fpsimd_state;fp_foreign=false;}
}
static void (*update_user_fpsimd)(const struct user_fpsimd_state *)=update_fp_mock;
static void (*flush_user_fpsimd)(struct task_struct *)=flush_fp_mock;
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
static void preserve_and_change_rules(void) {
    preserve_mock();
    ++session->rules_revision;
}
static void exit_during_rules_drain(void) { session->active=false; }

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
    static struct file owner={1};state.owner=&owner;
    current = &task; session = &state; state.mm = &mm; state.active = true;
    state.pages = 1; state.page[0].address = PAGE_SIZE;
    state.page[0].original = 0x1001; state.page[0].valid = true;
    state.page[0].page = &code; mm.entries[0] = 0x1001;
    state.snapshot.point_count = 1; state.snapshot.addresses[0] = PAGE_SIZE;
    state.snapshot.generation=1;
    regs.pc = PAGE_SIZE; regs.sp = 0x1234; regs.regs[5] = 0x5566;
    preserve_calls = 0; supports_fp = true; preserve_user_fpsimd = preserve_mock;
    sync_user_fpsimd = NULL; sync_calls = 0;
    flush_user_fpsimd=flush_fp_mock;update_user_fpsimd=update_fp_mock;
    assert(!srcu_readers && !bh_depth && !control_lock);
    syncs=flush_calls=update_calls=0;fp_foreign=false;ptrace_capable=true;
    update_saved_only=false;on_sync=NULL;
    memset(&live_fp, 0, sizeof(live_fp));
    for (unsigned n = 0; n < 32; ++n)
        live_fp.vregs[n] = ((unsigned __int128)(0x123456789abcdef0ULL + n) << 64) |
                          (0xfedcba9876543210ULL - n);
    live_fp.fpcr = 0x00400000; live_fp.fpsr = 0x08000001;
    ((u32 *)code.data)[0] = 0xd503201f; // NOP
    assert(set_armed(&mm, &state.page[0], true) == 0);
}
static void persistent_rules(bool saved_only)
{
    struct dfm_pte_rule rule = { .address=PAGE_SIZE, .x_mask=1U | (1U<<30),
        .q_mask=1U | (1U<<31), .flags=DFM_PTE_RULE_FPCR | DFM_PTE_RULE_FPSR };
    struct dfm_pte_rules_req req={ .abi_version=DFM_PTE_RULES_ABI_VERSION,
        .generation=1, .rules=(uintptr_t)&rule, .count=1 };
    struct file outsider={2};
    rule.x[0]=123;rule.x[30]=456;
    rule.q[0][0]=0x1111222233334444ULL;rule.q[0][1]=0x5555666677778888ULL;
    rule.q[31][0]=0x9999aaaabbbbccccULL;rule.q[31][1]=0xddddeeeeffff0000ULL;
    rule.fpcr=0x00400000;rule.fpsr=2;
    reset();
    update_saved_only=saved_only;
    assert(dfm_pte_rules(&outsider,&req)==-EACCES && !state.rule_count);
    req.generation=2;assert(dfm_pte_rules(state.owner,&req)==-ESTALE);req.generation=1;
    ptrace_capable=false;assert(dfm_pte_rules(state.owner,&req)==-EPERM);ptrace_capable=true;
    rule.x_mask|=1U<<31;assert(dfm_pte_rules(state.owner,&req)==-EINVAL);rule.x_mask&=~(1U<<31);
    rule.x[1]=1;assert(dfm_pte_rules(state.owner,&req)==-EINVAL);rule.x[1]=0;
    rule.q[1][1]=1;assert(dfm_pte_rules(state.owner,&req)==-EINVAL);rule.q[1][1]=0;
    rule.address+=4;assert(dfm_pte_rules(state.owner,&req)==-ENOENT);rule.address-=4;
    rule.flags|=8;assert(dfm_pte_rules(state.owner,&req)==-EINVAL);rule.flags&=~8U;
    flush_user_fpsimd=NULL;assert(dfm_pte_rules(state.owner,&req)==-EOPNOTSUPP);flush_user_fpsimd=flush_fp_mock;
    struct dfm_pte_rule duplicate[2]={rule,rule};req.rules=(uintptr_t)duplicate;req.count=2;
    assert(dfm_pte_rules(state.owner,&req)==-EEXIST);req.rules=(uintptr_t)&rule;req.count=1;
    assert(dfm_pte_rules(state.owner,&req)==0 && state.rules_active && syncs==1);
    rule.flags|=8;assert(dfm_pte_rules(state.owner,&req)==-EINVAL);rule.flags&=~8U;
    assert(state.rules[0].x[0]==123 && state.rules_active && syncs==1);
    const struct user_fpsimd_state before=live_fp;
    for(unsigned n=0;n<200;++n) {
        live_fp=before;regs.regs[0]=n;regs.regs[30]=n+1000;
        assert(handle_fault(regs.pc,syndrome,&regs));
        el0_restore_mock(); // New kernels reload saved state before original EL0 instruction.
        const struct dfm_pte_record *r=&state.snapshot.records[n%64];
        assert(r->x[0]==n && r->x[30]==n+1000 && r->patch_status==DFM_PTE_PATCH_APPLIED);
        assert(!memcmp(r->q,before.vregs,sizeof(r->q)) && r->fpcr==before.fpcr && r->fpsr==before.fpsr);
        assert(regs.regs[0]==123 && regs.regs[30]==456 && regs.regs[5]==0x5566);
        assert(!memcmp(&live_fp.vregs[0],rule.q[0],16) && !memcmp(&live_fp.vregs[31],rule.q[31],16));
        for(unsigned i=1;i<31;++i)assert(live_fp.vregs[i]==before.vregs[i]);
        assert(live_fp.fpcr==rule.fpcr && live_fp.fpsr==rule.fpsr);
        assert(regs.pc==PAGE_SIZE && regs.sp==0x1234);
        cancel_current(&regs);
    }
    assert(update_calls==200 && flush_calls==200 && syncs==1); // One config, no per-hit RPC.
    req.count=0;req.rules=0;assert(dfm_pte_rules(state.owner,&req)==0 && !state.rules_active && syncs==2);
    regs.regs[0]=9;assert(handle_fault(regs.pc,syndrome,&regs));
    assert(regs.regs[0]==9 && !state.snapshot.records[200%64].patch_status && update_calls==200);
    cancel_current(&regs);
    req.count=1;req.rules=(uintptr_t)&rule;assert(dfm_pte_rules(state.owner,&req)==0);
    preserve_user_fpsimd=NULL;regs.regs[0]=42;
    assert(handle_fault(regs.pc,syndrome,&regs));
    assert(regs.regs[0]==42 && state.snapshot.records[201%64].patch_status==-EOPNOTSUPP);
    cancel_current(&regs);
    preserve_user_fpsimd=preserve_and_change_rules;regs.regs[0]=43;
    assert(handle_fault(regs.pc,syndrome,&regs));
    assert(regs.regs[0]==43 && state.snapshot.records[202%64].patch_status==-ESTALE);
    cancel_current(&regs);
    // GPR-only rules work without an FPSIMD backend.
    rule=(struct dfm_pte_rule){ .address=PAGE_SIZE,.x_mask=1 };rule.x[0]=7;
    preserve_user_fpsimd=NULL;assert(dfm_pte_rules(state.owner,&req)==0);
    assert(handle_fault(regs.pc,syndrome,&regs));assert(regs.regs[0]==7 && update_calls==200);
    cancel_current(&regs);
    on_sync=exit_during_rules_drain;
    assert(dfm_pte_rules(state.owner,&req)==-ESRCH && !state.rules_active);
    on_sync=NULL;
    state.active=false;assert(dfm_pte_rules(state.owner,&req)==-ESRCH);
    session=NULL;assert(dfm_pte_rules(&outsider,&req)==-ENOENT);
    puts("PTE persistent register rules passed: 200 autonomous masked writes, pre-write records, ownership/generation, replace/remove and all-or-none failure");
}
static void predicate_rules(bool saved_only)
{
    struct dfm_pte_rule rule = { .address=PAGE_SIZE, .q_mask=1U<<3,
        .flags=DFM_PTE_RULE_MATCH_X0, .x={0x12340000} };
    struct dfm_pte_rules_req req = { .abi_version=DFM_PTE_RULES_ABI_VERSION,
        .generation=1, .rules=(uintptr_t)&rule, .count=1 };
    reset(); update_saved_only=saved_only;
    rule.q[3][0]=0x3f800000;
    rule.x_mask=1;assert(dfm_pte_rules(state.owner,&req)==-EINVAL);rule.x_mask=0;
    rule.x[0]=0;assert(dfm_pte_rules(state.owner,&req)==-EINVAL);rule.x[0]=0x12340000;
    rule.q_mask=0;assert(dfm_pte_rules(state.owner,&req)==-EINVAL);rule.q_mask=1U<<3;
    assert(dfm_pte_rules(state.owner,&req)==0);
    const struct user_fpsimd_state before=live_fp;
    for(unsigned n=0;n<40;++n) {
        const bool matches=(n&1)==0;
        live_fp=before;regs.regs[0]=rule.x[0]+!matches;
        assert(handle_fault(regs.pc,syndrome,&regs));el0_restore_mock();
        const struct dfm_pte_record *r=&state.snapshot.records[n%64];
        assert(r->patch_status==(matches?DFM_PTE_PATCH_APPLIED:0));
        assert(regs.regs[0]==rule.x[0]+!matches);
        assert(!memcmp(r->q,before.vregs,sizeof(r->q)));
        if(matches)assert(!memcmp(&live_fp.vregs[3],rule.q[3],16));
        else assert(!memcmp(&live_fp,&before,sizeof(before)));
        cancel_current(&regs);
    }
    assert(update_calls==20 && flush_calls==20);
    // A GPR predicate must not require the optional FPSIMD backend.
    rule.q_mask=0;rule.q[3][0]=0;rule.x_mask=2;rule.x[1]=123;
    preserve_user_fpsimd=NULL;assert(dfm_pte_rules(state.owner,&req)==0);
    regs.regs[0]=rule.x[0];assert(handle_fault(regs.pc,syndrome,&regs));
    assert(regs.regs[1]==123 && regs.regs[0]==rule.x[0]);cancel_current(&regs);
    puts("PTE X0 predicate passed: matches write, other objects unchanged, masked vectors and no-FP GPR rules");
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
    persistent_rules(false);
    persistent_rules(true);
    predicate_rules(false);
    predicate_rules(true);
    puts("PTE production fault/step/notifier and synchronized Q0-Q31/FPCR/FPSR model passed");
    return 0;
}
