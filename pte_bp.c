// SPDX-License-Identifier: GPL-2.0-only
/* UXN execution traps inspired by Linux-android-arm64/lsdriver. See
 * docs/third-party/LsLucky-NOTICE.md. Instructions execute natively at EL0. */
#include <linux/capability.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/slab.h>
#include <linux/srcu.h>
#include <linux/smp.h>
#include <linux/stop_machine.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>
#include <trace/events/sched.h>
#include <asm/debug-monitors.h>
#include <asm/cpufeature.h>
#include <asm/esr.h>
#include <asm/fpsimd.h>
#include <asm/pgtable.h>
#include <asm/sysreg.h>
#include "abi.h"
#include "pte_bp.h"
#include "pte_bp_policy.h"
#include "syscall.h"

#ifndef __nocfi
#define __nocfi __attribute__((no_sanitize("cfi")))
#endif

#if (defined(DFM_PTE_USER_STEP_HOOK) || \
     (defined(DFM_PTE_SOFTSTEP_KPROBE) && defined(CONFIG_KPROBES))) && \
    defined(CONFIG_MMU_NOTIFIER) && defined(CONFIG_TASKS_RCU) && \
    defined(CONFIG_HAVE_SYSCALL_TRACEPOINTS) && \
    (defined(CONFIG_SRCU) || defined(CONFIG_TREE_SRCU) || defined(CONFIG_TINY_SRCU))

struct pte_page {
    unsigned long address;
    pte_t original;
    struct page *page;
    bool valid, armed;
    unsigned int users;
};
struct pte_step {
    struct task_struct *task;
    unsigned int page;
};
struct pte_session {
    struct file *owner;
    struct mm_struct *mm;
    struct mmu_notifier notifier;
    bool registered, active;
    unsigned int pages;
    struct pte_page page[DFM_PTE_MAX_POINTS];
    struct pte_step steps[DFM_PTE_MAX_STEPPERS];
    struct dfm_pte_snapshot snapshot;
};
static DEFINE_MUTEX(control_lock);
static DEFINE_SPINLOCK(state_lock);
static struct pte_session *session;
static u64 generation;
DEFINE_STATIC_SRCU(fault_srcu);

#ifdef DFM_PTE_STEP_ESR32
typedef unsigned int pte_step_esr_t;
#else
typedef unsigned long pte_step_esr_t;
#endif
#ifdef DFM_PTE_FAULT_ESR32
typedef unsigned int pte_fault_esr_t;
#else
typedef unsigned long pte_fault_esr_t;
#endif

/* Layout from arch/arm64/mm/fault.c on the supported ARM64 kernels. */
struct pte_fault_info {
    int (*fn)(unsigned long, pte_fault_esr_t, struct pt_regs *);
    int sig, code;
    const char *name;
};
static struct pte_fault_info *fault_table;
static typeof(((struct pte_fault_info *)0)->fn) original_fault[3];
static bool fault_patched[3], step_registered;
static bool hooks_ready;
static int backend_error = -EAGAIN;
#ifdef DFM_PTE_USER_STEP_HOOK
static void (*register_step)(struct step_hook *);
static void (*unregister_step)(struct step_hook *);
#else
static unsigned long softstep_address;
static struct kprobe softstep_probe;
#endif
static bool (*target_access)(struct task_struct *, unsigned int);
static void (*preserve_user_fpsimd)(void);
static void (*sync_user_fpsimd)(struct task_struct *);
static struct tracepoint *fork_trace, *exit_trace, *sys_trace, *signal_trace;
static bool fork_registered, exit_registered, sys_registered, signal_registered;

static unsigned long symbol(const char *name)
{
    char cfi[KSYM_NAME_LEN];
    unsigned long address;
    snprintf(cfi, sizeof(cfi), "%s.cfi_jt", name);
    address = kallsyms_lookup_name(cfi);
    return address ? address : kallsyms_lookup_name(name);
}

/* Permission-only changes retain PFN/type. Broadcast includes KPTI ASIDs. */
static void invalidate_tlb(unsigned long address)
{
    unsigned long operand = __TLBI_VADDR(address, 0);
    asm volatile("dsb ishst\n\ttlbi vaale1is, %0\n\tdsb ish\n\tisb"
                 : : "r"(operand) : "memory");
}

/* mmap_lock OR the notifier/state-lock protocol protects the walk. RCU plus
 * PMD revalidation protects detached PTE tables on supported ARM64 kernels. */
static pte_t *lock_pte(struct mm_struct *mm, unsigned long address,
                       spinlock_t **lock)
{
    pgd_t *pgdp = pgd_offset(mm, address);
    p4d_t *p4dp;
    pud_t *pudp;
    pmd_t *pmdp, pmd;
    pte_t *ptep;
    if (pgd_none(*pgdp) || pgd_bad(*pgdp)) return NULL;
    p4dp = p4d_offset(pgdp, address);
    if (p4d_none(*p4dp) || p4d_bad(*p4dp)) return NULL;
    pudp = pud_offset(p4dp, address);
    if (pud_none(*pudp) || pud_bad(*pudp) || pud_leaf(*pudp)) return NULL;
    rcu_read_lock();
    pmdp = pmd_offset(pudp, address);
    pmd = READ_ONCE(*pmdp);
    if (pmd_none(pmd) || pmd_bad(pmd) || pmd_leaf(pmd)) goto fail;
    ptep = pte_offset_kernel(&pmd, address);
    *lock = pte_lockptr(mm, &pmd);
    spin_lock(*lock);
    if (!pmd_same(pmd, READ_ONCE(*pmdp))) {
        spin_unlock(*lock);
        goto fail;
    }
    return ptep;
fail:
    rcu_read_unlock();
    return NULL;
}
static void unlock_pte(spinlock_t *lock)
{
    spin_unlock(lock);
    rcu_read_unlock();
}

/* Change only UXN, preserving live AF/dirty bits. A changed identity or
 * permission is never overwritten with a stale PTE. Called with state_lock. */
static int set_armed(struct mm_struct *mm, struct pte_page *p, bool armed)
{
    spinlock_t *lock;
    pte_t *ptep, now;
    pteval_t mutable = PTE_AF | PTE_DIRTY;
    if (!p->valid) return -ESTALE;
    ptep = lock_pte(mm, p->address, &lock);
    if (!ptep) return -ESTALE;
    /* Hardware AF/dirty updates do not take the leaf lock. Retry instead of
     * overwriting an update that arrives between the load and store. */
    for (;;) {
        pteval_t value;
        now = READ_ONCE(*ptep);
        if (!pte_present(now) ||
            !dfm_pte_value_matches(pte_val(now), pte_val(p->original),
                                   PTE_UXN, mutable, p->armed)) {
            unlock_pte(lock);
            return -ESTALE;
        }
        value = armed ? pte_val(now) | PTE_UXN : pte_val(now) & ~PTE_UXN;
        if (cmpxchg_relaxed(&pte_val(*ptep), pte_val(now), value) == pte_val(now))
            break;
    }
    invalidate_tlb(p->address);
    p->armed = armed;
    unlock_pte(lock);
    return 0;
}

static void disarm_page(struct pte_session *s, unsigned int index, int error)
{
    struct pte_page *p = &s->page[index];
    if (p->valid && p->armed) set_armed(s->mm, p, false);
    p->valid = false;
    p->armed = false;
    s->snapshot.flags |= DFM_PTE_INVALIDATED;
    s->snapshot.last_error = error;
}

static void disable_local_step(struct pt_regs *regs)
{
    clear_thread_flag(TIF_SINGLESTEP);
    regs->pstate &= ~DBG_SPSR_SS;
    /* MDSCR_EL1.SS is bit zero on ARM64. The old DBG_MDSCR_SS alias was
     * removed with the legacy hook API; do not alter MDE/KDE ownership. */
    write_sysreg(read_sysreg(mdscr_el1) & ~1UL, mdscr_el1);
    isb();
}

static void finish_step(struct pte_session *s, unsigned int index,
                         struct pt_regs *regs)
{
    struct pte_step *step = &s->steps[index];
    struct pte_page *p = &s->page[step->page];
    struct task_struct *task = step->task;
    disable_local_step(regs);
    step->task = NULL;
    if (p->users) --p->users;
    if (s->active && p->valid && !p->users) {
        int rc = set_armed(s->mm, p, true);
        if (rc) disarm_page(s, step->page, rc);
        else ++s->snapshot.rearms;
    }
    put_task_struct(task);
}

static int step_handler(struct pt_regs *regs, pte_step_esr_t esr)
{
    unsigned long flags;
    unsigned int i;
    int result = DBG_HOOK_ERROR;
    (void)esr;
    spin_lock_irqsave(&state_lock, flags);
    if (session) for (i = 0; i < DFM_PTE_MAX_STEPPERS; ++i) {
        if (session->steps[i].task != current) continue;
        finish_step(session, i, regs);
        result = DBG_HOOK_HANDLED;
        break;
    }
    spin_unlock_irqrestore(&state_lock, flags);
    return result;
}
/* PTE_STEP_ROUTER_BEGIN: also exercised by the host production-path model. */
#ifdef DFM_PTE_USER_STEP_HOOK
static struct step_hook step_hook = { .fn = step_handler };
#else
static int softstep_pre(struct kprobe *probe, struct pt_regs *entry)
{
    unsigned long esr = entry->regs[0];
    struct pt_regs *regs = (void *)entry->regs[1];
    (void)probe;
    /* This is the exact AAPCS entry of void do_el0_softstep(esr, regs),
     * before its stack/PAC/SCS prologue. Never dereference an unrelated
     * argument or consume another task/debugger's exception. */
    if (regs != task_pt_regs(current) || !user_mode(regs) ||
        compat_user_mode(regs) || ESR_ELx_EC(esr) != ESR_ELx_EC_SOFTSTP_LOW ||
        step_handler(regs, esr) != DBG_HOOK_HANDLED)
        return 0;
    /* Kprobes owns the instruction slot and synchronization. Returning
     * nonzero skips only this already-consumed void call; no custom text
     * trampoline or kernel C call from a redirected PC is involved. */
    instruction_pointer_set(entry, entry->regs[30]);
    return 1;
}
NOKPROBE_SYMBOL(softstep_pre);
#endif
/* PTE_STEP_ROUTER_END */

/* Called in the user-fault task context, before taking state_lock/irqsave.
 * The signal helper first synchronizes live CPU registers, then converts a
 * saved SVE/SME register image to its low-128-bit FPSIMD view. Copying only
 * thread.uw.fpsimd_state without that helper could publish stale registers.
 * No user instruction runs between synchronization and the copy. */
static __nocfi int capture_fpsimd(struct user_fpsimd_state *out)
{
    memset(out, 0, sizeof(*out));
    if (!preserve_user_fpsimd || !system_supports_fpsimd()) return -EOPNOTSUPP;
    preserve_user_fpsimd();
    if (sync_user_fpsimd) sync_user_fpsimd(current);
    memcpy(out, &current->thread.uw.fpsimd_state, sizeof(*out));
    return 0;
}

static void record_hit(struct pte_session *s, unsigned long pc,
                        struct pt_regs *regs, const struct user_fpsimd_state *fp,
                        int fp_status)
{
    struct dfm_pte_snapshot *out = &s->snapshot;
    struct dfm_pte_record *r;
    unsigned int i;
    for (i = 0; i < out->point_count; ++i)
        if (out->addresses[i] == pc) break;
    if (i == out->point_count) return;
    r = &out->records[out->total_hits % DFM_PTE_MAX_RECORDS];
    memset(r, 0, sizeof(*r));
    r->sequence = ++out->total_hits;
    r->timestamp_ns = ktime_get_ns();
    r->address = pc; r->pc = regs->pc;
    r->sp = regs->sp; r->pstate = regs->pstate;
    memcpy(r->x, regs->regs, sizeof(r->x));
    r->pid = task_tgid_vnr(current);
    r->tid = task_pid_vnr(current);
    r->fp_status = fp_status;
    if (!fp_status) {
        memcpy(r->q, fp->vregs, sizeof(r->q));
        r->fpcr = fp->fpcr;
        r->fpsr = fp->fpsr;
    }
    if (out->record_count < DFM_PTE_MAX_RECORDS) ++out->record_count;
    else ++out->dropped;
}

/* Retry the same PC at EL0. Other faults retain the original kernel path. */
static bool handle_fault(unsigned long far, unsigned long esr,
                          struct pt_regs *regs)
{
    struct pte_session *s;
    struct pte_page *p = NULL;
    unsigned int i, index = 0, free_step = DFM_PTE_MAX_STEPPERS;
    unsigned long flags, pc = untagged_addr(regs->pc);
    u32 instruction;
    struct user_fpsimd_state fp;
    u64 fp_generation = 0;
    int fp_status = -EOPNOTSUPP;
    bool need_fp = false;
    bool handled = false;
    if (!user_mode(regs) || compat_user_mode(regs) ||
        ESR_ELx_EC(esr) != ESR_ELx_EC_IABT_LOW ||
        (esr & ESR_ELx_FSC) != 0x0f || untagged_addr(far) != pc)
        return false;
    /* Only requested PCs need vector synchronization. Do not run the helper
     * under the PTE/state spinlock: it manages the kernel's FPSIMD context
     * exclusion itself. Teardown may run here; revalidate the generation below. */
    spin_lock_irqsave(&state_lock, flags);
    s = session;
    if (s && s->active && s->mm == current->mm)
        for (i = 0; i < s->snapshot.point_count; ++i)
            if (s->snapshot.addresses[i] == pc) {
                need_fp = true;
                fp_generation = s->snapshot.generation;
                break;
            }
    spin_unlock_irqrestore(&state_lock, flags);
    if (need_fp) fp_status = capture_fpsimd(&fp);
    spin_lock_irqsave(&state_lock, flags);
    s = session;
    if (!s || !s->active || s->mm != current->mm) goto out;
    for (i = 0; i < s->pages; ++i)
        if (s->page[i].valid && s->page[i].address == (pc & PAGE_MASK)) {
            p = &s->page[i]; index = i; break;
        }
    if (!p) goto out;
    ++s->snapshot.faults;
    if (!p->armed && p->users) { invalidate_tlb(pc); handled = true; goto out; }
    if (!p->armed) goto out;
    for (i = 0; i < DFM_PTE_MAX_STEPPERS; ++i) {
        if (s->steps[i].task == current) goto conflict;
        if (!s->steps[i].task && free_step == DFM_PTE_MAX_STEPPERS) free_step = i;
    }
    if (test_thread_flag(TIF_SINGLESTEP) || READ_ONCE(current->ptrace) ||
        free_step == DFM_PTE_MAX_STEPPERS) goto conflict;
    instruction = READ_ONCE(*(u32 *)((char *)page_address(p->page) +
                                   offset_in_page(pc)));
    if (!dfm_pte_instruction_safe(instruction)) {
        disarm_page(s, index, -EOPNOTSUPP);
        handled = true;
        goto out;
    }
    if (set_armed(s->mm, p, false)) {
        disarm_page(s, index, -ESTALE);
        goto out;
    }
    if (need_fp && fp_generation != s->snapshot.generation) fp_status = -ESTALE;
    record_hit(s, pc, regs, &fp, fp_status);
    get_task_struct(current);
    s->steps[free_step].task = current;
    s->steps[free_step].page = index;
    ++p->users;
    set_thread_flag(TIF_SINGLESTEP);
    regs->pstate |= DBG_SPSR_SS;
    handled = true;
    goto out;
conflict:
    disarm_page(s, index, -EBUSY);
    handled = true;
out:
    spin_unlock_irqrestore(&state_lock, flags);
    return handled;
}

#define FAULT_WRAPPER(n) \
static __nocfi int fault_##n(unsigned long far, pte_fault_esr_t esr, \
                             struct pt_regs *regs) \
{ \
    int index = srcu_read_lock(&fault_srcu); \
    int result = handle_fault(far, esr, regs) ? 0 : original_fault[n](far, esr, regs); \
    srcu_read_unlock(&fault_srcu, index); \
    return result; \
}
FAULT_WRAPPER(0)
FAULT_WRAPPER(1)
FAULT_WRAPPER(2)
static typeof(original_fault[0]) fault_wrappers[] = { fault_0, fault_1, fault_2 };

static void cancel_current(struct pt_regs *regs)
{
    unsigned long flags;
    unsigned int i;
    spin_lock_irqsave(&state_lock, flags);
    if (session) for (i = 0; i < DFM_PTE_MAX_STEPPERS; ++i)
        if (session->steps[i].task == current) {
            finish_step(session, i, regs);
            break;
        }
    spin_unlock_irqrestore(&state_lock, flags);
}
static void sys_enter(void *unused, struct pt_regs *regs, long id)
{
    (void)unused; (void)id;
    cancel_current(regs);
}
static void signal_deliver(void *unused, int sig, struct kernel_siginfo *info,
                           struct k_sigaction *action)
{
    (void)unused; (void)sig; (void)info; (void)action;
    cancel_current(task_pt_regs(current));
}
#ifdef DFM_PTE_EXIT_GROUP_DEAD
static void task_exit(void *unused, struct task_struct *task, bool group_dead)
{
    (void)unused; (void)group_dead;
#else
static void task_exit(void *unused, struct task_struct *task)
{
    (void)unused;
#endif
    if (task == current) cancel_current(task_pt_regs(task));
}
static void task_fork(void *unused, struct task_struct *parent,
                       struct task_struct *child)
{
    struct pte_session *s;
    unsigned long flags;
    unsigned int i;
    (void)unused;
    /* Before wake_up_new_task: copied mms must not inherit unmanaged UXN. */
    spin_lock_irqsave(&state_lock, flags);
    s = session;
    if (s && parent->mm == s->mm && child->mm && child->mm != s->mm) {
        for (i = 0; i < s->pages; ++i) {
            struct pte_page copy = s->page[i];
            if (!copy.valid || !copy.armed) continue;
            set_armed(child->mm, &copy, false);
        }
    }
    spin_unlock_irqrestore(&state_lock, flags);
}

static int invalidate_start(struct mmu_notifier *notifier,
                             const struct mmu_notifier_range *range)
{
    struct pte_session *s = container_of(notifier, struct pte_session, notifier);
    unsigned long flags;
    unsigned int i;
    spin_lock_irqsave(&state_lock, flags);
    for (i = 0; i < s->pages; ++i)
        if (s->page[i].valid && s->page[i].address < range->end &&
            s->page[i].address + PAGE_SIZE > range->start)
            disarm_page(s, i, -ESTALE);
    spin_unlock_irqrestore(&state_lock, flags);
    return 0;
}
static void mm_release(struct mmu_notifier *notifier, struct mm_struct *mm)
{
    struct pte_session *s = container_of(notifier, struct pte_session, notifier);
    unsigned long flags;
    unsigned int i;
    (void)mm;
    spin_lock_irqsave(&state_lock, flags);
    for (i = 0; i < s->pages; ++i)
        if (s->page[i].valid) disarm_page(s, i, -ESRCH);
    s->active = false;
    spin_unlock_irqrestore(&state_lock, flags);
}
static const struct mmu_notifier_ops notifier_ops = {
    .invalidate_range_start = invalidate_start, .release = mm_release,
};

/* stop_machine prevents return to EL0 while saved owned step state is cleared.
 * EL0 exception entry already clears MDSCR.SS; do not change the stopper's
 * per-CPU debug controls, which may belong to an unrelated kernel debugger. */
static int cancel_steps_cpu(void *data)
{
    struct pte_session *s = data;
    unsigned int i;
    /* The callback runs as a stopper thread, not as the interrupted task.
     * All other CPUs are parked, so one CPU can edit saved task state. */
    if (smp_processor_id() == cpumask_first(cpu_online_mask))
      for (i = 0; i < DFM_PTE_MAX_STEPPERS; ++i) {
        struct task_struct *task = s->steps[i].task;
        if (!task) continue;
        clear_tsk_thread_flag(task, TIF_SINGLESTEP);
        task_pt_regs(task)->pstate &= ~DBG_SPSR_SS;
    }
    return 0;
}

static void stop_session(void)
{
    struct pte_session *s = session;
    unsigned int i;
    unsigned long flags;
    if (!s) return;
    spin_lock_irqsave(&state_lock, flags);
    s->active = false;
    spin_unlock_irqrestore(&state_lock, flags);
    if (s->registered) mmu_notifier_unregister(&s->notifier, s->mm);
    spin_lock_irqsave(&state_lock, flags);
    for (i = 0; i < s->pages; ++i)
        if (s->page[i].valid) disarm_page(s, i, 0);
    spin_unlock_irqrestore(&state_lock, flags);
    for (;;) {
        int rc = stop_machine(cancel_steps_cpu, s, cpu_online_mask);
        if (!rc) break;
        /* Final file release cannot reject teardown. Keep references and the
         * step hook alive until no task can return with an orphaned step. */
        pr_err_ratelimited("dfm: PTE step teardown failed %d; retrying safely\n", rc);
        msleep(20);
    }
    spin_lock_irqsave(&state_lock, flags);
    session = NULL;
    spin_unlock_irqrestore(&state_lock, flags);
    for (i = 0; i < DFM_PTE_MAX_STEPPERS; ++i) if (s->steps[i].task) {
        struct task_struct *task = s->steps[i].task;
        put_task_struct(task);
    }
    for (i = 0; i < s->pages; ++i)
        if (s->page[i].page) put_page(s->page[i].page);
    mmdrop(s->mm);
    kvfree(s);
}

static __nocfi bool may_access(struct task_struct *task)
{
    return target_access(task, PTRACE_MODE_ATTACH_REALCREDS);
}
/* PTE_STEP_REGISTRATION_BEGIN */
static __nocfi int step_register_call(bool add)
{
#ifdef DFM_PTE_USER_STEP_HOOK
    if (add) register_step(&step_hook);
    else unregister_step(&step_hook);
    return 0;
#else
    if (add) {
        int rc;
        /* unregister_kprobe drains handlers before this object is reused. */
        memset(&softstep_probe, 0, sizeof(softstep_probe));
        softstep_probe.addr = (kprobe_opcode_t *)softstep_address;
        softstep_probe.pre_handler = softstep_pre;
        rc = register_kprobe(&softstep_probe);
        if (rc) return rc;
        if (softstep_probe.addr != (kprobe_opcode_t *)softstep_address) {
            unregister_kprobe(&softstep_probe);
            return -EOPNOTSUPP;
        }
        return 0;
    }
    unregister_kprobe(&softstep_probe);
    return 0;
#endif
}
/* PTE_STEP_REGISTRATION_END */

/* Keep hooks until module exit: no session clear frees callback text. */
static int resolve_backend(void)
{
    unsigned int i;
    if (hooks_ready) return 0;
    preserve_user_fpsimd = (void *)symbol("fpsimd_signal_preserve_current_state");
    sync_user_fpsimd = NULL;
    if (!preserve_user_fpsimd) {
        /* Newer kernels split signal preservation into these two helpers.
         * Never use plain preserve alone: an SVE task's FPSIMD view may be old. */
        preserve_user_fpsimd = (void *)symbol("fpsimd_preserve_current_state");
        sync_user_fpsimd = (void *)symbol("fpsimd_sync_from_effective_state");
        if (!preserve_user_fpsimd || !sync_user_fpsimd) {
            preserve_user_fpsimd = NULL;
            sync_user_fpsimd = NULL;
        }
    }
    fault_table = (void *)symbol("fault_info");
#ifdef DFM_PTE_USER_STEP_HOOK
    register_step = (void *)symbol("register_user_step_hook");
    unregister_step = (void *)symbol("unregister_user_step_hook");
    if (!register_step || !unregister_step) return -EOPNOTSUPP;
#else
    /* Probe the real function entry, never a legacy CFI jump-table thunk. */
    softstep_address = kallsyms_lookup_name("do_el0_softstep");
    if (!softstep_address) return -EOPNOTSUPP;
#endif
    target_access = (void *)symbol("ptrace_may_access");
    fork_trace = (void *)symbol("__tracepoint_sched_process_fork");
    exit_trace = (void *)symbol("__tracepoint_sched_process_exit");
    sys_trace = (void *)symbol("__tracepoint_sys_enter");
    signal_trace = (void *)symbol("__tracepoint_signal_deliver");
    if (!fault_table || !target_access ||
        !fork_trace || !exit_trace || !sys_trace || !signal_trace) return -EOPNOTSUPP;
    for (i = 0; i < 3; ++i) {
        struct pte_fault_info *f = &fault_table[13 + i];
        if (!f->fn || f->sig != SIGSEGV || f->code != SEGV_ACCERR ||
            !f->name || !strstr(f->name, "permission fault")) return -EOPNOTSUPP;
        original_fault[i] = f->fn;
    }
    return 0;
}

static int ensure_hooks(void)
{
    unsigned int i;
    int rc;
    if (hooks_ready) return 0;
    rc = resolve_backend();
    if (rc) return rc;
    rc = step_register_call(true);
    if (rc) return rc;
    step_registered = true;
    rc = tracepoint_probe_register(fork_trace, task_fork, NULL);
    if (rc) return rc;
    fork_registered = true;
    /* Keep runtime-resolved tracepoints, while having the kernel headers
     * reject a CFI-incompatible callback on any supported/backported ABI. */
    check_trace_callback_type_sched_process_exit(task_exit);
    check_trace_callback_type_sched_process_fork(task_fork);
    rc = tracepoint_probe_register(exit_trace, task_exit, NULL);
    if (rc) return rc;
    exit_registered = true;
    rc = tracepoint_probe_register(sys_trace, sys_enter, NULL);
    if (rc) return rc;
    sys_registered = true;
    rc = tracepoint_probe_register(signal_trace, signal_deliver, NULL);
    if (rc) return rc;
    signal_registered = true;
    for (i = 0; i < 3; ++i) {
        rc = dfm_patch_pointer(&fault_table[13 + i].fn, fault_wrappers[i], original_fault[i]);
        if (rc) return rc;
        fault_patched[i] = true;
    }
    hooks_ready = true;
    return 0;
}

static void remove_hooks(void)
{
    unsigned int i;
    for (i = 0; i < 3; ++i) if (fault_patched[i]) {
        int rc;
        do {
            rc = dfm_patch_pointer(&fault_table[13 + i].fn, original_fault[i], fault_wrappers[i]);
            if (rc && READ_ONCE(fault_table[13 + i].fn) == original_fault[i]) rc = 0;
            if (rc) {
                pr_err_ratelimited("dfm: PTE fault hook restore failed %d; waiting for detach\n", rc);
                msleep(20);
            }
        } while (rc);
        fault_patched[i] = false;
    }
    synchronize_rcu_tasks();
    synchronize_srcu(&fault_srcu);
    synchronize_rcu_tasks();
    if (fork_registered) tracepoint_probe_unregister(fork_trace, task_fork, NULL);
    if (exit_registered) tracepoint_probe_unregister(exit_trace, task_exit, NULL);
    if (sys_registered) tracepoint_probe_unregister(sys_trace, sys_enter, NULL);
    if (signal_registered) tracepoint_probe_unregister(signal_trace, signal_deliver, NULL);
    tracepoint_synchronize_unregister();
    if (step_registered) step_register_call(false);
    fork_registered = exit_registered = sys_registered = signal_registered = false;
    step_registered = hooks_ready = false;
    synchronize_rcu_tasks();
}

long dfm_pte_info(void __user *arg)
{
    struct dfm_pte_info_req req;
    if (copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
    if (req.abi_version != DFM_PTE_ABI_VERSION || req.reserved) return -EINVAL;
    memset(&req, 0, sizeof(req));
    req.abi_version = DFM_PTE_ABI_VERSION;
    req.page_size = PAGE_SIZE; req.max_points = DFM_PTE_MAX_POINTS;
    req.max_records = DFM_PTE_MAX_RECORDS; req.max_steppers = DFM_PTE_MAX_STEPPERS;
    mutex_lock(&control_lock);
    backend_error = resolve_backend();
    req.flags = DFM_PTE_INFO_STEP_WINDOW | (!backend_error ? DFM_PTE_INFO_AVAILABLE : 0);
    if (preserve_user_fpsimd && system_supports_fpsimd()) req.flags |= DFM_PTE_INFO_FPSIMD;
    req.backend_errno = backend_error;
    mutex_unlock(&control_lock);
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

long dfm_pte_set(struct file *owner, void __user *arg)
{
    struct dfm_pte_set_req req;
    struct task_struct *task;
    struct mm_struct *mm;
    struct pte_session *s;
    unsigned int i, j;
    unsigned long flags;
    int rc;
    if (copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
    rc = dfm_pte_validate(&req, TASK_SIZE);
    if (rc) return rc;
    if (!ns_capable(&init_user_ns, CAP_SYS_PTRACE)) return -EPERM;
    mutex_lock(&control_lock);
    if (session) { rc = session->owner == owner ? -EALREADY : -EBUSY; goto unlock; }
    rc = ensure_hooks();
    backend_error = rc;
    if (rc) { remove_hooks(); goto unlock; }
    rcu_read_lock();
    task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) { rc = -ESRCH; goto unlock; }
    if (!may_access(task)) { rc = -EACCES; goto put_task; }
#ifdef CONFIG_COMPAT
    if (test_tsk_thread_flag(task, TIF_32BIT)) {
        rc = -EOPNOTSUPP; goto put_task;
    }
#endif
    if (READ_ONCE(task->ptrace) || test_tsk_thread_flag(task, TIF_SINGLESTEP)) {
        rc = -EBUSY; goto put_task;
    }
    mm = get_task_mm(task);
    if (!mm) { rc = -ESRCH; goto put_task; }
    s = kvzalloc(sizeof(*s), GFP_KERNEL);
    if (!s) { rc = -ENOMEM; goto put_mm; }
    s->owner = owner; s->mm = mm; mmgrab(mm);
    s->notifier.ops = &notifier_ops;
    rc = mmu_notifier_register(&s->notifier, mm);
    if (rc) { mmdrop(mm); kvfree(s); goto put_mm; }
    s->registered = true;
    s->snapshot.abi_version = DFM_PTE_ABI_VERSION;
    s->snapshot.pid = req.pid; s->snapshot.point_count = req.point_count;
    s->snapshot.generation = ++generation;
    memcpy(s->snapshot.addresses, req.addresses, sizeof(req.addresses));
    mmap_write_lock(mm);
    spin_lock_irqsave(&state_lock, flags);
    session = s;
    for (i = 0; i < req.point_count; ++i) {
        struct vm_area_struct *vma;
        struct pte_page *p;
        pte_t *ptep, entry;
        spinlock_t *ptl;
        unsigned long address = req.addresses[i] & PAGE_MASK;
        for (j = 0; j < s->pages; ++j)
            if (s->page[j].address == address) break;
        if (j < s->pages) continue;
        vma = find_vma(mm, address);
        if (!vma || address < vma->vm_start ||
            !(vma->vm_flags & VM_EXEC) || !(vma->vm_flags & VM_MAYWRITE) ||
            (vma->vm_flags & (VM_WRITE | VM_SHARED | VM_IO | VM_PFNMAP | VM_MIXEDMAP | VM_HUGETLB))) {
            rc = -EOPNOTSUPP; break;
        }
        ptep = lock_pte(mm, address, &ptl);
        if (!ptep) { rc = -EFAULT; break; }
        entry = READ_ONCE(*ptep);
        if (!pte_valid(entry) || !(pte_val(entry) & PTE_USER) || !pte_user_exec(entry) ||
            pte_cont(entry) || !pfn_valid(pte_pfn(entry)) ||
            PageCompound(pfn_to_page(pte_pfn(entry)))) {
            unlock_pte(ptl); rc = -EOPNOTSUPP; break;
        }
        p = &s->page[s->pages++];
        p->address = address; p->original = entry;
        p->page = pfn_to_page(pte_pfn(entry));
        get_page(p->page);
        p->valid = true;
        unlock_pte(ptl);
        rc = set_armed(mm, p, true);
        if (rc) break;
    }
    if (!rc) s->active = true;
    else for (i = 0; i < s->pages; ++i)
        if (s->page[i].valid) disarm_page(s, i, rc);
    spin_unlock_irqrestore(&state_lock, flags);
    mmap_write_unlock(mm);
    if (rc) stop_session();
put_mm:
    mmput(mm);
put_task:
    put_task_struct(task);
unlock:
    mutex_unlock(&control_lock);
    return rc;
}

long dfm_pte_read(struct file *owner, void __user *arg)
{
    struct dfm_pte_read_req req;
    struct dfm_pte_snapshot *out;
    unsigned long flags;
    unsigned int i, start;
    int rc = 0;
    if (copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
    if (req.abi_version != DFM_PTE_ABI_VERSION || req.reserved || req.reserved2) return -EINVAL;
    req.out_size = sizeof(*out);
    if (copy_to_user(arg, &req, sizeof(req))) return -EFAULT;
    if (!req.buf || req.buf_size < sizeof(*out)) return -ENOSPC;
    out = kvzalloc(sizeof(*out), GFP_KERNEL);
    if (!out) return -ENOMEM;
    mutex_lock(&control_lock);
    spin_lock_irqsave(&state_lock, flags);
    if (!session) rc = -ENOENT;
    else if (session->owner != owner) rc = -EACCES;
    else {
        *out = session->snapshot;
        out->flags |= session->active ? DFM_PTE_ACTIVE : 0;
        out->page_count = session->pages;
        for (i = 0; i < session->pages; ++i) {
            if (session->page[i].valid && session->page[i].armed) out->armed_pages |= 1U << i;
            if (session->page[i].valid && session->page[i].users) out->open_pages |= 1U << i;
        }
        start = out->total_hits > DFM_PTE_MAX_RECORDS ?
            out->total_hits % DFM_PTE_MAX_RECORDS : 0;
        for (i = 0; i < out->record_count; ++i)
            out->records[i] = session->snapshot.records[(start + i) % DFM_PTE_MAX_RECORDS];
    }
    spin_unlock_irqrestore(&state_lock, flags);
    mutex_unlock(&control_lock);
    if (!rc && copy_to_user(u64_to_user_ptr(req.buf), out, sizeof(*out))) rc = -EFAULT;
    kvfree(out);
    return rc;
}

long dfm_pte_clear(struct file *owner)
{
    int rc = 0;
    mutex_lock(&control_lock);
    if (session && session->owner != owner) rc = -EACCES;
    else stop_session();
    mutex_unlock(&control_lock);
    return rc;
}
void dfm_pte_release(struct file *owner) { dfm_pte_clear(owner); }
void dfm_pte_exit(void)
{
    mutex_lock(&control_lock);
    stop_session();
    remove_hooks();
    mutex_unlock(&control_lock);
}
#else
long dfm_pte_info(void __user *arg)
{
    struct dfm_pte_info_req r;
    if (copy_from_user(&r, arg, sizeof(r))) return -EFAULT;
    if (r.abi_version != DFM_PTE_ABI_VERSION || r.reserved) return -EINVAL;
    memset(&r, 0, sizeof(r));
    r.abi_version = DFM_PTE_ABI_VERSION; r.page_size = PAGE_SIZE;
    r.backend_errno = -EOPNOTSUPP;
    return copy_to_user(arg, &r, sizeof(r)) ? -EFAULT : 0;
}
long dfm_pte_set(struct file *owner, void __user *arg) { return -EOPNOTSUPP; }
long dfm_pte_read(struct file *owner, void __user *arg) { return -EOPNOTSUPP; }
long dfm_pte_clear(struct file *owner) { return -EOPNOTSUPP; }
void dfm_pte_release(struct file *owner) {}
void dfm_pte_exit(void) {}
#endif
