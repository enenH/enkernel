/* SPDX-License-Identifier: GPL-2.0-only */
/* Read-only native futex continuations. Matching uses the Linux syscall ABI,
 * the pinned mm and the kernel's actual futex sleep site, never application
 * instruction addresses, thread names, mutex encodings or queue layouts. */
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <asm/thread_info.h>
#include <linux/atomic.h>
#include <linux/file.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include "abi.h"
#include "futex.h"

struct futex_context {
    struct list_head list;
    struct file *owner;
    struct task_struct *task;
    struct mm_struct *mm;
    u64 identity;
};
static LIST_HEAD(contexts);
static DEFINE_MUTEX(contexts_lock);
static atomic64_t next_context_id = ATOMIC64_INIT(0);
static unsigned int context_count;

static bool context_alive(struct futex_context *context)
{
    return context && context->task && context->mm &&
        pid_alive(context->task) && !READ_ONCE(context->task->exit_state) &&
        READ_ONCE(context->task->mm) == context->mm;
}

static void free_context(struct futex_context *context)
{
    list_del(&context->list);
    mmput(context->mm);
    put_task_struct(context->task);
    kfree(context);
    context_count--;
}

static struct futex_context *find_context(struct file *owner)
{
    struct futex_context *context;
    list_for_each_entry(context, &contexts, list)
        if (context->owner == owner) return context;
    return NULL;
}

/* contexts_lock pins this mm across every discovery and validation ioctl.
 * No task/mm address is exported. Rebinding to an exec or another process
 * retires the old context id, even if numeric PIDs are reused. */
static struct futex_context *open_context(struct file *owner, pid_t pid)
{
    struct futex_context *context = find_context(owner);
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *target_pid = find_get_pid(pid);
    task = get_pid_task(target_pid, PIDTYPE_PID);
    put_pid(target_pid);
    if (!task) return ERR_PTR(-ESRCH);
    if (task_tgid_vnr(task) != pid) {
        put_task_struct(task);
        return ERR_PTR(-EINVAL);
    }
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return ERR_PTR(-ESRCH);
    }
    if (context && context_alive(context) && context->task == task && context->mm == mm) {
        mmput(mm);
        put_task_struct(task);
        return context;
    }
    if (context) free_context(context);
    if (context_count >= 64) {
        mmput(mm);
        put_task_struct(task);
        return ERR_PTR(-EMFILE);
    }
    context = kzalloc(sizeof(*context), GFP_KERNEL);
    if (!context) {
        mmput(mm);
        put_task_struct(task);
        return ERR_PTR(-ENOMEM);
    }
    context->owner = owner;
    context->task = task;
    context->mm = mm;
    context->identity = atomic64_inc_return(&next_context_id);
    if (!context->identity) context->identity = atomic64_inc_return(&next_context_id);
    list_add(&context->list, &contexts);
    context_count++;
    return context;
}

void dfm_futex_release(struct file *owner)
{
    struct futex_context *context;
    mutex_lock(&contexts_lock);
    context = find_context(owner);
    if (context) free_context(context);
    mutex_unlock(&contexts_lock);
}

static unsigned long futex_symbol(const char *name)
{
    char cfi[KSYM_NAME_LEN];
    unsigned long address;
    if (snprintf(cfi, sizeof(cfi), "%s.cfi_jt", name) >= sizeof(cfi)) return 0;
    address = kallsyms_lookup_name(cfi);
    return address ? address : kallsyms_lookup_name(name);
}

#define KD_FUTEX_TASK_LIMIT 512U
#define KD_FUTEX_OUTPUT_LIMIT 64U
#define KD_AARCH64_NR_FUTEX 98U

static DEFINE_MUTEX(futex_symbols_lock);
static typeof(&wait_task_inactive) wait_inactive;
/* Some Android kernels retain this function without exporting it to modules.
 * Keep the exact header-declared signature and the normal pin/release pair. */
static typeof(&put_task_stack) release_stack;
static unsigned long futex_sleep_start,futex_sleep_size;

static int resolve_symbols(void)
{
    int (*symbol_size)(unsigned long,unsigned long *,unsigned long *);
    typeof(&wait_task_inactive) inactive;
    typeof(&put_task_stack) put_stack;
    unsigned long start,size=0,offset=0;
    int error=0;
    if(smp_load_acquire(&futex_sleep_size))return 0;
    mutex_lock(&futex_symbols_lock);
    if(futex_sleep_size)goto out;
    inactive=(void *)futex_symbol("wait_task_inactive");
    put_stack=(void *)futex_symbol("put_task_stack");
    symbol_size=(void *)futex_symbol("kallsyms_lookup_size_offset");
    start=kallsyms_lookup_name("futex_wait_queue");
    if(!start)start=kallsyms_lookup_name("futex_wait_queue_me");
    if(!start)start=kallsyms_lookup_name("futex_do_wait");
    if(!inactive||!put_stack||!symbol_size||!start||!symbol_size(start,&size,&offset)||
       offset||!size){error=-EOPNOTSUPP;goto out;}
    wait_inactive=inactive;release_stack=put_stack;futex_sleep_start=start;
    smp_store_release(&futex_sleep_size,size);
out:
    mutex_unlock(&futex_symbols_lock);return error;
}

static u64 futex_address(u64 address)
{
    return (u64)untagged_addr((unsigned long)address);
}

static bool same_process(struct futex_context *context,struct task_struct *task)
{
    return context_alive(context)&&pid_alive(task)&&
           !READ_ONCE(task->exit_state)&&READ_ONCE(task->mm)==context->mm&&
           task_tgid_nr(task)==task_tgid_nr(context->task);
}

static bool wait_matches(const unsigned long args[6],u64 address,u32 bitset)
{
    u32 operation=(u32)args[1],command=operation&127U;
    if(!(operation&DFM_FUTEX_PRIVATE_FLAG)||(operation&~0x1ffU)||
       (command!=DFM_FUTEX_WAIT&&command!=DFM_FUTEX_WAIT_BITSET)||
       futex_address(args[0])!=address)
        return false;
    return command==DFM_FUTEX_WAIT||((u32)args[5]&bitset)!=0;
}

/* A successful sample is bracketed by identical wait_task_inactive cookies.
 * try_get_task_stack protects the pt_regs storage even if the task exits.
 * Merely seeing nr=98 is insufficient: the task must be sleeping inside the
 * actual kernel futex wait-queue function, not in a fault or exit trace stop.
 * Return 1 for a sample, 0 for a non-matching task, negative for a matching
 * candidate whose state could not be proved. */
static int sample_waiter(struct futex_context *context,struct task_struct *task,
                         u64 address,u32 bitset,struct dfm_futex_thread *out)
{
    struct pt_regs regs;
    unsigned long args[6],before,after,wchan;
    unsigned int state;
    int result=0;
    memset(out,0,sizeof(*out));
    if(!same_process(context,task)||task==current)return 0;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    state=READ_ONCE(task->__state);
#else
    state=READ_ONCE(task->state);
#endif
    if(!(state&TASK_INTERRUPTIBLE)||READ_ONCE(task->on_cpu)||
       READ_ONCE(task->on_rq))return 0;
    if(!try_get_task_stack(task))return 0;
    /* This preliminary copy is only a filter. It is never returned as a
     * continuation until the subsequent stable interval has been checked. */
    memcpy(&regs,task_pt_regs(task),sizeof(regs));
    syscall_get_arguments(task,&regs,args);
    if(syscall_get_nr(task,&regs)!=KD_AARCH64_NR_FUTEX||
       !wait_matches(args,address,bitset))goto out;
    before=wait_inactive(task,state);
    if(!before){result=-EAGAIN;goto out;}
    wchan=get_wchan(task);
    if(wchan<futex_sleep_start||wchan-futex_sleep_start>=futex_sleep_size)
        goto out;
    memcpy(&regs,task_pt_regs(task),sizeof(regs));
    syscall_get_arguments(task,&regs,args);
    if(syscall_get_nr(task,&regs)!=KD_AARCH64_NR_FUTEX||
       !wait_matches(args,address,bitset)||!same_process(context,task)){
        result=-EAGAIN;goto out;
    }
    if(!user_mode(&regs)||compat_user_mode(&regs)
#ifdef TIF_SVE
       ||test_tsk_thread_flag(task,TIF_SVE)
#endif
#ifdef TIF_SME
       ||test_tsk_thread_flag(task,TIF_SME)
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
       ||READ_ONCE(task->thread.fp_type)!=FP_STATE_FPSIMD
#endif
#ifdef CONFIG_ARM64_SME
       ||READ_ONCE(task->thread.svcr)||READ_ONCE(task->thread.tpidr2_el0)
#endif
       ){
        result=-EOPNOTSUPP;goto out;
    }
    out->pid=task_tgid_vnr(task);out->tid=task_pid_vnr(task);
    out->identity=READ_ONCE(task->start_boottime);
    out->sequence=before;out->context_id=context->identity;
    memcpy(out->x,regs.regs,sizeof(out->x));
    out->sp=regs.sp;out->pc=regs.pc;out->pstate=(u32)regs.pstate;
    out->tls=READ_ONCE(*task_user_tls(task));
    /* The native (non-compat) ARM64 tls_thread_switch ABI writes zero to
     * TPIDRRO_EL0. tp2_value/NT_ARM_TLS[1] must not be mistaken for it. */
    out->tpidrro=0;
    memcpy(out->v,task->thread.uw.fpsimd_state.vregs,sizeof(out->v));
    out->fpcr=READ_ONCE(task->thread.uw.fpsimd_state.fpcr);
    out->fpsr=READ_ONCE(task->thread.uw.fpsimd_state.fpsr);
    out->syscall_nr=KD_AARCH64_NR_FUTEX;
    memcpy(out->args,args,sizeof(out->args));
    after=wait_inactive(task,state);
    if(after!=before||!same_process(context,task)||
       out->identity!=READ_ONCE(task->start_boottime)||
       out->tls!=READ_ONCE(*task_user_tls(task))){result=-EAGAIN;goto out;}
    if(out->pid<=0||out->tid<=0||!out->tls||!out->sp||(out->sp&15)||
       !out->pc||(out->pc&3)||out->pc>=TASK_SIZE_64||out->sp>=TASK_SIZE_64){
        result=-EOPNOTSUPP;goto out;
    }
    result=1;
out:
    release_stack(task);
    if(result!=1)memset(out,0,sizeof(*out));
    return result;
}

static int collect_waiters(struct futex_context *context,u64 address,u32 operation,
                        u32 bitset,struct dfm_futex_thread *out,u32 capacity,u32 *count)
{
    struct task_struct **tasks,*task;
    struct dfm_futex_thread *sample;
    unsigned total=0,i;
    u32 command=operation&127U;
    int error=0;
    if(count)*count=0;
    if(!count||!out||!capacity||capacity>KD_FUTEX_OUTPUT_LIMIT)return -EINVAL;
    memset(out,0,capacity*sizeof(*out));
    if(!context_alive(context))return -ESRCH;
    if(!(operation&DFM_FUTEX_PRIVATE_FLAG)||(operation&~0xffU)||
       (command!=DFM_FUTEX_WAKE&&command!=DFM_FUTEX_WAKE_BITSET))return -EOPNOTSUPP;
    if(command==DFM_FUTEX_WAKE)bitset=DFM_FUTEX_BITSET_MATCH_ANY;
    if(!bitset)return -EINVAL;
    address=futex_address(address);
    if(!address||(address&3)||address>=TASK_SIZE_64)return -EINVAL;
    error=resolve_symbols();if(error)return error;
    tasks=kcalloc(KD_FUTEX_TASK_LIMIT,sizeof(*tasks),GFP_KERNEL);
    sample=kmalloc(sizeof(*sample),GFP_KERNEL);
    if(!tasks||!sample){error=-ENOMEM;goto done;}
    rcu_read_lock();
    for_each_thread(context->task->group_leader,task){
        if(!same_process(context,task))continue;
        if(total==KD_FUTEX_TASK_LIMIT){error=-E2BIG;break;}
        get_task_struct(task);tasks[total++]=task;
    }
    rcu_read_unlock();
    if(error)goto release;
    for(i=0;i<total;i++){
        int rc=sample_waiter(context,tasks[i],address,bitset,sample);
        if(rc<0){error=rc;break;}
        if(!rc)continue;
        /* A subset of waiters is sufficient for a bounded WAKE. Already
         * imported continuations are de-duplicated by the emulator's TID. */
        out[(*count)++]=*sample;
        if(*count==capacity)break;
    }
    if(!error&&!context_alive(context))error=-ESTALE;
release:
    for(i=0;i<total;i++)put_task_struct(tasks[i]);
done:
    kfree(sample);kfree(tasks);
    if(error){memset(out,0,capacity*sizeof(*out));*count=0;}
    return error;
}

long dfm_futex_waiters(struct file *owner, void __user *arg)
{
    struct dfm_futex_waiters_req req;
    struct dfm_futex_thread *threads;
    struct futex_context *context;
    int error;
    if (!arg || copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
    if (req.version != DFM_FUTEX_ABI_VERSION || req.pid <= 0 ||
        req.reserved[0] || req.reserved[1] || !req.out_threads ||
        !req.capacity || req.capacity > DFM_FUTEX_MAX_THREADS) return -EINVAL;
    if (!access_ok(u64_to_user_ptr(req.out_threads),
                   req.capacity * sizeof(*threads))) return -EFAULT;
    threads = kcalloc(req.capacity, sizeof(*threads), GFP_KERNEL);
    if (!threads) return -ENOMEM;
    req.out_count = 0;
    mutex_lock(&contexts_lock);
    context = open_context(owner, req.pid);
    if (IS_ERR(context)) error = PTR_ERR(context);
    else error = collect_waiters(context, req.address, req.operation, req.bitset,
                                  threads, req.capacity, &req.out_count);
    if (!error && ((req.out_count && copy_to_user(u64_to_user_ptr(req.out_threads),
            threads, req.out_count * sizeof(*threads))) ||
            copy_to_user(arg, &req, sizeof(req)))) error = -EFAULT;
    mutex_unlock(&contexts_lock);
    kfree(threads);
    return error;
}

long dfm_futex_validate(struct file *owner, void __user *arg)
{
    struct dfm_futex_validate_req req;
    struct dfm_futex_thread *sample, *snapshot;
    struct futex_context *context;
    struct task_struct *task = NULL;
    struct pid *pid;
    u32 command, bitset;
    int error;
    if (!arg || copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
    if (req.version != DFM_FUTEX_ABI_VERSION || req.pid <= 0 ||
        req.reserved[0] || req.reserved[1] || !req.snapshot) return -EINVAL;
    snapshot = memdup_user(u64_to_user_ptr(req.snapshot), sizeof(*snapshot));
    if (IS_ERR(snapshot)) return PTR_ERR(snapshot);
    if (snapshot->pid != req.pid || snapshot->tid <= 0 || snapshot->reserved ||
        snapshot->syscall_nr != KD_AARCH64_NR_FUTEX ||
        !snapshot->context_id || !snapshot->sequence) { error = -EINVAL; goto free_snapshot; }
    sample = kzalloc(sizeof(*sample), GFP_KERNEL);
    if (!sample) { error = -ENOMEM; goto free_snapshot; }
    mutex_lock(&contexts_lock);
    context = find_context(owner);
    if (!context_alive(context) || context->identity != snapshot->context_id ||
        task_tgid_vnr(context->task) != req.pid) { error = -ESTALE; goto unlock; }
    error = resolve_symbols();
    if (error) goto unlock;
    pid = find_get_pid(snapshot->tid);
    task = get_pid_task(pid, PIDTYPE_PID);
    put_pid(pid);
    if (!task || !same_process(context, task) ||
        task_tgid_vnr(task) != snapshot->pid ||
        READ_ONCE(task->start_boottime) != snapshot->identity) {
        error = -ESTALE; goto unlock;
    }
    command = (u32)snapshot->args[1] & 127U;
    bitset = command == DFM_FUTEX_WAIT_BITSET ? (u32)snapshot->args[5] : DFM_FUTEX_BITSET_MATCH_ANY;
    error = sample_waiter(context, task, futex_address(snapshot->args[0]), bitset, sample);
    if (error >= 0) error = error == 1 && !memcmp(snapshot, sample, sizeof(*sample)) ? 0 : -EAGAIN;
unlock:
    if (task) put_task_struct(task);
    mutex_unlock(&contexts_lock);
    kfree(sample);
free_snapshot:
    kfree(snapshot);
    return error;
}

long dfm_capabilities(void __user *arg)
{
    struct dfm_capabilities_req req;
    if (!arg || copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
    if (req.abi_version != DFM_CAPABILITIES_ABI_VERSION ||
        req.reserved[0] || req.reserved[1]) return -EINVAL;
    req.out_abi_version = DFM_CAPABILITIES_ABI_VERSION;
    req.out_features = DFM_CAP_REQUIRED;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}
