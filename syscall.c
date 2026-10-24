#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#ifndef __aarch64__
#error "DFM kernel module requires ARM64"
#endif

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>
#include <asm-generic/fixmap.h>

#include "abi.h"
#include "install.h"
#include "syscall.h"

#ifndef __nocfi
#define __nocfi
#endif

typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *regs);

static syscall_fn_t *g_sys_call_table;
static syscall_fn_t g_orig_syscall;
static int g_hooked_nr = -1;

static void *syscall_lookup_symbol(const char *symbol_name)
{
    char cfi_name[KSYM_NAME_LEN];
    void *addr;
    size_t symbol_len;
    static const char cfi_suffix[] = ".cfi_jt";
    size_t cfi_suffix_len = sizeof(cfi_suffix) - 1;

    if (!symbol_name || !symbol_name[0])
        return NULL;

    symbol_len = strlen(symbol_name);
    if ((symbol_len < cfi_suffix_len ||
         strcmp(symbol_name + symbol_len - cfi_suffix_len, cfi_suffix) != 0) &&
        strscpy(cfi_name, symbol_name, sizeof(cfi_name)) > 0 &&
        strlen(cfi_name) + cfi_suffix_len + 1 <= sizeof(cfi_name)) {
        /* Linux 6.12 removed strlcat; the prior length check guarantees room,
         * so append via strscpy on the tail (idiomatic post-strlcat). */
        size_t off = strlen(cfi_name);
        strscpy(cfi_name + off, cfi_suffix, sizeof(cfi_name) - off);
        addr = (void *)kallsyms_lookup_name(cfi_name);
        if (addr)
            return addr;
    }

    return (void *)kallsyms_lookup_name(symbol_name);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#define syscall_flush_dcache(start, sz)                         \
    do {                                                    \
        unsigned long __start = (unsigned long)(start);     \
        dcache_clean_inval_poc(__start, __start + (sz));    \
    } while (0)
#else
#define syscall_flush_dcache(start, sz) __flush_dcache_area((void *)(start), (sz))
#endif

struct syscall_patch_text_info {
    void *dst;
    const void *src;
    size_t len;
    atomic_t cpu_count;
};

static unsigned long syscall_phys_from_virt(unsigned long addr, int *err)
{
    struct mm_struct *mm = &init_mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    *err = 0;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto fail;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto fail;
#if defined(p4d_leaf)
    if (p4d_leaf(*p4d))
        return __p4d_to_phys(*p4d) + (addr & ~P4D_MASK);
#endif

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto fail;
#if defined(pud_leaf)
    if (pud_leaf(*pud))
        return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
#endif

    pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
    if (pmd_leaf(*pmd))
        return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto fail;

    pte = pte_offset_kernel(pmd, addr);
    if (!pte || !pte_present(*pte))
        goto fail;

    return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);

fail:
    *err = -ENOENT;
    return 0;
}

static int syscall_patch_text_nosync(void *dst, const void *src, size_t len)
{
    unsigned long phys;
    void *map;
    int err;
    int ret;

    phys = syscall_phys_from_virt((unsigned long)dst, &err);
    if (err)
        return err;

    map = (void *)set_fixmap_offset(FIX_TEXT_POKE0, phys);
    ret = (int)copy_to_kernel_nofault(map, src, len);
    clear_fixmap(FIX_TEXT_POKE0);

    if (!ret)
        syscall_flush_dcache(dst, len);

    return ret;
}

static int syscall_patch_text_cb(void *arg)
{
    struct syscall_patch_text_info *info = arg;
    int ret = 0;

    if (atomic_inc_return(&info->cpu_count) == num_online_cpus()) {
        ret = syscall_patch_text_nosync(info->dst, info->src, info->len);
        atomic_inc(&info->cpu_count);
    } else {
        while (atomic_read(&info->cpu_count) <= num_online_cpus())
            cpu_relax();
        isb();
    }

    return ret;
}

static int syscall_patch_text(void *dst, const void *src, size_t len)
{
    struct syscall_patch_text_info info = {
        .dst = dst,
        .src = src,
        .len = len,
        .cpu_count = ATOMIC_INIT(0),
    };

    return stop_machine(syscall_patch_text_cb, &info, cpu_online_mask);
}

static int syscall_patch_table(int nr, syscall_fn_t fn)
{
    if (!g_sys_call_table)
        return -ENOENT;
    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;

    return syscall_patch_text(&g_sys_call_table[nr], &fn, sizeof(fn));
}

static asmlinkage long __nocfi syscall_install_handler(const struct pt_regs *regs)
{
    int magic1;
    int magic2;
    int __user *outp;

    if (!regs || current_uid().val > 1000)
        return -ENOSYS;

    magic1 = (int)regs->regs[0];
    magic2 = (int)regs->regs[1];
    if (magic1 != INSTALL_MAGIC1 || magic2 != INSTALL_MAGIC2)
        return -ENOSYS;

    outp = (int __user *)(unsigned long)regs->regs[3];
    return install_fd_to_user(outp);
}

static syscall_fn_t syscall_lookup_ni(void)
{
    syscall_fn_t ni;

    ni = (syscall_fn_t)syscall_lookup_symbol("__arm64_sys_ni_syscall");
    if (ni)
        return ni;

    return (syscall_fn_t)syscall_lookup_symbol("sys_ni_syscall");
}

int syscall_hook_init(void)
{
    syscall_fn_t ni_syscall;
    int i;
    int ret;
    int install_ret = -ENOENT;

    if (g_hooked_nr >= 0)
        return 0;

    g_sys_call_table = (syscall_fn_t *)syscall_lookup_symbol("sys_call_table");
    if (!g_sys_call_table)
        return -ENOENT;

    ni_syscall = syscall_lookup_ni();
    if (!ni_syscall)
        return -ENOENT;

    for (i = 0; i < __NR_syscalls; i++) {
        if (READ_ONCE(g_sys_call_table[i]) != ni_syscall)
            continue;

        ret = syscall_patch_table(i, syscall_install_handler);
        if (ret) {
            install_ret = ret;
            continue;
        }

        g_orig_syscall = ni_syscall;
        g_hooked_nr = i;
        pr_info("syscall install hook registered at nr %d\n", g_hooked_nr);
        return 0;
    }

    return install_ret;
}

void syscall_hook_exit(void)
{
    int ret;

    if (!g_sys_call_table)
        return;

    if (g_hooked_nr >= 0 && g_orig_syscall) {
        ret = syscall_patch_table(g_hooked_nr, g_orig_syscall);
        if (ret)
            pr_err("failed to restore syscall nr %d: %d\n", g_hooked_nr, ret);
        else
            pr_info("syscall install hook restored nr %d\n", g_hooked_nr);
    }

    g_hooked_nr = -1;
    g_orig_syscall = NULL;
}

int syscall_hook_nr(void)
{
    return g_hooked_nr;
}
