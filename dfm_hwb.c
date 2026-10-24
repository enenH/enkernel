/*
 * Hardware breakpoint support adapted from Linux-android-arm64/lsdriver.
 *
 * MIT License
 * Copyright (c) 2025 LsLucky
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

#ifndef __aarch64__
#error "DFM kernel module requires ARM64"
#endif

#include <linux/bitmap.h>
#include <linux/build_bug.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/hw_breakpoint.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#include <asm/debug-monitors.h>
#include <asm/hw_breakpoint.h>
#include <asm/insn.h>
#include <asm/ptrace.h>

#include "abi.h"
#include "dfm_hwb.h"

#ifndef __nocfi
#define __nocfi __attribute__((no_sanitize("cfi")))
#endif

#ifndef ARM_BREAKPOINT_EXECUTE
#define ARM_BREAKPOINT_EXECUTE 0
#define ARM_BREAKPOINT_LOAD    1
#define ARM_BREAKPOINT_STORE   2
#endif

#ifndef AARCH64_BREAKPOINT_EL0
#define AARCH64_BREAKPOINT_EL0 2
#endif

#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

#define DFM_HWB_ESR_ACCESS_MASK (1U << 6)

#define DFM_HWB_DBG_BVR 0
#define DFM_HWB_DBG_BCR 1
#define DFM_HWB_DBG_WVR 2
#define DFM_HWB_DBG_WCR 3

struct dfm_hwb_session {
    int configured;
    int hooks_installed;
    int target_tid;
    uint64_t generation;
    struct file *owner;
    uint32_t point_count;
    uint32_t used_brps;
    uint32_t used_wrps;
    struct dfm_hwb_point_req points[DFM_HWB_MAX_POINTS];
    struct dfm_hwb_snapshot *snapshots[2];
    int active_snapshot;
};

static DEFINE_MUTEX(g_hwb_mutex);
static DEFINE_SPINLOCK(g_hwb_lock);
static struct dfm_hwb_session g_hwb;
static atomic_t g_hwb_finish_returns_inflight = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(g_hwb_finish_return_wait);

static inline int dfm_hwb_clamp_slots(int count)
{
    if (count < 0)
        return 0;
    if (count > DFM_HWB_MAX_HW_SLOTS)
        return DFM_HWB_MAX_HW_SLOTS;
    return count;
}

static int dfm_hwb_get_brps(void)
{
    uint64_t dfr0;

    asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
    return dfm_hwb_clamp_slots((int)((dfr0 >> 12) & 0xF) + 1);
}

static int dfm_hwb_get_wrps(void)
{
    uint64_t dfr0;

    asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
    return dfm_hwb_clamp_slots((int)((dfr0 >> 20) & 0xF) + 1);
}

#define DFM_READ_DBG_CASE(N, NAME, VAL)                 \
    case N:                                             \
        asm volatile("mrs %0, dbg" #NAME #N "_el1"     \
                     : "=r"(VAL));                     \
        break

#define DFM_WRITE_DBG_CASE(N, NAME, VAL)                \
    case N:                                             \
        asm volatile("msr dbg" #NAME #N "_el1, %x0"    \
                     :                                  \
                     : "rZ"(VAL));                     \
        break

static uint64_t dfm_hwb_read_dbg_reg(int reg, int n)
{
    uint64_t val = 0;

    switch (reg) {
    case DFM_HWB_DBG_BVR:
        switch (n) {
        DFM_READ_DBG_CASE(0, bvr, val);
        DFM_READ_DBG_CASE(1, bvr, val);
        DFM_READ_DBG_CASE(2, bvr, val);
        DFM_READ_DBG_CASE(3, bvr, val);
        DFM_READ_DBG_CASE(4, bvr, val);
        DFM_READ_DBG_CASE(5, bvr, val);
        DFM_READ_DBG_CASE(6, bvr, val);
        DFM_READ_DBG_CASE(7, bvr, val);
        DFM_READ_DBG_CASE(8, bvr, val);
        DFM_READ_DBG_CASE(9, bvr, val);
        DFM_READ_DBG_CASE(10, bvr, val);
        DFM_READ_DBG_CASE(11, bvr, val);
        DFM_READ_DBG_CASE(12, bvr, val);
        DFM_READ_DBG_CASE(13, bvr, val);
        DFM_READ_DBG_CASE(14, bvr, val);
        DFM_READ_DBG_CASE(15, bvr, val);
        default:
            break;
        }
        break;
    case DFM_HWB_DBG_BCR:
        switch (n) {
        DFM_READ_DBG_CASE(0, bcr, val);
        DFM_READ_DBG_CASE(1, bcr, val);
        DFM_READ_DBG_CASE(2, bcr, val);
        DFM_READ_DBG_CASE(3, bcr, val);
        DFM_READ_DBG_CASE(4, bcr, val);
        DFM_READ_DBG_CASE(5, bcr, val);
        DFM_READ_DBG_CASE(6, bcr, val);
        DFM_READ_DBG_CASE(7, bcr, val);
        DFM_READ_DBG_CASE(8, bcr, val);
        DFM_READ_DBG_CASE(9, bcr, val);
        DFM_READ_DBG_CASE(10, bcr, val);
        DFM_READ_DBG_CASE(11, bcr, val);
        DFM_READ_DBG_CASE(12, bcr, val);
        DFM_READ_DBG_CASE(13, bcr, val);
        DFM_READ_DBG_CASE(14, bcr, val);
        DFM_READ_DBG_CASE(15, bcr, val);
        default:
            break;
        }
        break;
    case DFM_HWB_DBG_WVR:
        switch (n) {
        DFM_READ_DBG_CASE(0, wvr, val);
        DFM_READ_DBG_CASE(1, wvr, val);
        DFM_READ_DBG_CASE(2, wvr, val);
        DFM_READ_DBG_CASE(3, wvr, val);
        DFM_READ_DBG_CASE(4, wvr, val);
        DFM_READ_DBG_CASE(5, wvr, val);
        DFM_READ_DBG_CASE(6, wvr, val);
        DFM_READ_DBG_CASE(7, wvr, val);
        DFM_READ_DBG_CASE(8, wvr, val);
        DFM_READ_DBG_CASE(9, wvr, val);
        DFM_READ_DBG_CASE(10, wvr, val);
        DFM_READ_DBG_CASE(11, wvr, val);
        DFM_READ_DBG_CASE(12, wvr, val);
        DFM_READ_DBG_CASE(13, wvr, val);
        DFM_READ_DBG_CASE(14, wvr, val);
        DFM_READ_DBG_CASE(15, wvr, val);
        default:
            break;
        }
        break;
    case DFM_HWB_DBG_WCR:
        switch (n) {
        DFM_READ_DBG_CASE(0, wcr, val);
        DFM_READ_DBG_CASE(1, wcr, val);
        DFM_READ_DBG_CASE(2, wcr, val);
        DFM_READ_DBG_CASE(3, wcr, val);
        DFM_READ_DBG_CASE(4, wcr, val);
        DFM_READ_DBG_CASE(5, wcr, val);
        DFM_READ_DBG_CASE(6, wcr, val);
        DFM_READ_DBG_CASE(7, wcr, val);
        DFM_READ_DBG_CASE(8, wcr, val);
        DFM_READ_DBG_CASE(9, wcr, val);
        DFM_READ_DBG_CASE(10, wcr, val);
        DFM_READ_DBG_CASE(11, wcr, val);
        DFM_READ_DBG_CASE(12, wcr, val);
        DFM_READ_DBG_CASE(13, wcr, val);
        DFM_READ_DBG_CASE(14, wcr, val);
        DFM_READ_DBG_CASE(15, wcr, val);
        default:
            break;
        }
        break;
    default:
        break;
    }

    return val;
}

static void dfm_hwb_write_dbg_reg(int reg, int n, uint64_t val)
{
    switch (reg) {
    case DFM_HWB_DBG_BVR:
        switch (n) {
        DFM_WRITE_DBG_CASE(0, bvr, val);
        DFM_WRITE_DBG_CASE(1, bvr, val);
        DFM_WRITE_DBG_CASE(2, bvr, val);
        DFM_WRITE_DBG_CASE(3, bvr, val);
        DFM_WRITE_DBG_CASE(4, bvr, val);
        DFM_WRITE_DBG_CASE(5, bvr, val);
        DFM_WRITE_DBG_CASE(6, bvr, val);
        DFM_WRITE_DBG_CASE(7, bvr, val);
        DFM_WRITE_DBG_CASE(8, bvr, val);
        DFM_WRITE_DBG_CASE(9, bvr, val);
        DFM_WRITE_DBG_CASE(10, bvr, val);
        DFM_WRITE_DBG_CASE(11, bvr, val);
        DFM_WRITE_DBG_CASE(12, bvr, val);
        DFM_WRITE_DBG_CASE(13, bvr, val);
        DFM_WRITE_DBG_CASE(14, bvr, val);
        DFM_WRITE_DBG_CASE(15, bvr, val);
        default:
            break;
        }
        break;
    case DFM_HWB_DBG_BCR:
        switch (n) {
        DFM_WRITE_DBG_CASE(0, bcr, val);
        DFM_WRITE_DBG_CASE(1, bcr, val);
        DFM_WRITE_DBG_CASE(2, bcr, val);
        DFM_WRITE_DBG_CASE(3, bcr, val);
        DFM_WRITE_DBG_CASE(4, bcr, val);
        DFM_WRITE_DBG_CASE(5, bcr, val);
        DFM_WRITE_DBG_CASE(6, bcr, val);
        DFM_WRITE_DBG_CASE(7, bcr, val);
        DFM_WRITE_DBG_CASE(8, bcr, val);
        DFM_WRITE_DBG_CASE(9, bcr, val);
        DFM_WRITE_DBG_CASE(10, bcr, val);
        DFM_WRITE_DBG_CASE(11, bcr, val);
        DFM_WRITE_DBG_CASE(12, bcr, val);
        DFM_WRITE_DBG_CASE(13, bcr, val);
        DFM_WRITE_DBG_CASE(14, bcr, val);
        DFM_WRITE_DBG_CASE(15, bcr, val);
        default:
            break;
        }
        break;
    case DFM_HWB_DBG_WVR:
        switch (n) {
        DFM_WRITE_DBG_CASE(0, wvr, val);
        DFM_WRITE_DBG_CASE(1, wvr, val);
        DFM_WRITE_DBG_CASE(2, wvr, val);
        DFM_WRITE_DBG_CASE(3, wvr, val);
        DFM_WRITE_DBG_CASE(4, wvr, val);
        DFM_WRITE_DBG_CASE(5, wvr, val);
        DFM_WRITE_DBG_CASE(6, wvr, val);
        DFM_WRITE_DBG_CASE(7, wvr, val);
        DFM_WRITE_DBG_CASE(8, wvr, val);
        DFM_WRITE_DBG_CASE(9, wvr, val);
        DFM_WRITE_DBG_CASE(10, wvr, val);
        DFM_WRITE_DBG_CASE(11, wvr, val);
        DFM_WRITE_DBG_CASE(12, wvr, val);
        DFM_WRITE_DBG_CASE(13, wvr, val);
        DFM_WRITE_DBG_CASE(14, wvr, val);
        DFM_WRITE_DBG_CASE(15, wvr, val);
        default:
            break;
        }
        break;
    case DFM_HWB_DBG_WCR:
        switch (n) {
        DFM_WRITE_DBG_CASE(0, wcr, val);
        DFM_WRITE_DBG_CASE(1, wcr, val);
        DFM_WRITE_DBG_CASE(2, wcr, val);
        DFM_WRITE_DBG_CASE(3, wcr, val);
        DFM_WRITE_DBG_CASE(4, wcr, val);
        DFM_WRITE_DBG_CASE(5, wcr, val);
        DFM_WRITE_DBG_CASE(6, wcr, val);
        DFM_WRITE_DBG_CASE(7, wcr, val);
        DFM_WRITE_DBG_CASE(8, wcr, val);
        DFM_WRITE_DBG_CASE(9, wcr, val);
        DFM_WRITE_DBG_CASE(10, wcr, val);
        DFM_WRITE_DBG_CASE(11, wcr, val);
        DFM_WRITE_DBG_CASE(12, wcr, val);
        DFM_WRITE_DBG_CASE(13, wcr, val);
        DFM_WRITE_DBG_CASE(14, wcr, val);
        DFM_WRITE_DBG_CASE(15, wcr, val);
        default:
            break;
        }
        break;
    default:
        break;
    }
    isb();
}

static void dfm_hwb_enable_cpu(void)
{
    uint64_t mdscr;

    asm volatile("msr oslar_el1, xzr\n\t"
                 "isb\n\t"
                 :
                 :
                 : "memory");

    asm volatile("mrs %[val], mdscr_el1\n\t"
                 "orr %[val], %[val], %[mask]\n\t"
                 "msr mdscr_el1, %[val]\n\t"
                 "isb\n\t"
                 : [val] "=&r"(mdscr)
                 : [mask] "r"((uint64_t)((1UL << 15) | (1UL << 13)))
                 : "memory");
}

static void dfm_hwb_disable_cpu(void)
{
    uint64_t mdscr;

    asm volatile("mrs %[val], mdscr_el1\n\t"
                 "bic %[val], %[val], %[mask]\n\t"
                 "msr mdscr_el1, %[val]\n\t"
                 "isb\n\t"
                 : [val] "=&r"(mdscr)
                 : [mask] "r"((uint64_t)((1UL << 15) | (1UL << 13)))
                 : "memory");

    asm volatile("mov x0, #1\n\t"
                 "msr oslar_el1, x0\n\t"
                 "isb\n\t"
                 :
                 :
                 : "x0", "memory");
}

static uint64_t dfm_hwb_encode_ctrl(uint32_t type, uint32_t len_mask)
{
    return ((uint64_t)(len_mask & 0xFFU) << 5) |
           ((uint64_t)(type & 0x3U) << 3) |
           ((uint64_t)(AARCH64_BREAKPOINT_EL0 & 0x3U) << 1);
}

static int dfm_hwb_parse_point(const struct dfm_hwb_point_req *point,
                               uint64_t *addr, uint64_t *ctrl, int *is_exec)
{
    uint32_t type;
    uint32_t len_mask;
    uint64_t base;
    uint32_t offset;

    if (!point || !addr || !ctrl || !is_exec)
        return -EINVAL;
    if (!point->addr || point->len < 1 || point->len > 8)
        return -EINVAL;

    switch (point->type) {
    case DFM_HWB_TYPE_X:
        type = ARM_BREAKPOINT_EXECUTE;
        base = point->addr & ~0x3ULL;
        len_mask = 0xFU;
        *is_exec = 1;
        break;
    case DFM_HWB_TYPE_R:
        type = ARM_BREAKPOINT_LOAD;
        base = point->addr & ~0x7ULL;
        offset = (uint32_t)(point->addr & 0x7ULL);
        if (offset + point->len > 8)
            return -EINVAL;
        len_mask = ((1U << point->len) - 1U) << offset;
        *is_exec = 0;
        break;
    case DFM_HWB_TYPE_W:
        type = ARM_BREAKPOINT_STORE;
        base = point->addr & ~0x7ULL;
        offset = (uint32_t)(point->addr & 0x7ULL);
        if (offset + point->len > 8)
            return -EINVAL;
        len_mask = ((1U << point->len) - 1U) << offset;
        *is_exec = 0;
        break;
    case DFM_HWB_TYPE_RW:
        type = ARM_BREAKPOINT_LOAD | ARM_BREAKPOINT_STORE;
        base = point->addr & ~0x7ULL;
        offset = (uint32_t)(point->addr & 0x7ULL);
        if (offset + point->len > 8)
            return -EINVAL;
        len_mask = ((1U << point->len) - 1U) << offset;
        *is_exec = 0;
        break;
    default:
        return -EINVAL;
    }

    *addr = base;
    *ctrl = dfm_hwb_encode_ctrl(type, len_mask);
    return 0;
}

static uint32_t dfm_hwb_lowest_set_bit(uint32_t value)
{
    uint32_t bit;

    for (bit = 0; bit < 32; bit++) {
        if (value & (1U << bit))
            return bit;
    }
    return 32;
}

static uint32_t dfm_hwb_highest_set_bit(uint32_t value)
{
    int bit;

    for (bit = 31; bit >= 0; bit--) {
        if (value & (1U << bit))
            return (uint32_t)bit;
    }
    return 32;
}

static uint64_t dfm_hwb_watch_distance(uint64_t fault_addr, uint64_t watch_addr,
                                       uint32_t len_mask)
{
    uint32_t low;
    uint32_t high;
    uint64_t wp_low;
    uint64_t wp_high;

    fault_addr = untagged_addr(fault_addr);
    low = dfm_hwb_lowest_set_bit(len_mask);
    high = dfm_hwb_highest_set_bit(len_mask);
    if (low >= 32 || high >= 32)
        return ~0ULL;

    wp_low = watch_addr + low;
    wp_high = watch_addr + high;
    if (fault_addr < wp_low)
        return wp_low - fault_addr;
    if (fault_addr > wp_high)
        return fault_addr - wp_high;
    return 0;
}

static int dfm_hwb_access_matches(uint32_t point_type, uint64_t esr)
{
    int is_write = !!(esr & DFM_HWB_ESR_ACCESS_MASK);

    if (is_write)
        return !!(point_type & DFM_HWB_TYPE_W);
    return !!(point_type & DFM_HWB_TYPE_R);
}

static inline void dfm_hwb_read_q_reg(int n, uint64_t q[2])
{
    switch (n) {
#define DFM_READ_Q_CASE(N)                                           \
    case N:                                                          \
        asm volatile(".arch_extension fp\n.arch_extension simd\n\t"  \
                     "str q" #N ", [%0]\n\t"                        \
                     :                                               \
                     : "r"(q)                                       \
                     : "memory");                                  \
        break
    DFM_READ_Q_CASE(0);
    DFM_READ_Q_CASE(1);
    DFM_READ_Q_CASE(2);
    DFM_READ_Q_CASE(3);
    DFM_READ_Q_CASE(4);
    DFM_READ_Q_CASE(5);
    DFM_READ_Q_CASE(6);
    DFM_READ_Q_CASE(7);
    DFM_READ_Q_CASE(8);
    DFM_READ_Q_CASE(9);
    DFM_READ_Q_CASE(10);
    DFM_READ_Q_CASE(11);
    DFM_READ_Q_CASE(12);
    DFM_READ_Q_CASE(13);
    DFM_READ_Q_CASE(14);
    DFM_READ_Q_CASE(15);
    DFM_READ_Q_CASE(16);
    DFM_READ_Q_CASE(17);
    DFM_READ_Q_CASE(18);
    DFM_READ_Q_CASE(19);
    DFM_READ_Q_CASE(20);
    DFM_READ_Q_CASE(21);
    DFM_READ_Q_CASE(22);
    DFM_READ_Q_CASE(23);
    DFM_READ_Q_CASE(24);
    DFM_READ_Q_CASE(25);
    DFM_READ_Q_CASE(26);
    DFM_READ_Q_CASE(27);
    DFM_READ_Q_CASE(28);
    DFM_READ_Q_CASE(29);
    DFM_READ_Q_CASE(30);
    DFM_READ_Q_CASE(31);
#undef DFM_READ_Q_CASE
    default:
        break;
    }
}

static inline uint32_t dfm_hwb_read_fpcr(void)
{
    uint64_t v;

    asm volatile(".arch_extension fp\n\t"
                 "mrs %0, fpcr"
                 : "=r"(v));
    return (uint32_t)v;
}

static inline uint32_t dfm_hwb_read_fpsr(void)
{
    uint64_t v;

    asm volatile(".arch_extension fp\n\t"
                 "mrs %0, fpsr"
                 : "=r"(v));
    return (uint32_t)v;
}

typedef int (*dfm_hwb_patch_text_fn_t)(void *addrs[], uint32_t insns[], int cnt);
static dfm_hwb_patch_text_fn_t g_hwb_patch_text;

static void *dfm_hwb_lookup_symbol(const char *name)
{
    if (!name || !name[0])
        return NULL;
    return (void *)kallsyms_lookup_name(name);
}

static int __nocfi dfm_hwb_patch_words(uint32_t *dst, const uint32_t *src, int count)
{
    void *addrs[120];
    int i;

    if (count <= 0 || count > (int)(sizeof(addrs) / sizeof(addrs[0])))
        return -EINVAL;

    if (!g_hwb_patch_text)
        g_hwb_patch_text =
            (dfm_hwb_patch_text_fn_t)dfm_hwb_lookup_symbol("aarch64_insn_patch_text");
    if (!g_hwb_patch_text)
        return -ENOENT;

    for (i = 0; i < count; i++)
        addrs[i] = &dst[i];

    return g_hwb_patch_text(addrs, (uint32_t *)src, count);
}

#define DFM_HOOK_STUB_WORDS 4
#define DFM_HOOK_STUB_BYTES (DFM_HOOK_STUB_WORDS * 4)
#define DFM_HWB_HOOK_METADATA_BYTES 32
#define DFM_HWB_HOOK_REGS_BYTES 272
#define DFM_HWB_HOOK_FRAME_BYTES 304
#define DFM_TRAMP_WORDS 120
#define DFM_TRAMP_BYTES (DFM_TRAMP_WORDS * 4)
#define DFM_TRAMP_SLOT_COUNT 8
#define DFM_TRAMP_ORIG_INSN_INDEX 57
#define DFM_TRAMP_RET_TO_ORIG_INDEX 61
#define DFM_TRAMP_RET_SLOT_INDEX 116
#define DFM_TRAMP_WORK_SLOT_INDEX 118

#define DFM_HOOK_STR_1(x) #x
#define DFM_HOOK_STR(x) DFM_HOOK_STR_1(x)

extern uint32_t dfm_hwb_trampoline_slots[];

asm(
    ".pushsection .text\n\t"
    ".balign 8\n\t"
    ".globl dfm_hwb_trampoline_slots\n\t"
    "dfm_hwb_trampoline_slots:\n\t"
    ".rept " DFM_HOOK_STR(DFM_TRAMP_SLOT_COUNT * DFM_TRAMP_WORDS) "\n\t"
    ".word 0xD503201F\n\t"
    ".endr\n\t"
    ".popsection\n\t");

static DECLARE_BITMAP(g_hwb_slot_used, DFM_TRAMP_SLOT_COUNT);

struct dfm_hwb_hook_entry {
    const char *target_sym;
    uint64_t target_addr;
    void *work_fn;
    uint32_t *trampoline;
    uint32_t saved_insn[DFM_HOOK_STUB_WORDS];
    int installed;
    int slot_index;
};

struct dfm_hwb_finish_return_frame {
    unsigned long return_addr;
    unsigned long return_x0;
    uint64_t generation;
    uint64_t reserved;
};

static struct dfm_hwb_finish_return_frame *
dfm_hwb_hook_frame_metadata(struct pt_regs *regs)
{
    if (!regs)
        return NULL;
    return (struct dfm_hwb_finish_return_frame *)
        ((char *)regs - DFM_HWB_HOOK_METADATA_BYTES);
}

static int dfm_hwb_slot_alloc(uint32_t **trampoline_out)
{
    int bit = find_first_zero_bit(g_hwb_slot_used, DFM_TRAMP_SLOT_COUNT);

    if (bit >= DFM_TRAMP_SLOT_COUNT)
        return -ENOSPC;
    set_bit(bit, g_hwb_slot_used);
    *trampoline_out = dfm_hwb_trampoline_slots + bit * DFM_TRAMP_WORDS;
    return bit;
}

static void dfm_hwb_slot_free(int index)
{
    if (index >= 0 && index < DFM_TRAMP_SLOT_COUNT)
        clear_bit(index, g_hwb_slot_used);
}

static void dfm_hwb_make_ldr_ret(uint64_t target, uint32_t *insn)
{
    uint32_t ldr_x16_literal = 0x58000050;
    uint32_t ret_x16 = 0xD65F0200;

    memcpy(&insn[0], &ldr_x16_literal, sizeof(uint32_t));
    memcpy(&insn[1], &ret_x16, sizeof(uint32_t));
    memcpy(&insn[2], &target, sizeof(target));
}

static void dfm_hwb_trampoline_build(uint32_t *buf,
                                     const uint32_t orig_insn[DFM_HOOK_STUB_WORDS],
                                     uint64_t work_fn, uint64_t return_addr)
{
    static const uint32_t tmpl[DFM_TRAMP_WORDS] = {
        0xD104C3FF, 0xA90207E0, 0xA9030FE2, 0xA90417E4,
        0xA9051FE6, 0xA90627E8, 0xA9072FEA, 0xA90837EC,
        0xA9093FEE, 0xA90A47F0, 0xA90B4FF2, 0xA90C57F4,
        0xA90D5FF6, 0xA90E67F8, 0xA90F6FFA, 0xA91077FC,
        0xF9008BFE, 0x9104C3E9, 0xF9008FE9, 0x58000C29,
        0xD1004129, 0xF90093E9, 0xD53B4209, 0xF90097E9,
        0x910003FD, 0x910083E0, 0x58000B89, 0xD63F0120,
        0xF100041F, 0x54000440, 0x58000AC9, 0xD1004129,
        0xF94093EA, 0xEB09015F, 0x54000721, 0x910083F0,
        0xF9407E11, 0xF9408609, 0xD51B4209, 0xF9407A1E,
        0xA94E761C, 0xA94D6E1A, 0xA94C6618, 0xA94B5E16,
        0xA94A5614, 0xA9494E12, 0xA9473E0E, 0xA946360C,
        0xA9452E0A, 0xA9442608, 0xA9431E06, 0xA9421604,
        0xA9410E02, 0xA9400600, 0x9100023F, 0xF9404611,
        0xF9404210,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x580006F0, 0xD65F0200, 0x580006A9, 0xD1004129,
        0xF94093EA, 0xEB09015F, 0x54000301, 0x910083F0,
        0xF9407E11, 0xF9408609, 0xD51B4209, 0xF9407A1E,
        0xA94E761C, 0xA94D6E1A, 0xA94C6618, 0xA94B5E16,
        0xA94A5614, 0xA9494E12, 0xA9473E0E, 0xA946360C,
        0xA9452E0A, 0xA9442608, 0xA9431E06, 0xA9421604,
        0xA9410E02, 0xA9400600, 0x9100023F, 0xF9404611,
        0xF9404210,
        0xD65F03C0, 0x910083F1, 0xF9408230, 0xF9407E2F,
        0xF9408629, 0xD51B4209, 0xF9407A3E, 0xA94E763C,
        0xA94D6E3A, 0xA94C6638, 0xA94B5E36, 0xA94A5634,
        0xA9494E32, 0xF9403A2E, 0xA946362C, 0xA9452E2A,
        0xA9442628, 0xA9431E26, 0xA9421624, 0xA9410E22,
        0xA9400620, 0x910001FF, 0xF9403E2F, 0xF9404631,
        0xD65F0200, 0xD503201F, 0x00000000, 0x00000000,
        0x00000000, 0x00000000,
    };

    BUILD_BUG_ON(offsetof(struct pt_regs, regs) != 0);
    BUILD_BUG_ON(offsetof(struct pt_regs, sp) != 248);
    BUILD_BUG_ON(offsetof(struct pt_regs, pc) != 256);
    BUILD_BUG_ON(offsetof(struct pt_regs, pstate) != 264);
    BUILD_BUG_ON(offsetof(struct pt_regs, orig_x0) != DFM_HWB_HOOK_REGS_BYTES);
    BUILD_BUG_ON(offsetof(struct dfm_hwb_finish_return_frame, return_addr) != 0);
    BUILD_BUG_ON(offsetof(struct dfm_hwb_finish_return_frame, return_x0) != 8);
    BUILD_BUG_ON(offsetof(struct dfm_hwb_finish_return_frame, generation) != 16);
    BUILD_BUG_ON(offsetof(struct dfm_hwb_finish_return_frame, reserved) != 24);
    BUILD_BUG_ON(sizeof(struct dfm_hwb_finish_return_frame) !=
                 DFM_HWB_HOOK_METADATA_BYTES);
    BUILD_BUG_ON(DFM_HWB_HOOK_FRAME_BYTES !=
                 DFM_HWB_HOOK_METADATA_BYTES + DFM_HWB_HOOK_REGS_BYTES);
    BUILD_BUG_ON(DFM_TRAMP_RET_TO_ORIG_INDEX !=
                 DFM_TRAMP_ORIG_INSN_INDEX + DFM_HOOK_STUB_WORDS);

    memcpy(buf, tmpl, DFM_TRAMP_BYTES);
    memcpy(&buf[DFM_TRAMP_ORIG_INSN_INDEX], orig_insn, DFM_HOOK_STUB_BYTES);
    memcpy(&buf[DFM_TRAMP_RET_SLOT_INDEX], &return_addr, sizeof(uint64_t));
    memcpy(&buf[DFM_TRAMP_WORK_SLOT_INDEX], &work_fn, sizeof(uint64_t));
}

static int dfm_hwb_hook_install_one(struct dfm_hwb_hook_entry *entry)
{
    uint32_t tramp_code[DFM_TRAMP_WORDS];
    uint32_t hook_code[DFM_HOOK_STUB_WORDS];
    uint64_t return_addr;
    int slot;
    int ret;
    int i;

    if (entry->installed)
        return 0;
    if (!entry->target_addr && entry->target_sym) {
        entry->target_addr = (uint64_t)dfm_hwb_lookup_symbol(entry->target_sym);
        if (!entry->target_addr)
            return -ENOENT;
    }
    if (!entry->target_addr || !entry->work_fn)
        return -EINVAL;

    slot = dfm_hwb_slot_alloc(&entry->trampoline);
    if (slot < 0)
        return slot;
    entry->slot_index = slot;

    for (i = 0; i < DFM_HOOK_STUB_WORDS; i++)
        entry->saved_insn[i] = READ_ONCE(*(uint32_t *)(uintptr_t)
                                         (entry->target_addr + i * 4));

    return_addr = entry->target_addr + DFM_HOOK_STUB_BYTES;
    dfm_hwb_trampoline_build(tramp_code, entry->saved_insn,
                             (uint64_t)entry->work_fn, return_addr);

    ret = dfm_hwb_patch_words(entry->trampoline, tramp_code, DFM_TRAMP_WORDS);
    if (ret)
        goto out_slot;

    dfm_hwb_make_ldr_ret((uint64_t)entry->trampoline, hook_code);
    ret = dfm_hwb_patch_words((uint32_t *)(uintptr_t)entry->target_addr,
                              hook_code, DFM_HOOK_STUB_WORDS);
    if (ret)
        goto out_restore;

    entry->installed = 1;
    return 0;

out_restore:
    dfm_hwb_patch_words((uint32_t *)(uintptr_t)entry->target_addr,
                        entry->saved_insn, DFM_HOOK_STUB_WORDS);
out_slot:
    dfm_hwb_slot_free(slot);
    entry->slot_index = -1;
    entry->trampoline = NULL;
    return ret;
}

static void dfm_hwb_hook_remove_one(struct dfm_hwb_hook_entry *entry)
{
    if (!entry->installed)
        return;

    dfm_hwb_patch_words((uint32_t *)(uintptr_t)entry->target_addr,
                        entry->saved_insn, DFM_HOOK_STUB_WORDS);
    dfm_hwb_slot_free(entry->slot_index);
    entry->slot_index = -1;
    entry->trampoline = NULL;
    entry->installed = 0;
}

static int dfm_hwb_hook_install_many(struct dfm_hwb_hook_entry *entries, int count)
{
    int i;
    int ret;

    for (i = 0; i < count; i++) {
        ret = dfm_hwb_hook_install_one(&entries[i]);
        if (ret) {
            while (--i >= 0)
                dfm_hwb_hook_remove_one(&entries[i]);
            return ret;
        }
    }
    return 0;
}

static void dfm_hwb_hook_remove_many(struct dfm_hwb_hook_entry *entries, int count)
{
    int i;

    for (i = count - 1; i >= 0; i--)
        dfm_hwb_hook_remove_one(&entries[i]);
}

#define DFM_HWB_HOOK(sym, fn)               \
    {                                       \
        .target_sym = (sym),                \
        .target_addr = 0,                   \
        .work_fn = (fn),                    \
        .trampoline = NULL,                 \
        .saved_insn = {0},                  \
        .installed = 0,                     \
        .slot_index = -1,                   \
    }

static void dfm_hwb_reset_snapshot(struct dfm_hwb_snapshot *snapshot)
{
    uint32_t i;

    if (!snapshot)
        return;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->target_tid = g_hwb.target_tid;
    snapshot->flags = g_hwb.configured ? DFM_HWB_SNAPSHOT_ACTIVE : 0;
    snapshot->point_count = g_hwb.point_count;
    for (i = 0; i < g_hwb.point_count && i < DFM_HWB_MAX_POINTS; i++) {
        snapshot->points[i].type = g_hwb.points[i].type;
        snapshot->points[i].len = g_hwb.points[i].len;
        snapshot->points[i].addr = g_hwb.points[i].addr;
    }
}

static int dfm_hwb_alloc_snapshots_locked(void)
{
    if (g_hwb.snapshots[0] && g_hwb.snapshots[1])
        return 0;

    g_hwb.snapshots[0] = vzalloc(sizeof(struct dfm_hwb_snapshot));
    g_hwb.snapshots[1] = vzalloc(sizeof(struct dfm_hwb_snapshot));
    if (!g_hwb.snapshots[0] || !g_hwb.snapshots[1]) {
        vfree(g_hwb.snapshots[0]);
        vfree(g_hwb.snapshots[1]);
        g_hwb.snapshots[0] = NULL;
        g_hwb.snapshots[1] = NULL;
        return -ENOMEM;
    }

    return 0;
}

static int dfm_hwb_tid_alive(int tid)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int alive = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(tid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();

    if (!task)
        return 0;

    mm = get_task_mm(task);
    if (mm) {
        alive = 1;
        mmput(mm);
    }

    put_task_struct(task);
    return alive;
}

static struct task_struct *dfm_hwb_get_task(int tid)
{
    struct task_struct *task;

    rcu_read_lock();
    task = pid_task(find_vpid(tid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    return task;
}

#if defined(CONFIG_PERF_EVENTS) && defined(CONFIG_HAVE_HW_BREAKPOINT)

static struct perf_event_context *
dfm_hwb_task_perf_context(struct task_struct *task)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    return rcu_dereference(task->perf_event_ctxp);
#else
    return rcu_dereference(task->perf_event_ctxp[perf_sw_context]);
#endif
}

static uint32_t dfm_hwb_perf_type(const struct perf_event *event)
{
    switch (event->attr.bp_type) {
    case HW_BREAKPOINT_X:
        return DFM_HWB_TYPE_X;
    case HW_BREAKPOINT_R:
        return DFM_HWB_TYPE_R;
    case HW_BREAKPOINT_W:
        return DFM_HWB_TYPE_W;
    case HW_BREAKPOINT_RW:
        return DFM_HWB_TYPE_RW;
    default:
        return 0;
    }
}

static int dfm_hwb_perf_event_is_ptrace(struct task_struct *task,
                                        struct perf_event *event)
{
    int i;

    for (i = 0; i < ARM_MAX_BRP; i++) {
        if (READ_ONCE(task->thread.debug.hbp_break[i]) == event)
            return 1;
    }
    for (i = 0; i < ARM_MAX_WRP; i++) {
        if (READ_ONCE(task->thread.debug.hbp_watch[i]) == event)
            return 1;
    }
    return 0;
}

static void dfm_hwb_copy_perf_event(struct dfm_hwb_slots_req *req,
                                    struct task_struct *task,
                                    struct perf_event *event)
{
    struct dfm_hwb_perf_event_state *out;
    uint32_t type;
    int active;

    if (event->attr.type != PERF_TYPE_BREAKPOINT)
        return;

    type = dfm_hwb_perf_type(event);
    if (!type)
        return;

    active = event->state == PERF_EVENT_STATE_ACTIVE;
    req->perf_event_total++;
    if (type == DFM_HWB_TYPE_X) {
        req->perf_brp_count++;
        if (active)
            req->active_perf_brp_count++;
    } else {
        req->perf_wrp_count++;
        if (active)
            req->active_perf_wrp_count++;
    }

    if (req->perf_event_count >= DFM_HWB_MAX_SLOT_EVENTS) {
        req->flags |= DFM_HWB_SLOTS_F_TRUNCATED;
        return;
    }

    out = &req->perf_events[req->perf_event_count++];
    out->type = type;
    out->len = (uint32_t)event->attr.bp_len;
    out->slot = DFM_HWB_SLOT_NONE;
    out->state = (int)event->state;
    out->cpu = event->cpu;
    out->oncpu = event->oncpu;
    out->addr = event->attr.bp_addr;
    out->hw_addr = event->hw.info.address;
    out->ctrl = (uint64_t)encode_ctrl_reg(event->hw.info.ctrl);
    out->event_id = event->id;

    if (event->state >= PERF_EVENT_STATE_INACTIVE)
        out->flags |= DFM_HWB_EVENT_F_ENABLED;
    if (active)
        out->flags |= DFM_HWB_EVENT_F_ACTIVE;
    if (event->attr.pinned)
        out->flags |= DFM_HWB_EVENT_F_PINNED;
    if (event->attr.exclusive)
        out->flags |= DFM_HWB_EVENT_F_EXCLUSIVE;
    if (dfm_hwb_perf_event_is_ptrace(task, event))
        out->flags |= DFM_HWB_EVENT_F_PTRACE;
    if (event->parent)
        out->flags |= DFM_HWB_EVENT_F_INHERITED;
}

static void dfm_hwb_capture_perf_events(struct dfm_hwb_slots_req *req,
                                        struct task_struct *task)
{
    struct perf_event_context *ctx;
    struct perf_event *event;
    unsigned long irq_flags;
    int attempt;

    for (attempt = 0; attempt < 4; attempt++) {
        rcu_read_lock();
        ctx = dfm_hwb_task_perf_context(task);
        if (!ctx) {
            rcu_read_unlock();
            return;
        }

        raw_spin_lock_irqsave(&ctx->lock, irq_flags);
        if (ctx != dfm_hwb_task_perf_context(task)) {
            raw_spin_unlock_irqrestore(&ctx->lock, irq_flags);
            rcu_read_unlock();
            continue;
        }

        req->flags |= DFM_HWB_SLOTS_F_PERF_CONTEXT;
        list_for_each_entry(event, &ctx->event_list, event_entry)
            dfm_hwb_copy_perf_event(req, task, event);

        raw_spin_unlock_irqrestore(&ctx->lock, irq_flags);
        rcu_read_unlock();
        return;
    }
}

#else

static void dfm_hwb_capture_perf_events(struct dfm_hwb_slots_req *req,
                                        struct task_struct *task)
{
    (void)req;
    (void)task;
}

#endif

static uint32_t dfm_hwb_type_from_ctrl(int is_exec, uint64_t ctrl)
{
    uint32_t type;

    if (is_exec)
        return DFM_HWB_TYPE_X;

    type = (uint32_t)((ctrl >> 3) & 0x3U);
    if (type == ARM_BREAKPOINT_LOAD)
        return DFM_HWB_TYPE_R;
    if (type == ARM_BREAKPOINT_STORE)
        return DFM_HWB_TYPE_W;
    if (type == (ARM_BREAKPOINT_LOAD | ARM_BREAKPOINT_STORE))
        return DFM_HWB_TYPE_RW;
    return 0;
}

static void dfm_hwb_mark_local_slots_locked(struct dfm_hwb_slots_req *req)
{
    uint32_t brp_slot = 0;
    uint32_t wrp_slot = 0;
    uint32_t i;

    if (!g_hwb.configured || g_hwb.target_tid != req->target_tid)
        return;

    for (i = 0; i < g_hwb.point_count; i++) {
        struct dfm_hwb_slot_state *slot;
        uint64_t addr;
        uint64_t ctrl;
        int is_exec;

        if (dfm_hwb_parse_point(&g_hwb.points[i], &addr, &ctrl, &is_exec))
            continue;

        if (is_exec) {
            if (brp_slot >= req->num_brps)
                continue;
            slot = &req->brps[brp_slot++];
        } else {
            if (wrp_slot >= req->num_wrps)
                continue;
            slot = &req->wrps[wrp_slot++];
        }

        if ((slot->flags & DFM_HWB_SLOT_F_OCCUPIED) &&
            slot->addr == addr && slot->ctrl == (ctrl | 0x1ULL))
            slot->flags |= DFM_HWB_SLOT_F_DFM;
    }
}

struct dfm_hwb_slots_cpu_arg {
    struct task_struct *task;
    struct dfm_hwb_slots_req *req;
};

static void dfm_hwb_capture_cpu_slots_cb(void *data)
{
    struct dfm_hwb_slots_cpu_arg *arg = data;
    struct dfm_hwb_slots_req *req = arg->req;
    uint32_t i;

    if (current != arg->task)
        return;

    req->observed_cpu = raw_smp_processor_id();
    req->flags |= DFM_HWB_SLOTS_F_TARGET_RUNNING |
                  DFM_HWB_SLOTS_F_REGS_VALID;

    for (i = 0; i < req->num_brps; i++) {
        struct dfm_hwb_slot_state *slot = &req->brps[i];

        slot->addr = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_BVR, (int)i);
        slot->ctrl = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_BCR, (int)i);
        slot->type = dfm_hwb_type_from_ctrl(1, slot->ctrl);
        slot->flags = DFM_HWB_SLOT_F_VALID;
        if (slot->ctrl) {
            slot->flags |= DFM_HWB_SLOT_F_OCCUPIED;
            req->occupied_brp_mask |= 1U << i;
        }
        if (slot->ctrl & 0x1ULL) {
            slot->flags |= DFM_HWB_SLOT_F_ENABLED;
            req->enabled_brp_mask |= 1U << i;
        }
    }

    for (i = 0; i < req->num_wrps; i++) {
        struct dfm_hwb_slot_state *slot = &req->wrps[i];

        slot->addr = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_WVR, (int)i);
        slot->ctrl = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_WCR, (int)i);
        slot->type = dfm_hwb_type_from_ctrl(0, slot->ctrl);
        slot->flags = DFM_HWB_SLOT_F_VALID;
        if (slot->ctrl) {
            slot->flags |= DFM_HWB_SLOT_F_OCCUPIED;
            req->occupied_wrp_mask |= 1U << i;
        }
        if (slot->ctrl & 0x1ULL) {
            slot->flags |= DFM_HWB_SLOT_F_ENABLED;
            req->enabled_wrp_mask |= 1U << i;
        }
    }

}

static void dfm_hwb_capture_cpu_slots(struct dfm_hwb_slots_req *req,
                                      struct task_struct *task)
{
    struct dfm_hwb_slots_cpu_arg arg = {
        .task = task,
        .req = req,
    };
    int attempt;
    int cpu;
    unsigned long irq_flags;

    for (attempt = 0; attempt < 4; attempt++) {
        cpu = task_cpu(task);
        req->task_cpu = cpu;
        if (cpu >= 0 && cpu < nr_cpu_ids && cpu_online(cpu))
            smp_call_function_single(cpu, dfm_hwb_capture_cpu_slots_cb,
                                     &arg, 1);
        if (req->flags & DFM_HWB_SLOTS_F_REGS_VALID) {
            spin_lock_irqsave(&g_hwb_lock, irq_flags);
            dfm_hwb_mark_local_slots_locked(req);
            spin_unlock_irqrestore(&g_hwb_lock, irq_flags);
            return;
        }
    }
}

static int dfm_hwb_slot_matches_event(
    const struct dfm_hwb_slot_state *slot,
    const struct dfm_hwb_perf_event_state *event)
{
    if (!(slot->flags & DFM_HWB_SLOT_F_OCCUPIED))
        return 0;
    if (slot->type != event->type || slot->addr != event->hw_addr)
        return 0;
    return (slot->ctrl & ~0x1ULL) == (event->ctrl & ~0x1ULL);
}

static void dfm_hwb_correlate_perf_slots(struct dfm_hwb_slots_req *req)
{
    uint32_t matched_brps = 0;
    uint32_t matched_wrps = 0;
    uint32_t i;

    if (!(req->flags & DFM_HWB_SLOTS_F_REGS_VALID))
        return;

    for (i = 0; i < req->perf_event_count; i++) {
        struct dfm_hwb_perf_event_state *event = &req->perf_events[i];
        struct dfm_hwb_slot_state *slots;
        uint32_t *matched;
        uint32_t count;
        uint32_t slot_index;

        if (!(event->flags & DFM_HWB_EVENT_F_ACTIVE))
            continue;
        if (event->oncpu >= 0 && event->oncpu != req->observed_cpu)
            continue;

        if (event->type == DFM_HWB_TYPE_X) {
            slots = req->brps;
            matched = &matched_brps;
            count = req->num_brps;
        } else {
            slots = req->wrps;
            matched = &matched_wrps;
            count = req->num_wrps;
        }

        for (slot_index = 0; slot_index < count; slot_index++) {
            struct dfm_hwb_slot_state *slot = &slots[slot_index];

            if (*matched & (1U << slot_index))
                continue;
            if (!dfm_hwb_slot_matches_event(slot, event))
                continue;

            *matched |= 1U << slot_index;
            event->slot = slot_index;
            slot->event_id = event->event_id;
            slot->flags |= DFM_HWB_SLOT_F_PERF;
            if (event->flags & DFM_HWB_EVENT_F_PTRACE)
                slot->flags |= DFM_HWB_SLOT_F_PTRACE;
            break;
        }
    }
}

static void dfm_hwb_clear_cpu_slots(uint32_t used_brps, uint32_t used_wrps)
{
    uint32_t i;

    for (i = 0; i < used_brps && i < DFM_HWB_MAX_HW_SLOTS; i++) {
        dfm_hwb_write_dbg_reg(DFM_HWB_DBG_BCR, i, 0);
        dfm_hwb_write_dbg_reg(DFM_HWB_DBG_BVR, i, 0);
    }
    for (i = 0; i < used_wrps && i < DFM_HWB_MAX_HW_SLOTS; i++) {
        dfm_hwb_write_dbg_reg(DFM_HWB_DBG_WCR, i, 0);
        dfm_hwb_write_dbg_reg(DFM_HWB_DBG_WVR, i, 0);
    }
}

struct dfm_hwb_cpu_clear_arg {
    uint32_t used_brps;
    uint32_t used_wrps;
    int disable_debug;
};

static void dfm_hwb_clear_cpu_cb(void *data)
{
    struct dfm_hwb_cpu_clear_arg *arg = data;

    dfm_hwb_clear_cpu_slots(arg->used_brps, arg->used_wrps);
    if (arg->disable_debug)
        dfm_hwb_disable_cpu();
}

static void dfm_hwb_install_current_cpu_locked(void)
{
    uint32_t i;
    int brp_slot = 0;
    int wrp_slot = 0;

    if (!g_hwb.configured)
        return;

    dfm_hwb_enable_cpu();

    for (i = 0; i < g_hwb.point_count; i++) {
        uint64_t addr;
        uint64_t ctrl;
        int is_exec;

        if (dfm_hwb_parse_point(&g_hwb.points[i], &addr, &ctrl, &is_exec))
            continue;

        if (is_exec) {
            if (brp_slot >= g_hwb.used_brps)
                continue;
            dfm_hwb_write_dbg_reg(DFM_HWB_DBG_BVR, brp_slot, addr);
            dfm_hwb_write_dbg_reg(DFM_HWB_DBG_BCR, brp_slot, ctrl | 0x1ULL);
            brp_slot++;
        } else {
            if (wrp_slot >= g_hwb.used_wrps)
                continue;
            dfm_hwb_write_dbg_reg(DFM_HWB_DBG_WVR, wrp_slot, addr);
            dfm_hwb_write_dbg_reg(DFM_HWB_DBG_WCR, wrp_slot, ctrl | 0x1ULL);
            wrp_slot++;
        }
    }
}

static void dfm_hwb_refresh_cpu_cb(void *data)
{
    unsigned long flags;
    int target_tid = *(int *)data;

    spin_lock_irqsave(&g_hwb_lock, flags);
    if (g_hwb.configured && current->pid == target_tid)
        dfm_hwb_install_current_cpu_locked();
    else
        dfm_hwb_clear_cpu_slots(g_hwb.used_brps, g_hwb.used_wrps);
    spin_unlock_irqrestore(&g_hwb_lock, flags);
}

static void dfm_hwb_record_hit(uint32_t point_index, uint64_t hit_addr,
                               uint64_t fault_addr, uint64_t esr,
                               struct pt_regs *regs)
{
    struct dfm_hwb_record rec;
    struct dfm_hwb_snapshot *snapshot;
    struct dfm_hwb_point_snapshot *point;
    unsigned long flags;
    uint32_t i;

    if (!regs || point_index >= DFM_HWB_MAX_POINTS)
        return;

    memset(&rec, 0, sizeof(rec));
    rec.point_index = point_index;
    rec.hit_addr = hit_addr;
    rec.fault_addr = fault_addr;
    rec.esr = esr;
    rec.pc = regs->pc;
    rec.lr = regs->regs[30];
    rec.sp = regs->sp;
    rec.pstate = regs->pstate;
    memcpy(rec.x, regs->regs, sizeof(rec.x));
    rec.fpsr = dfm_hwb_read_fpsr();
    rec.fpcr = dfm_hwb_read_fpcr();
    for (i = 0; i < 32; i++)
        dfm_hwb_read_q_reg(i, rec.q[i]);

    spin_lock_irqsave(&g_hwb_lock, flags);

    if (!g_hwb.configured || !g_hwb.snapshots[g_hwb.active_snapshot] ||
        point_index >= g_hwb.point_count) {
        spin_unlock_irqrestore(&g_hwb_lock, flags);
        return;
    }

    rec.type = g_hwb.points[point_index].type;
    snapshot = g_hwb.snapshots[g_hwb.active_snapshot];
    point = &snapshot->points[point_index];
    snapshot->total_hits++;

    for (i = 0; i < point->record_count && i < DFM_HWB_MAX_RECORDS; i++) {
        if (point->records[i].pc != rec.pc)
            continue;
        rec.hit_count = point->records[i].hit_count + 1;
        point->records[i] = rec;
        spin_unlock_irqrestore(&g_hwb_lock, flags);
        return;
    }

    if (point->record_count < DFM_HWB_MAX_RECORDS) {
        rec.hit_count = 1;
        point->records[point->record_count++] = rec;
    } else {
        point->overflow_count++;
    }

    spin_unlock_irqrestore(&g_hwb_lock, flags);
}

static int dfm_hwb_breakpoint_work(struct pt_regs *hook_regs)
{
    struct pt_regs *regs;
    unsigned long flags;
    int target_tid;
    int slot;
    uint32_t i;

    if (!hook_regs)
        return 0;

    regs = (struct pt_regs *)hook_regs->regs[2];
    if (!regs || !user_mode(regs))
        return 0;

    target_tid = READ_ONCE(g_hwb.target_tid);
    if (!READ_ONCE(g_hwb.configured) || current->pid != target_tid)
        return 0;

    spin_lock_irqsave(&g_hwb_lock, flags);
    if (!g_hwb.configured || current->pid != g_hwb.target_tid) {
        spin_unlock_irqrestore(&g_hwb_lock, flags);
        return 0;
    }

    for (slot = 0; slot < (int)g_hwb.used_brps; slot++) {
        uint64_t slot_addr = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_BVR, slot);
        uint64_t slot_ctrl = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_BCR, slot);

        if (!(slot_ctrl & 0x1ULL))
            continue;

        for (i = 0; i < g_hwb.point_count; i++) {
            uint64_t addr;
            uint64_t ctrl;
            int is_exec;

            if (dfm_hwb_parse_point(&g_hwb.points[i], &addr, &ctrl, &is_exec) ||
                !is_exec || addr != slot_addr ||
                (regs->pc & ~0x3ULL) != addr ||
                ((slot_ctrl & ~0x1ULL) != ctrl))
                continue;

            dfm_hwb_write_dbg_reg(DFM_HWB_DBG_BCR, slot, 0);
            dfm_hwb_write_dbg_reg(DFM_HWB_DBG_BVR, slot, 0);
            spin_unlock_irqrestore(&g_hwb_lock, flags);

            dfm_hwb_record_hit(i, regs->pc, regs->pc, hook_regs->regs[1], regs);
            hook_regs->regs[0] = 0;
            return 1;
        }
    }

    spin_unlock_irqrestore(&g_hwb_lock, flags);
    return 0;
}

static int dfm_hwb_watchpoint_work(struct pt_regs *hook_regs)
{
    struct pt_regs *regs;
    unsigned long flags;
    uint64_t fault_addr;
    uint64_t esr;
    uint64_t best_dist = ~0ULL;
    int best_slot = -1;
    int best_point = -1;
    int target_tid;
    int slot;
    uint32_t i;

    if (!hook_regs)
        return 0;

    fault_addr = hook_regs->regs[0];
    esr = hook_regs->regs[1];
    regs = (struct pt_regs *)hook_regs->regs[2];
    if (!regs || !user_mode(regs))
        return 0;

    target_tid = READ_ONCE(g_hwb.target_tid);
    if (!READ_ONCE(g_hwb.configured) || current->pid != target_tid)
        return 0;

    spin_lock_irqsave(&g_hwb_lock, flags);
    if (!g_hwb.configured || current->pid != g_hwb.target_tid) {
        spin_unlock_irqrestore(&g_hwb_lock, flags);
        return 0;
    }

    for (slot = 0; slot < (int)g_hwb.used_wrps; slot++) {
        uint64_t slot_addr = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_WVR, slot);
        uint64_t slot_ctrl = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_WCR, slot);

        if (!(slot_ctrl & 0x1ULL))
            continue;

        for (i = 0; i < g_hwb.point_count; i++) {
            uint64_t addr;
            uint64_t ctrl;
            int is_exec;
            uint32_t len_mask;
            uint64_t dist;

            if (dfm_hwb_parse_point(&g_hwb.points[i], &addr, &ctrl, &is_exec) ||
                is_exec || addr != slot_addr ||
                ((slot_ctrl & ~0x1ULL) != ctrl) ||
                !dfm_hwb_access_matches(g_hwb.points[i].type, esr))
                continue;

            len_mask = (uint32_t)((ctrl >> 5) & 0xFFU);
            dist = dfm_hwb_watch_distance(fault_addr, addr, len_mask);
            if (dist >= best_dist)
                continue;

            best_dist = dist;
            best_slot = slot;
            best_point = (int)i;
            if (dist == 0)
                break;
        }
        if (best_dist == 0)
            break;
    }

    if (best_point < 0) {
        spin_unlock_irqrestore(&g_hwb_lock, flags);
        return 0;
    }

    dfm_hwb_write_dbg_reg(DFM_HWB_DBG_WCR, best_slot, 0);
    dfm_hwb_write_dbg_reg(DFM_HWB_DBG_WVR, best_slot, 0);
    spin_unlock_irqrestore(&g_hwb_lock, flags);

    dfm_hwb_record_hit((uint32_t)best_point, regs->pc, fault_addr, esr, regs);
    hook_regs->regs[0] = 0;
    return 1;
}

static void dfm_hwb_clear_matching_current_cpu_locked(void)
{
    uint32_t brp_slot = 0;
    uint32_t wrp_slot = 0;
    uint32_t i;

    for (i = 0; i < g_hwb.point_count; i++) {
        uint64_t slot_addr;
        uint64_t slot_ctrl;
        uint64_t addr;
        uint64_t ctrl;
        int is_exec;

        if (dfm_hwb_parse_point(&g_hwb.points[i], &addr, &ctrl, &is_exec))
            continue;

        if (is_exec) {
            if (brp_slot >= g_hwb.used_brps)
                continue;
            slot_addr = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_BVR,
                                             (int)brp_slot);
            slot_ctrl = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_BCR,
                                             (int)brp_slot);
            if (slot_ctrl && slot_addr == addr &&
                ((slot_ctrl & ~0x1ULL) == ctrl)) {
                dfm_hwb_write_dbg_reg(DFM_HWB_DBG_BCR, (int)brp_slot, 0);
                dfm_hwb_write_dbg_reg(DFM_HWB_DBG_BVR, (int)brp_slot, 0);
            }
            brp_slot++;
        } else {
            if (wrp_slot >= g_hwb.used_wrps)
                continue;
            slot_addr = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_WVR,
                                             (int)wrp_slot);
            slot_ctrl = dfm_hwb_read_dbg_reg(DFM_HWB_DBG_WCR,
                                             (int)wrp_slot);
            if (slot_ctrl && slot_addr == addr &&
                ((slot_ctrl & ~0x1ULL) == ctrl)) {
                dfm_hwb_write_dbg_reg(DFM_HWB_DBG_WCR, (int)wrp_slot, 0);
                dfm_hwb_write_dbg_reg(DFM_HWB_DBG_WVR, (int)wrp_slot, 0);
            }
            wrp_slot++;
        }
    }
}

static void __attribute__((used, __noinline__))
dfm_hwb_finish_task_switch_return_work(
    struct dfm_hwb_finish_return_frame *frame);

__attribute__((naked, used))
static void dfm_hwb_finish_task_switch_return_trampoline(void)
{
    asm volatile(
        "str x0, [sp, #8]\n\t"
        "mov x0, sp\n\t"
        "bl dfm_hwb_finish_task_switch_return_work\n\t"
        "ldp x16, x0, [sp], #" DFM_HOOK_STR(DFM_HWB_HOOK_FRAME_BYTES) "\n\t"
        "ret x16\n\t");
}

static void __attribute__((used, __noinline__))
dfm_hwb_finish_task_switch_return_work(
    struct dfm_hwb_finish_return_frame *frame)
{
    unsigned long flags;
    uint64_t generation = frame ? READ_ONCE(frame->generation) : 0;

    spin_lock_irqsave(&g_hwb_lock, flags);
    if (g_hwb.configured && generation == g_hwb.generation) {
        if (current->pid == g_hwb.target_tid)
            dfm_hwb_install_current_cpu_locked();
        else
            dfm_hwb_clear_matching_current_cpu_locked();
    }
    spin_unlock_irqrestore(&g_hwb_lock, flags);

    if (atomic_dec_and_test(&g_hwb_finish_returns_inflight))
        wake_up_all(&g_hwb_finish_return_wait);
}

static int dfm_hwb_finish_task_switch_work(struct pt_regs *hook_regs)
{
    struct dfm_hwb_finish_return_frame *frame;
    unsigned long flags;

    if (!hook_regs)
        return 0;

    frame = dfm_hwb_hook_frame_metadata(hook_regs);
    if (!frame)
        return 0;

    spin_lock_irqsave(&g_hwb_lock, flags);
    if (g_hwb.configured) {
        frame->return_addr = hook_regs->regs[30];
        frame->return_x0 = 0;
        frame->generation = g_hwb.generation;
        frame->reserved = 0;
        atomic_inc(&g_hwb_finish_returns_inflight);
        hook_regs->sp = (unsigned long)frame;
        hook_regs->regs[30] =
            (unsigned long)dfm_hwb_finish_task_switch_return_trampoline;
    }
    spin_unlock_irqrestore(&g_hwb_lock, flags);
    return 0;
}

static struct dfm_hwb_hook_entry g_hwb_exception_hooks[] = {
    DFM_HWB_HOOK("breakpoint_handler", dfm_hwb_breakpoint_work),
    DFM_HWB_HOOK("watchpoint_handler", dfm_hwb_watchpoint_work),
};

static struct dfm_hwb_hook_entry g_hwb_finish_hooks[] = {
    DFM_HWB_HOOK("finish_task_switch", dfm_hwb_finish_task_switch_work),
};

static int dfm_hwb_hooks_install_locked(void)
{
    int ret;

    if (g_hwb.hooks_installed)
        return 0;

    ret = dfm_hwb_hook_install_many(g_hwb_exception_hooks,
                                    ARRAY_SIZE(g_hwb_exception_hooks));
    if (ret)
        return ret;

    ret = dfm_hwb_hook_install_many(g_hwb_finish_hooks,
                                    ARRAY_SIZE(g_hwb_finish_hooks));
    if (ret) {
        dfm_hwb_hook_remove_many(g_hwb_exception_hooks,
                                 ARRAY_SIZE(g_hwb_exception_hooks));
        return ret;
    }

    g_hwb.hooks_installed = 1;
    return 0;
}

static void dfm_hwb_hooks_remove_locked(void)
{
    if (!g_hwb.hooks_installed)
        return;

    dfm_hwb_hook_remove_many(g_hwb_finish_hooks, ARRAY_SIZE(g_hwb_finish_hooks));
    /*
     * finish_task_switch() runs before __schedule() reenables preemption.
     * The grace period drains CPUs that entered the patched entry before it
     * was restored; the counter then drains every redirected return frame.
     */
    synchronize_rcu();
    wait_event(g_hwb_finish_return_wait,
               atomic_read(&g_hwb_finish_returns_inflight) == 0);
    dfm_hwb_hook_remove_many(g_hwb_exception_hooks,
                             ARRAY_SIZE(g_hwb_exception_hooks));
    g_hwb.hooks_installed = 0;
}

static void dfm_hwb_stop_locked(void)
{
    struct dfm_hwb_cpu_clear_arg arg;
    unsigned long flags;
    int cpu;

    spin_lock_irqsave(&g_hwb_lock, flags);
    g_hwb.generation++;
    if (!g_hwb.generation)
        g_hwb.generation = 1;
    arg.used_brps = g_hwb.used_brps;
    arg.used_wrps = g_hwb.used_wrps;
    arg.disable_debug = 1;
    g_hwb.configured = 0;
    spin_unlock_irqrestore(&g_hwb_lock, flags);

    if (arg.used_brps || arg.used_wrps) {
        for_each_online_cpu(cpu)
            smp_call_function_single(cpu, dfm_hwb_clear_cpu_cb, &arg, 1);
    }

    dfm_hwb_hooks_remove_locked();

    spin_lock_irqsave(&g_hwb_lock, flags);
    g_hwb.target_tid = 0;
    g_hwb.owner = NULL;
    g_hwb.point_count = 0;
    g_hwb.used_brps = 0;
    g_hwb.used_wrps = 0;
    memset(g_hwb.points, 0, sizeof(g_hwb.points));
    spin_unlock_irqrestore(&g_hwb_lock, flags);
}

long dfm_hwb_info(void __user *arg)
{
    struct dfm_hwb_info_req req;

    memset(&req, 0, sizeof(req));
    req.num_brps = (uint32_t)dfm_hwb_get_brps();
    req.num_wrps = (uint32_t)dfm_hwb_get_wrps();
    req.max_points = DFM_HWB_MAX_POINTS;
    req.max_records = DFM_HWB_MAX_RECORDS;

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;
    return 0;
}

long dfm_hwb_slots(void __user *arg)
{
    struct dfm_hwb_slots_req *req;
    struct task_struct *task;
    struct mm_struct *mm;
    int target_tid;
    long ret = 0;

    if (copy_from_user(&target_tid, arg, sizeof(target_tid)))
        return -EFAULT;
    if (target_tid <= 0)
        return -EINVAL;

    req = kzalloc(sizeof(*req), GFP_KERNEL);
    if (!req)
        return -ENOMEM;

    req->target_tid = target_tid;
    req->task_cpu = -1;
    req->observed_cpu = -1;
    req->num_brps = (uint32_t)dfm_hwb_get_brps();
    req->num_wrps = (uint32_t)dfm_hwb_get_wrps();

    task = dfm_hwb_get_task(target_tid);
    if (!task) {
        ret = -ESRCH;
        goto out_free;
    }

    mm = get_task_mm(task);
    if (!mm) {
        ret = -ESRCH;
        goto out_task;
    }
    mmput(mm);

    dfm_hwb_capture_perf_events(req, task);
    dfm_hwb_capture_cpu_slots(req, task);
    dfm_hwb_correlate_perf_slots(req);

    if (copy_to_user(arg, req, sizeof(*req)))
        ret = -EFAULT;

out_task:
    put_task_struct(task);
out_free:
    kfree(req);
    return ret;
}

long dfm_hwb_set(struct file *owner, void __user *arg)
{
    struct dfm_hwb_set_req req;
    struct dfm_hwb_point_req points[DFM_HWB_MAX_POINTS];
    uint32_t i;
    uint32_t brps_needed = 0;
    uint32_t wrps_needed = 0;
    int brps;
    int wrps;
    int ret;
    unsigned long flags;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.target_tid <= 0 || req.point_count == 0 ||
        req.point_count > DFM_HWB_MAX_POINTS)
        return -EINVAL;
    if (!dfm_hwb_tid_alive(req.target_tid))
        return -ESRCH;

    brps = dfm_hwb_get_brps();
    wrps = dfm_hwb_get_wrps();

    for (i = 0; i < req.point_count; i++) {
        uint64_t addr;
        uint64_t ctrl;
        int is_exec;

        points[i] = req.points[i];
        ret = dfm_hwb_parse_point(&points[i], &addr, &ctrl, &is_exec);
        if (ret)
            return ret;

        if (is_exec)
            brps_needed++;
        else
            wrps_needed++;
    }

    if (brps_needed > (uint32_t)brps || wrps_needed > (uint32_t)wrps)
        return -ENOSPC;

    mutex_lock(&g_hwb_mutex);

    dfm_hwb_stop_locked();

    ret = dfm_hwb_alloc_snapshots_locked();
    if (ret)
        goto out_unlock;

    ret = dfm_hwb_hooks_install_locked();
    if (ret)
        goto out_unlock;

    spin_lock_irqsave(&g_hwb_lock, flags);
    g_hwb.target_tid = req.target_tid;
    g_hwb.owner = owner;
    g_hwb.point_count = req.point_count;
    g_hwb.used_brps = brps_needed;
    g_hwb.used_wrps = wrps_needed;
    memset(g_hwb.points, 0, sizeof(g_hwb.points));
    memcpy(g_hwb.points, points, sizeof(points[0]) * req.point_count);
    g_hwb.active_snapshot = 0;
    g_hwb.configured = 1;
    dfm_hwb_reset_snapshot(g_hwb.snapshots[0]);
    dfm_hwb_reset_snapshot(g_hwb.snapshots[1]);
    spin_unlock_irqrestore(&g_hwb_lock, flags);

    on_each_cpu(dfm_hwb_refresh_cpu_cb, &req.target_tid, 1);

out_unlock:
    if (ret)
        dfm_hwb_stop_locked();
    mutex_unlock(&g_hwb_mutex);
    return ret;
}

long dfm_hwb_read(void __user *arg)
{
    struct dfm_hwb_read_req req;
    struct dfm_hwb_snapshot *out;
    int old_idx;
    int new_idx;
    unsigned long flags;
    long ret = 0;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    req.out_size = sizeof(struct dfm_hwb_snapshot);
    if (!req.buf || req.buf_size < req.out_size) {
        if (copy_to_user(arg, &req, sizeof(req)))
            return -EFAULT;
        return -ENOSPC;
    }

    mutex_lock(&g_hwb_mutex);

    if (!g_hwb.snapshots[0] || !g_hwb.snapshots[1]) {
        ret = -ENOENT;
        goto out_unlock;
    }

    new_idx = 1 - g_hwb.active_snapshot;
    dfm_hwb_reset_snapshot(g_hwb.snapshots[new_idx]);

    spin_lock_irqsave(&g_hwb_lock, flags);
    old_idx = g_hwb.active_snapshot;
    g_hwb.active_snapshot = new_idx;
    spin_unlock_irqrestore(&g_hwb_lock, flags);

    out = g_hwb.snapshots[old_idx];
    if (out->target_tid > 0 && !dfm_hwb_tid_alive(out->target_tid))
        out->flags |= DFM_HWB_SNAPSHOT_TARGET_MISSING;

    if (copy_to_user((void __user *)(uintptr_t)req.buf, out, sizeof(*out)))
        ret = -EFAULT;

out_unlock:
    mutex_unlock(&g_hwb_mutex);
    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;
    return ret;
}

long dfm_hwb_clear(void)
{
    mutex_lock(&g_hwb_mutex);
    dfm_hwb_stop_locked();
    if (g_hwb.snapshots[0])
        memset(g_hwb.snapshots[0], 0, sizeof(struct dfm_hwb_snapshot));
    if (g_hwb.snapshots[1])
        memset(g_hwb.snapshots[1], 0, sizeof(struct dfm_hwb_snapshot));
    mutex_unlock(&g_hwb_mutex);
    return 0;
}

void dfm_hwb_release_owner(struct file *owner)
{
    int should_clear;
    unsigned long flags;

    if (!owner)
        return;

    spin_lock_irqsave(&g_hwb_lock, flags);
    should_clear = g_hwb.configured && g_hwb.owner == owner;
    spin_unlock_irqrestore(&g_hwb_lock, flags);

    if (!should_clear)
        return;

    mutex_lock(&g_hwb_mutex);
    spin_lock_irqsave(&g_hwb_lock, flags);
    should_clear = g_hwb.configured && g_hwb.owner == owner;
    spin_unlock_irqrestore(&g_hwb_lock, flags);
    if (should_clear)
        dfm_hwb_stop_locked();
    mutex_unlock(&g_hwb_mutex);
}

void dfm_hwb_exit(void)
{
    mutex_lock(&g_hwb_mutex);
    dfm_hwb_stop_locked();
    vfree(g_hwb.snapshots[0]);
    vfree(g_hwb.snapshots[1]);
    g_hwb.snapshots[0] = NULL;
    g_hwb.snapshots[1] = NULL;
    mutex_unlock(&g_hwb_mutex);
}
