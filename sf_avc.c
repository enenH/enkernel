// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) KBUILD_MODNAME ": sf_avc: " fmt

#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#include "sf_avc.h"

#ifndef __nocfi
#define __nocfi
#endif

#if defined(CONFIG_SECURITY_SELINUX) && defined(CONFIG_KRETPROBES)
/* Use the target kernel's declarations, including its gfp_t/CFI types. */
#include "avc.h"

static const char sf_context[] = "u:r:surfaceflinger:s0";
static const char netd_context[] = "u:r:netd:s0";
static u32 sf_sid;
static u32 netd_sid;
static bool sf_registered;
static struct kretprobe sf_probe;

/* The selinux_state argument was removed in Linux 6.4. The supported GKI
 * families are 5.10/5.15/6.1 and 6.6/6.12/6.18 respectively. Check the public
 * AVC declaration at build time as well, so a backport cannot silently use
 * the wrong SID registers. Only the source and target SIDs are read. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
#define DFM_AVC_SSID_REG 1
typedef int (*dfm_avc_noaudit_t)(struct selinux_state *, u32, u32, u16,
                               u32, unsigned int, struct av_decision *);
#else
#define DFM_AVC_SSID_REG 0
typedef int (*dfm_avc_noaudit_t)(u32, u32, u16, u32, unsigned int,
                               struct av_decision *);
#endif
static_assert(__same_type(typeof(&avc_has_perm_noaudit), dfm_avc_noaudit_t),
              "Unsupported SELinux AVC argument layout");

/* Resolve and verify the exact context in sleepable module-init context.
 * No allocation, policy lookup, credential change or name lookup occurs in
 * either probe handler. A pre-policy fallback SID must not be accepted. */
static int __nocfi sf_resolve_sid(const char *expected_context,
                                u32 expected_length, u32 *sid)
{
    typeof(&security_context_to_sid) context_to_sid;
    typeof(&security_sid_to_context) sid_to_context;
    char *context = NULL;
    u32 context_len = 0;
    int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    struct selinux_state *state;

    state = (void *)kallsyms_lookup_name("selinux_state");
    if (!state)
        return -ENOENT;
#endif

    context_to_sid = (void *)kallsyms_lookup_name("security_context_to_sid");
    sid_to_context = (void *)kallsyms_lookup_name("security_sid_to_context");
    if (!context_to_sid || !sid_to_context)
        return -ENOENT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    ret = context_to_sid(state, expected_context, expected_length, sid, GFP_KERNEL);
#else
    ret = context_to_sid(expected_context, expected_length, sid, GFP_KERNEL);
#endif
    if (ret)
        return ret;
    if (!*sid || *sid == SECSID_WILD)
        return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    ret = sid_to_context(state, *sid, &context, &context_len);
#else
    ret = sid_to_context(*sid, &context, &context_len);
#endif
    if (!ret && (!context || context_len != expected_length ||
                 memcmp(context, expected_context, expected_length)))
        ret = -EINVAL;
    kfree(context);
    return ret;
}

static int sf_avc_enter(struct kretprobe_instance *instance, struct pt_regs *regs)
{
    const u32 sid = READ_ONCE(sf_sid);
    const u32 network_sid = READ_ONCE(netd_sid);
    const u32 source = (u32)regs->regs[DFM_AVC_SSID_REG];

    /* Match the AVC subject, not current->comm/current credentials or tsid:
     * socket/file subjects may differ from the currently executing task. */
    if (sid && source == sid)
        return 0;
    /* fwmarkd must receive and operate on SF-labelled socket descriptors.
     * The explicitly supported reverse direction covers every AVC class
     * and permission, but only the exact netd source and SF target pair. */
    return sid && network_sid && source == network_sid &&
           (u32)regs->regs[DFM_AVC_SSID_REG + 1] == sid ? 0 : 1;
}
NOKPROBE_SYMBOL(sf_avc_enter);

static int sf_avc_return(struct kretprobe_instance *instance, struct pt_regs *regs)
{
    /* Entry admitted the SF source or the exact netd->SF SID pair.
     * As in kernel_draw's VFS probe, keep the native ABI/PAC return path and
     * leave av_decision, AVC caches, policy and audit handling untouched. */
    if ((int)regs_return_value(regs) == -EACCES)
        regs_set_return_value(regs, 0);
    return 0;
}
NOKPROBE_SYMBOL(sf_avc_return);

int dfm_sf_avc_init(void)
{
    u32 sid = 0;
    u32 network_sid = 0;
    int ret;

    if (sf_registered)
        return 0;
    ret = sf_resolve_sid(sf_context, sizeof(sf_context), &sid);
    if (ret) {
        pr_err("cannot resolve %s: %d\n", sf_context, ret);
        return ret;
    }
    ret = sf_resolve_sid(netd_context, sizeof(netd_context), &network_sid);
    if (ret) {
        pr_err("cannot resolve %s: %d\n", netd_context, ret);
        return ret;
    }
    WRITE_ONCE(sf_sid, sid);
    WRITE_ONCE(netd_sid, network_sid);
    sf_probe = (struct kretprobe) {
        .kp.symbol_name = "avc_denied",
        .entry_handler = sf_avc_enter,
        .handler = sf_avc_return,
        /* Exhaustion retains the original denial; it never broadens scope. */
        .maxactive = 256,
    };
    ret = register_kretprobe(&sf_probe);
    if (ret) {
        WRITE_ONCE(sf_sid, 0);
        WRITE_ONCE(netd_sid, 0);
        pr_err("avc_denied probe registration failed: %d\n", ret);
        return ret;
    }
    WRITE_ONCE(sf_registered, true);
    pr_info("avc_denied enabled for source %s (sid=%u), "
            "netd (sid=%u) socket handoff ready\n", sf_context, sid,
            network_sid);
    return 0;
}

void dfm_sf_avc_exit(void)
{
    if (!sf_registered)
        return;
    WRITE_ONCE(sf_registered, false);
    unregister_kretprobe(&sf_probe);
    if (sf_probe.nmissed || sf_probe.kp.nmissed)
        pr_warn("missed return=%d entry=%lu; original decisions retained\n",
                sf_probe.nmissed, sf_probe.kp.nmissed);
    WRITE_ONCE(sf_sid, 0);
    WRITE_ONCE(netd_sid, 0);
}

bool dfm_sf_avc_ready(void)
{
    return READ_ONCE(sf_registered);
}
#else
int dfm_sf_avc_init(void)
{
    pr_err("SELinux and return probes are required\n");
    return -EOPNOTSUPP;
}

void dfm_sf_avc_exit(void) {}
bool dfm_sf_avc_ready(void) { return false; }
#endif
