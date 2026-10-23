#define pr_fmt(fmt) KBUILD_MODNAME ": touch-v2: " fmt

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/input.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "abi.h"
#include "touch_v2.h"

/*
 * Touch Aim V2 follows the event-pool design from the supplied kernel
 * touch.h: user requests are cached, then spliced into the real touchscreen
 * stream immediately before its next SYN_REPORT.  The existing read-proxy
 * backend in touch.c remains independent and unchanged.
 */
#define TOUCH_V2_MAX_SLOTS  10
#define TOUCH_V2_MAX_EVENTS 1024
#define TOUCH_V2_TRACKING_BASE 666

struct touch_v2_cached_event {
    unsigned int type;
    unsigned int code;
    int value;
};

static DEFINE_SPINLOCK(g_touch_v2_pool_lock);
static struct touch_v2_cached_event
    g_touch_v2_events[TOUCH_V2_MAX_EVENTS];
static unsigned int g_touch_v2_event_count;
static bool g_touch_v2_slot_active[TOUCH_V2_MAX_SLOTS];

static DEFINE_MUTEX(g_touch_v2_init_lock);
static atomic_t g_touch_v2_draining = ATOMIC_INIT(0);
static struct kprobe g_touch_v2_input_event_kp;
static struct kprobe g_touch_v2_input_inject_event_kp;
static bool g_touch_v2_input_event_registered;
static bool g_touch_v2_input_inject_event_registered;

static bool touch_v2_is_touchscreen(struct input_dev *dev)
{
    if (!dev)
        return false;

    return test_bit(EV_ABS, dev->evbit) &&
           test_bit(ABS_MT_SLOT, dev->absbit) &&
           test_bit(ABS_MT_TRACKING_ID, dev->absbit) &&
           test_bit(ABS_MT_POSITION_X, dev->absbit) &&
           test_bit(ABS_MT_POSITION_Y, dev->absbit) &&
           test_bit(EV_KEY, dev->evbit) &&
           (test_bit(BTN_TOUCH, dev->keybit) ||
            test_bit(BTN_TOOL_FINGER, dev->keybit));
}

static bool touch_v2_make_room_locked(unsigned int needed)
{
    if (needed > TOUCH_V2_MAX_EVENTS)
        return false;

    if (g_touch_v2_event_count + needed > TOUCH_V2_MAX_EVENTS) {
        /* Match the reference event-pool recovery: discard a stale full
         * batch and keep accepting the newest aim state. Reset the announced
         * slots too, so the next down is a complete tracking-id frame rather
         * than an orphaned position-only move. */
        g_touch_v2_event_count = 0;
        memset(g_touch_v2_slot_active, 0,
               sizeof(g_touch_v2_slot_active));
        pr_warn_ratelimited("event pool full; stale batch discarded\n");
        return true;
    }

    return false;
}

static void touch_v2_append_locked(unsigned int type,
                                   unsigned int code, int value)
{
    struct touch_v2_cached_event *event;

    if (g_touch_v2_event_count >= TOUCH_V2_MAX_EVENTS)
        return;

    event = &g_touch_v2_events[g_touch_v2_event_count++];
    event->type = type;
    event->code = code;
    event->value = value;
}

static void touch_v2_queue_down_locked(int slot, int x, int y)
{
    bool first_down = !g_touch_v2_slot_active[slot];

    if (touch_v2_make_room_locked(first_down ? 8U : 3U))
        first_down = true;
    touch_v2_append_locked(EV_ABS, ABS_MT_SLOT, slot);

    if (first_down) {
        touch_v2_append_locked(EV_ABS, ABS_MT_TRACKING_ID,
                               TOUCH_V2_TRACKING_BASE + slot);
        touch_v2_append_locked(EV_ABS, ABS_MT_TOOL_TYPE,
                               MT_TOOL_FINGER);
    }

    touch_v2_append_locked(EV_ABS, ABS_MT_POSITION_X, x);
    touch_v2_append_locked(EV_ABS, ABS_MT_POSITION_Y, y);

    if (first_down) {
        touch_v2_append_locked(EV_ABS, ABS_MT_PRESSURE, 30);
        touch_v2_append_locked(EV_ABS, ABS_MT_TOUCH_MAJOR, 30);
        touch_v2_append_locked(EV_ABS, ABS_MT_TOUCH_MINOR, 30);
    }

    g_touch_v2_slot_active[slot] = true;
}

static void touch_v2_queue_up_locked(int slot)
{
    if (!g_touch_v2_slot_active[slot])
        return;

    (void)touch_v2_make_room_locked(2U);
    touch_v2_append_locked(EV_ABS, ABS_MT_SLOT, slot);
    touch_v2_append_locked(EV_ABS, ABS_MT_TRACKING_ID, -1);
    g_touch_v2_slot_active[slot] = false;
}

static void touch_v2_flush_on_sync(struct input_dev *dev)
{
    unsigned long flags;
    unsigned int i;

    if (!touch_v2_is_touchscreen(dev))
        return;

    /* input_event() below re-enters the probed symbol.  Kprobes normally
     * suppresses a nested pre-handler; this guard also makes that assumption
     * explicit and prevents a second CPU from draining the same batch. */
    if (atomic_cmpxchg(&g_touch_v2_draining, 0, 1) != 0)
        return;

    spin_lock_irqsave(&g_touch_v2_pool_lock, flags);
    for (i = 0; i < g_touch_v2_event_count; ++i) {
        const struct touch_v2_cached_event *event =
            &g_touch_v2_events[i];
        input_event(dev, event->type, event->code, event->value);
    }
    g_touch_v2_event_count = 0;
    spin_unlock_irqrestore(&g_touch_v2_pool_lock, flags);

    atomic_set(&g_touch_v2_draining, 0);
}

static int touch_v2_input_event_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct input_dev *dev = (struct input_dev *)regs->regs[0];
    unsigned int type = (unsigned int)regs->regs[1];
    unsigned int code = (unsigned int)regs->regs[2];

    if (type == EV_SYN && code == SYN_REPORT)
        touch_v2_flush_on_sync(dev);
    return 0;
}

static int touch_v2_input_inject_event_pre(struct kprobe *p,
                                           struct pt_regs *regs)
{
    struct input_handle *handle =
        (struct input_handle *)regs->regs[0];
    unsigned int type = (unsigned int)regs->regs[1];
    unsigned int code = (unsigned int)regs->regs[2];

    if (handle && type == EV_SYN && code == SYN_REPORT)
        touch_v2_flush_on_sync(handle->dev);
    return 0;
}

static int touch_v2_register_hooks_locked(void)
{
    int event_ret = 0;
    int inject_ret = 0;

    if (g_touch_v2_input_event_registered ||
        g_touch_v2_input_inject_event_registered)
        return 0;

    memset(&g_touch_v2_input_event_kp, 0,
           sizeof(g_touch_v2_input_event_kp));
    g_touch_v2_input_event_kp.symbol_name = "input_event";
    g_touch_v2_input_event_kp.pre_handler = touch_v2_input_event_pre;
    event_ret = register_kprobe(&g_touch_v2_input_event_kp);
    if (!event_ret)
        g_touch_v2_input_event_registered = true;
    else
        pr_warn("register input_event kprobe failed: %d\n", event_ret);

    memset(&g_touch_v2_input_inject_event_kp, 0,
           sizeof(g_touch_v2_input_inject_event_kp));
    g_touch_v2_input_inject_event_kp.symbol_name = "input_inject_event";
    g_touch_v2_input_inject_event_kp.pre_handler =
        touch_v2_input_inject_event_pre;
    inject_ret = register_kprobe(&g_touch_v2_input_inject_event_kp);
    if (!inject_ret)
        g_touch_v2_input_inject_event_registered = true;
    else
        pr_warn("register input_inject_event kprobe failed: %d\n",
                inject_ret);

    /* Real panel drivers report through input_event(), so that probe is the
     * required clock for this backend. input_inject_event() is supplemental;
     * accepting it alone would report init success but never drain hardware
     * touch frames on normal devices. */
    if (!g_touch_v2_input_event_registered) {
        if (g_touch_v2_input_inject_event_registered) {
            unregister_kprobe(&g_touch_v2_input_inject_event_kp);
            g_touch_v2_input_inject_event_registered = false;
        }
        return event_ret ? event_ret : -ENOENT;
    }

    pr_info("event-pool hooks ready input_event=%d input_inject_event=%d\n",
            g_touch_v2_input_event_registered ? 1 : 0,
            g_touch_v2_input_inject_event_registered ? 1 : 0);
    return 0;
}

long touch_v2_init(void)
{
    int ret;

    mutex_lock(&g_touch_v2_init_lock);
    ret = touch_v2_register_hooks_locked();
    mutex_unlock(&g_touch_v2_init_lock);
    return ret;
}

long touch_v2_event(void __user *arg)
{
    struct touch_event_req req;
    unsigned long flags;
    int ret;

    if (!arg)
        return -EINVAL;
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.slot < 0 || req.slot >= TOUCH_V2_MAX_SLOTS)
        return -EINVAL;

    ret = touch_v2_init();
    if (ret < 0)
        return ret;

    spin_lock_irqsave(&g_touch_v2_pool_lock, flags);
    if (req.down)
        touch_v2_queue_down_locked(req.slot, req.x, req.y);
    else
        touch_v2_queue_up_locked(req.slot);
    spin_unlock_irqrestore(&g_touch_v2_pool_lock, flags);
    return 0;
}

void touch_v2_release_all(void)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&g_touch_v2_pool_lock, flags);
    for (i = 0; i < TOUCH_V2_MAX_SLOTS; ++i)
        touch_v2_queue_up_locked(i);
    spin_unlock_irqrestore(&g_touch_v2_pool_lock, flags);
}

void touch_v2_exit(void)
{
    unsigned long flags;

    mutex_lock(&g_touch_v2_init_lock);
    if (g_touch_v2_input_inject_event_registered) {
        unregister_kprobe(&g_touch_v2_input_inject_event_kp);
        g_touch_v2_input_inject_event_registered = false;
    }
    if (g_touch_v2_input_event_registered) {
        unregister_kprobe(&g_touch_v2_input_event_kp);
        g_touch_v2_input_event_registered = false;
    }
    mutex_unlock(&g_touch_v2_init_lock);

    spin_lock_irqsave(&g_touch_v2_pool_lock, flags);
    g_touch_v2_event_count = 0;
    memset(g_touch_v2_slot_active, 0, sizeof(g_touch_v2_slot_active));
    spin_unlock_irqrestore(&g_touch_v2_pool_lock, flags);
    atomic_set(&g_touch_v2_draining, 0);
}
