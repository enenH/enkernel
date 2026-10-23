#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/input.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "abi.h"
#include "touch.h"

#define TOUCH_MAX_SLOTS 10
#define TOUCH_MAX_EVENTS 256
#define TOUCH_CUSTOM_TRACKING_BASE 666

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
struct evdev {
    int open;
    struct input_handle handle;
    wait_queue_head_t wait;
    struct evdev_client __rcu *grab;
    struct list_head client_list;
    spinlock_t client_lock;
    struct mutex mutex;
    struct device dev;
    struct cdev cdev;
    bool exist;
};

struct evdev_client {
    unsigned int head;
    unsigned int tail;
    unsigned int packet_head;
    spinlock_t buffer_lock;
    struct fasync_struct *fasync;
    struct evdev *evdev;
    struct list_head node;
    unsigned int clk_type;
    bool revoked;
    unsigned long *evmasks[EV_CNT];
    unsigned int bufsize;
    struct input_event buffer[];
};
#else
struct evdev {
    int open;
    struct input_handle handle;
    struct evdev_client __rcu *grab;
    struct list_head client_list;
    spinlock_t client_lock;
    struct mutex mutex;
    struct device dev;
    struct cdev cdev;
    bool exist;
};

struct evdev_client {
    unsigned int head;
    unsigned int tail;
    unsigned int packet_head;
    spinlock_t buffer_lock;
    wait_queue_head_t wait;
    struct fasync_struct *fasync;
    struct evdev *evdev;
    struct list_head node;
    enum input_clock_type clk_type;
    bool revoked;
    unsigned long *evmasks[EV_CNT];
    unsigned int bufsize;
    struct input_event buffer[];
};
#endif

struct touch_slot_state {
    bool active;
    bool is_custom;
    int tracking_id;
    int x;
    int y;
    bool dirty;
};

struct touch_event_list {
    struct input_event events[TOUCH_MAX_EVENTS];
    int count;
};

struct touch_device_caps {
    bool has_mt_slot;
    bool has_mt_tracking_id;
    bool has_mt_touch_major;
    bool has_mt_pressure;
    bool has_btn_touch;
    bool has_btn_tool_finger;
};

static DEFINE_MUTEX(g_touch_lock);
static struct touch_slot_state g_touch_slots[TOUCH_MAX_SLOTS];
static int g_touch_current_slot;
static bool g_touch_slots_initialized;
static struct input_dev *g_touch_input_dev;
static struct touch_device_caps g_touch_device_caps;
static ssize_t (*g_touch_orig_read)(struct file *, char __user *, size_t, loff_t *);
static struct file_operations g_touch_proxy_fops;
static struct work_struct g_touch_stop_read_work;
static bool g_touch_stop_work_initialized;
static bool g_touch_read_hook_registered;
static bool g_touch_proxy_installed;
static struct input_event g_touch_read_events[TOUCH_MAX_EVENTS];
static struct touch_event_list g_touch_final_events;

/* Cross-boundary snapshot (see abi.h struct touch_status) for user-side
 * verification. Fill on successful install; bump reject counters on the fail
 * paths so a stuck hook still shows *why*. Kept under g_touch_lock; a full copy
 * lives in the struct so user copy_to_user reads a coherent view. */
static struct touch_status g_touch_status;

static bool touch_test_bit(int bit, const unsigned long *array)
{
    return (array[bit / BITS_PER_LONG] >> (bit % BITS_PER_LONG)) & 1UL;
}

static void touch_cache_device_caps(struct input_dev *idev)
{
    memset(&g_touch_device_caps, 0, sizeof(g_touch_device_caps));

    if (!idev)
        return;

    g_touch_device_caps.has_mt_slot =
        touch_test_bit(ABS_MT_SLOT, idev->absbit);
    g_touch_device_caps.has_mt_tracking_id =
        touch_test_bit(ABS_MT_TRACKING_ID, idev->absbit);
    g_touch_device_caps.has_mt_touch_major =
        touch_test_bit(ABS_MT_TOUCH_MAJOR, idev->absbit);
    g_touch_device_caps.has_mt_pressure =
        touch_test_bit(ABS_MT_PRESSURE, idev->absbit);
    g_touch_device_caps.has_btn_touch =
        touch_test_bit(BTN_TOUCH, idev->keybit);
    g_touch_device_caps.has_btn_tool_finger =
        touch_test_bit(BTN_TOOL_FINGER, idev->keybit);
}

static void touch_init_slots_locked(void)
{
    int i;

    if (g_touch_slots_initialized)
        return;

    for (i = 0; i < TOUCH_MAX_SLOTS; ++i) {
        g_touch_slots[i].tracking_id = -1;
        g_touch_slots[i].x = 0;
        g_touch_slots[i].y = 0;
        g_touch_slots[i].active = false;
        g_touch_slots[i].is_custom = false;
        g_touch_slots[i].dirty = false;
    }

    g_touch_current_slot = 0;
    g_touch_slots_initialized = true;
}

static void touch_signal_device_locked(void)
{
    if (!g_touch_input_dev)
        return;

    input_event(g_touch_input_dev, EV_SYN, SYN_CONFIG, 0);
    input_event(g_touch_input_dev, EV_SYN, SYN_REPORT, 0);
}

static int touch_move_slot_locked(int slot, int x, int y)
{
    if (slot < 0 || slot >= TOUCH_MAX_SLOTS)
        return -EINVAL;

    touch_init_slots_locked();

    g_touch_slots[slot].active = true;
    g_touch_slots[slot].is_custom = true;
    g_touch_slots[slot].x = x;
    g_touch_slots[slot].y = y;
    g_touch_slots[slot].tracking_id = slot + TOUCH_CUSTOM_TRACKING_BASE;
    g_touch_slots[slot].dirty = true;
    touch_signal_device_locked();
    return 0;
}

static int touch_release_slot_locked(int slot)
{
    if (slot < 0 || slot >= TOUCH_MAX_SLOTS)
        return -EINVAL;

    touch_init_slots_locked();

    if (g_touch_slots[slot].active || g_touch_slots[slot].tracking_id != -1) {
        g_touch_slots[slot].active = false;
        g_touch_slots[slot].is_custom = true;
        g_touch_slots[slot].tracking_id = -1;
        g_touch_slots[slot].dirty = true;
        touch_signal_device_locked();
    }

    return 0;
}

static void touch_append_event(struct touch_event_list *list,
                                   const struct input_event *src_event,
                                   __u16 type, __u16 code, __s32 value)
{
    if (list->count >= TOUCH_MAX_EVENTS)
        return;

    if (src_event) {
        list->events[list->count].input_event_sec = src_event->input_event_sec;
        list->events[list->count].input_event_usec = src_event->input_event_usec;
    } else {
        list->events[list->count].input_event_sec = 0;
        list->events[list->count].input_event_usec = 0;
    }

    list->events[list->count].type = type;
    list->events[list->count].code = code;
    list->events[list->count].value = value;
    list->count++;
}

static ssize_t touch_read_proxy(struct file *file, char __user *buf,
                                    size_t count, loff_t *pos)
{
    static bool first_down;
    struct evdev_client *client = file->private_data;
    struct input_event *time_template = NULL;
    int current_slot;
    int any_active = 0;
    int num_events;
    int i;
    ssize_t ret;
    size_t copy_size;

    if (!client || !g_touch_orig_read)
        return -EINVAL;

    mutex_lock(&g_touch_lock);
    touch_init_slots_locked();

    if (!g_touch_input_dev)
        g_touch_input_dev = client->evdev->handle.dev;

    ret = g_touch_orig_read(file, buf, count, pos);
    if (ret <= 0 || (ret % sizeof(struct input_event)) != 0) {
        mutex_unlock(&g_touch_lock);
        return ret;
    }

    num_events = ret / sizeof(struct input_event);
    if (num_events > TOUCH_MAX_EVENTS) {
        mutex_unlock(&g_touch_lock);
        return ret;
    }

    copy_size = (size_t)ret;
    memset(g_touch_read_events, 0, sizeof(g_touch_read_events));
    memset(&g_touch_final_events, 0, sizeof(g_touch_final_events));

    if (copy_from_user(g_touch_read_events, buf, copy_size)) {
        mutex_unlock(&g_touch_lock);
        return -EFAULT;
    }

    current_slot = g_touch_current_slot;
    for (i = 0; i < num_events; ++i) {
        struct input_event *event = &g_touch_read_events[i];

        if (event->type == EV_ABS && event->code == ABS_MT_SLOT) {
            if (event->value >= 0 && event->value < TOUCH_MAX_SLOTS)
                current_slot = event->value;
            continue;
        }

        if (current_slot < 0 || current_slot >= TOUCH_MAX_SLOTS)
            continue;

        if (event->type == EV_ABS &&
            (event->code == ABS_MT_TRACKING_ID ||
             event->code == ABS_MT_POSITION_X ||
             event->code == ABS_MT_POSITION_Y)) {
            g_touch_slots[current_slot].dirty = true;

            if (event->code == ABS_MT_TRACKING_ID) {
                g_touch_slots[current_slot].tracking_id = event->value;
                g_touch_slots[current_slot].active = (event->value >= 0);
                g_touch_slots[current_slot].is_custom =
                    (event->value >= TOUCH_CUSTOM_TRACKING_BASE);
            } else if (event->code == ABS_MT_POSITION_X) {
                g_touch_slots[current_slot].x = event->value;
                if (!g_touch_slots[current_slot].active)
                    g_touch_slots[current_slot].active = true;
            } else if (event->code == ABS_MT_POSITION_Y) {
                g_touch_slots[current_slot].y = event->value;
                if (!g_touch_slots[current_slot].active)
                    g_touch_slots[current_slot].active = true;
            }
        }
    }
    g_touch_current_slot = current_slot;
    time_template = &g_touch_read_events[0];

    for (i = 0; i < TOUCH_MAX_SLOTS; ++i) {
        if (!g_touch_slots[i].dirty)
            continue;

        if (g_touch_device_caps.has_mt_slot) {
            touch_append_event(&g_touch_final_events, time_template,
                                   EV_ABS, ABS_MT_SLOT, i);
        }

        if (g_touch_slots[i].active) {
            if (g_touch_device_caps.has_mt_tracking_id) {
                touch_append_event(&g_touch_final_events, time_template,
                                       EV_ABS, ABS_MT_TRACKING_ID,
                                       g_touch_slots[i].tracking_id);
            }
            if (g_touch_device_caps.has_mt_touch_major) {
                touch_append_event(&g_touch_final_events, time_template,
                                       EV_ABS, ABS_MT_TOUCH_MAJOR, 2);
            }
            if (g_touch_device_caps.has_mt_pressure) {
                touch_append_event(&g_touch_final_events, time_template,
                                       EV_ABS, ABS_MT_PRESSURE, 1);
            }
            if (!first_down) {
                if (g_touch_device_caps.has_btn_touch) {
                    touch_append_event(&g_touch_final_events, time_template,
                                           EV_KEY, BTN_TOUCH, 1);
                }
                if (g_touch_device_caps.has_btn_tool_finger) {
                    touch_append_event(&g_touch_final_events, time_template,
                                           EV_KEY, BTN_TOOL_FINGER, 1);
                }
                first_down = true;
            }
            touch_append_event(&g_touch_final_events, time_template,
                                   EV_ABS, ABS_MT_POSITION_X, g_touch_slots[i].x);
            touch_append_event(&g_touch_final_events, time_template,
                                   EV_ABS, ABS_MT_POSITION_Y, g_touch_slots[i].y);
        } else {
            if (g_touch_device_caps.has_mt_touch_major) {
                touch_append_event(&g_touch_final_events, time_template,
                                       EV_ABS, ABS_MT_TOUCH_MAJOR, 0);
            }
            if (g_touch_device_caps.has_mt_pressure) {
                touch_append_event(&g_touch_final_events, time_template,
                                       EV_ABS, ABS_MT_PRESSURE, 0);
            }
            if (g_touch_device_caps.has_mt_tracking_id) {
                touch_append_event(&g_touch_final_events, time_template,
                                       EV_ABS, ABS_MT_TRACKING_ID, -1);
            }
        }

        g_touch_slots[i].dirty = false;
    }

    for (i = 0; i < TOUCH_MAX_SLOTS; ++i) {
        if (g_touch_slots[i].active) {
            any_active = 1;
            break;
        }
    }

    if (!any_active && first_down) {
        first_down = false;
        if (g_touch_device_caps.has_btn_touch) {
            touch_append_event(&g_touch_final_events, time_template,
                                   EV_KEY, BTN_TOUCH, 0);
        }
        if (g_touch_device_caps.has_btn_tool_finger) {
            touch_append_event(&g_touch_final_events, time_template,
                                   EV_KEY, BTN_TOOL_FINGER, 0);
        }
    }

    touch_append_event(&g_touch_final_events, time_template, EV_SYN, SYN_REPORT, 0);
    copy_size = (size_t)g_touch_final_events.count * sizeof(struct input_event);
    mutex_unlock(&g_touch_lock);

    if (copy_to_user(buf, g_touch_final_events.events, copy_size))
        return -EFAULT;

    return (ssize_t)copy_size;
}

static struct kprobe g_touch_read_kprobe;

static void touch_unregister_read_hook_now(void)
{
    if (!g_touch_read_hook_registered)
        return;

    unregister_kprobe(&g_touch_read_kprobe);
    g_touch_read_hook_registered = false;
}

static void touch_stop_read_workfn(struct work_struct *work)
{
    touch_unregister_read_hook_now();
}

static void touch_stop_read_hook(void)
{
    if (!g_touch_stop_work_initialized)
        return;

    schedule_work(&g_touch_stop_read_work);
}

/* Reject-reason codes mirrored in struct touch_status.last_reject_reason.
 * Keep 0=none / 1..N=reasons stable — user side compares by number. */
enum {
    TOUCH_REJECT_NONE       = 0,
    TOUCH_REJECT_UID        = 1,   /* uid≠1000 */
    TOUCH_REJECT_NAME       = 2,   /* dentry name lacks "event" */
    TOUCH_REJECT_PATH       = 3,   /* d_path 非 /dev/input/event */
    TOUCH_REJECT_CAPS       = 4,   /* 缺 EV_ABS/ABS_MT_* */
    TOUCH_REJECT_INSTALLED  = 5,   /* 已装, 进入去重路径 */
};

/* pr_warn 会被 dmesg 记录; 用 ratelimit 避免主循环高频路径把内核日志刷爆.
 * user 侧靠 struct touch_status.reject_*_count 做无损累计. */
static void touch_note_reject(int reason, const char *path)
{
    g_touch_status.last_reject_reason = reason;

    switch (reason) {
    case TOUCH_REJECT_UID:
        g_touch_status.reject_uid_count++;
        break;
    case TOUCH_REJECT_NAME:
        g_touch_status.reject_name_count++;
        break;
    case TOUCH_REJECT_PATH:
        g_touch_status.reject_path_count++;
        break;
    case TOUCH_REJECT_CAPS:
        g_touch_status.reject_caps_count++;
        break;
    default:
        break;
    }

    /* 只在真“可疑”的拒因(uid 通过后仍被过滤)上落 dmesg, 且限速. */
    if (reason == TOUCH_REJECT_CAPS)
        pr_warn_ratelimited(
            "touch reject reason=caps uid=%u comm=%s path=%s\n",
            current_uid().val, current->comm, path ? path : "?");
}

static int touch_try_patch_file(struct file *file)
{
    struct evdev_client *client;
    struct evdev *evdev;
    struct input_dev *idev;
    char leader[TASK_COMM_LEN];
    char path_buf[256];
    char *path;

    if (!file || IS_ERR(file))
        return 0;

    /* uid 门是 hot path (每次任何进程 read 都会命中), 不做 pr_warn/累计 —
     * 只对通过 uid=1000 才进入的路径做拒因记录, 保信噪比. */
    if (current_uid().val != 1000)
        return 0;

    /* SF also runs as UID 1000. Its payload reads input for its own UI and
     * must never become the injection target. Match the process leader, not
     * the current thread: SF render/payload workers have different names. */
    get_task_comm(leader, current->group_leader);
    if (!strcmp(leader, "surfaceflinger"))
        return 0;

    if (!file->f_op || !file->f_op->read)
        return 0;

    if (!file->f_path.dentry || !file->f_path.dentry->d_name.name)
        return 0;

    if (!strstr(file->f_path.dentry->d_name.name, "event")) {
        touch_note_reject(TOUCH_REJECT_NAME, NULL);
        return 0;
    }

    path = d_path(&file->f_path, path_buf, sizeof(path_buf));
    if (IS_ERR(path) || strncmp(path, "/dev/input/event", 16) != 0) {
        touch_note_reject(TOUCH_REJECT_PATH, IS_ERR(path) ? NULL : path);
        return 0;
    }

    client = file->private_data;
    if (!client || !client->evdev)
        return 0;

    evdev = client->evdev;
    idev = evdev->handle.dev;
    if (!idev)
        return 0;

    if (!touch_test_bit(EV_ABS, idev->evbit) ||
        !touch_test_bit(ABS_MT_SLOT, idev->absbit) ||
        !touch_test_bit(ABS_MT_TRACKING_ID, idev->absbit) ||
        !touch_test_bit(ABS_MT_POSITION_X, idev->absbit) ||
        !touch_test_bit(ABS_MT_POSITION_Y, idev->absbit)) {
        touch_note_reject(TOUCH_REJECT_CAPS, path);
        return 0;
    }

    /* v3 root-fix 候选: 要求 BTN_TOUCH 或 BTN_TOOL_FINGER 位, 排除仅 4-bit
     * ABS_MT 通过但不是真主触屏的幻影设备(部分手写笔 uinput 面板/hover
     * 传感/次屏 backpad 会通过 ABS_MT_* 门, 但不上报 BTN_TOUCH). Linux input
     * 协议约定实体触屏至少上 BTN_TOUCH; 此门理论上不该拒真主面板.
     *
     * 反面风险: 若某 OEM 主面板故意不上 BTN_TOUCH(极罕见, 违反 Linux input
     * 规范), 会被过滤. 诊断兜底: CSV kInstalled=0 + kRejectReason=4(CAPS)
     * + kRejectCount 只有 caps 分量增长, 一眼判决. 回退办法就是从这里删除
     * 这个块, 一次重刷内核解决. 与参考实现 checkDeviceIsTouch 保
     * 持一致的语义: 只承认真触屏. */
    if (!touch_test_bit(EV_KEY, idev->evbit) ||
        (!touch_test_bit(BTN_TOUCH, idev->keybit) &&
         !touch_test_bit(BTN_TOOL_FINGER, idev->keybit))) {
        touch_note_reject(TOUCH_REJECT_CAPS, path);
        pr_warn_ratelimited(
            "touch reject reason=btn_touch uid=%u comm=%s path=%s (缺 BTN_TOUCH/BTN_TOOL_FINGER, 疑幻影设备)\n",
            current_uid().val, current->comm, path);
        return 0;
    }

    if (g_touch_proxy_installed) {
        g_touch_status.last_reject_reason = TOUCH_REJECT_INSTALLED;
        touch_stop_read_hook();
        return 0;
    }

    memcpy(&g_touch_proxy_fops, file->f_op, sizeof(g_touch_proxy_fops));
    g_touch_orig_read = file->f_op->read;
    g_touch_proxy_fops.read = touch_read_proxy;
    file->f_op = &g_touch_proxy_fops;
    g_touch_input_dev = idev;
    touch_cache_device_caps(idev);
    g_touch_proxy_installed = true;

    /* 装完立刻填 status, 给用户态 GET_STATUS 用. path/comm 装成安全的终止串.
     * absinfo 直接读 idev(hint 内核 ABI, 无需 EVIOCGABS). */
    g_touch_status.installed = 1;
    g_touch_status.patched_uid = current_uid().val;
    strscpy(g_touch_status.patched_path, path,
            sizeof(g_touch_status.patched_path));
    strscpy(g_touch_status.patched_comm, current->comm,
            sizeof(g_touch_status.patched_comm));
    g_touch_status.abs_x_min = idev->absinfo
        ? idev->absinfo[ABS_MT_POSITION_X].minimum : 0;
    g_touch_status.abs_x_max = idev->absinfo
        ? idev->absinfo[ABS_MT_POSITION_X].maximum : 0;
    g_touch_status.abs_y_min = idev->absinfo
        ? idev->absinfo[ABS_MT_POSITION_Y].minimum : 0;
    g_touch_status.abs_y_max = idev->absinfo
        ? idev->absinfo[ABS_MT_POSITION_Y].maximum : 0;
    g_touch_status.has_mt_slot = g_touch_device_caps.has_mt_slot ? 1 : 0;
    g_touch_status.has_mt_tracking_id =
        g_touch_device_caps.has_mt_tracking_id ? 1 : 0;
    g_touch_status.has_btn_touch =
        g_touch_device_caps.has_btn_touch ? 1 : 0;
    g_touch_status.last_reject_reason = TOUCH_REJECT_NONE;

    touch_stop_read_hook();
    pr_info("touch proxy installed on %s for %s (absX=[%d,%d] absY=[%d,%d])\n",
            path, current->comm,
            g_touch_status.abs_x_min, g_touch_status.abs_x_max,
            g_touch_status.abs_y_min, g_touch_status.abs_y_max);
    return 0;
}

static int touch_read_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs;
    unsigned int fd;
    struct file *file;

    real_regs = (struct pt_regs *)regs->regs[0];
    fd = (unsigned int)real_regs->regs[0];

    file = fget(fd);
    if (!file)
        return 0;

    touch_try_patch_file(file);
    fput(file);
    return 0;
}

static int touch_start_read_hook(void)
{
    int ret;

    if (g_touch_proxy_installed || g_touch_read_hook_registered)
        return 0;

    if (!g_touch_stop_work_initialized) {
        INIT_WORK(&g_touch_stop_read_work, touch_stop_read_workfn);
        g_touch_stop_work_initialized = true;
    }

    memset(&g_touch_read_kprobe, 0, sizeof(g_touch_read_kprobe));
    g_touch_read_kprobe.symbol_name = "__arm64_sys_read";
    g_touch_read_kprobe.pre_handler = touch_read_pre_handler;

    ret = register_kprobe(&g_touch_read_kprobe);
    if (ret < 0)
        return ret;

    g_touch_read_hook_registered = true;
    return 0;
}

long touch_init(void)
{
    int ret;

    mutex_lock(&g_touch_lock);
    touch_init_slots_locked();
    ret = touch_start_read_hook();
    mutex_unlock(&g_touch_lock);
    return ret;
}

long touch_event(void __user *arg)
{
    struct touch_event_req req;
    int ret;

    if (!arg)
        return -EINVAL;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    mutex_lock(&g_touch_lock);
    touch_init_slots_locked();
    ret = touch_start_read_hook();
    if (ret < 0)
        goto out;

    if (req.down)
        ret = touch_move_slot_locked(req.slot, req.x, req.y);
    else
        ret = touch_release_slot_locked(req.slot);

out:
    mutex_unlock(&g_touch_lock);
    return ret;
}

long touch_get_status(void __user *arg)
{
    struct touch_status snap;

    if (!arg)
        return -EINVAL;

    mutex_lock(&g_touch_lock);
    snap = g_touch_status;
    mutex_unlock(&g_touch_lock);

    if (copy_to_user(arg, &snap, sizeof(snap)))
        return -EFAULT;

    return 0;
}

void touch_release_all(void)
{
    int i;

    mutex_lock(&g_touch_lock);
    touch_init_slots_locked();
    for (i = 0; i < TOUCH_MAX_SLOTS; ++i) {
        if (g_touch_slots[i].is_custom)
            touch_release_slot_locked(i);
    }
    mutex_unlock(&g_touch_lock);
}

void touch_exit(void)
{
    touch_release_all();

    if (g_touch_stop_work_initialized)
        cancel_work_sync(&g_touch_stop_read_work);

    mutex_lock(&g_touch_lock);
    touch_unregister_read_hook_now();
    g_touch_proxy_installed = false;
    g_touch_orig_read = NULL;
    g_touch_input_dev = NULL;
    memset(&g_touch_device_caps, 0, sizeof(g_touch_device_caps));
    memset(&g_touch_status, 0, sizeof(g_touch_status));
    mutex_unlock(&g_touch_lock);
}
