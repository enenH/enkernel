#define pr_fmt(fmt) KBUILD_MODNAME ": sf_groups: " fmt

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>

#include "abi.h"
#include "sf_groups.h"

#define DFM_AID_SYSTEM 1000U
#define DFM_AID_INPUT  1004U
#define DFM_AID_INET   3003U

#define DFM_SF_EXE_PATH "/system/bin/surfaceflinger"
#define DFM_SF_COMM     "surfaceflinger"

static bool caller_has_system_uids(const struct cred *cred)
{
    kuid_t system_uid = KUIDT_INIT(DFM_AID_SYSTEM);

    return cred->user_ns == &init_user_ns &&
           uid_eq(cred->uid, system_uid) &&
           uid_eq(cred->euid, system_uid) &&
           uid_eq(cred->suid, system_uid) &&
           uid_eq(cred->fsuid, system_uid);
}

static bool caller_has_surfaceflinger_identity(void)
{
    struct file *exe_file;
    char leader_comm[TASK_COMM_LEN];
    char *path_buffer;
    char *path;
    bool allowed = false;

    get_task_comm(leader_comm, current->group_leader);
    if (strcmp(leader_comm, DFM_SF_COMM) != 0)
        return false;

    exe_file = get_task_exe_file(current->group_leader);
    if (!exe_file)
        return false;

    path_buffer = (char *)__get_free_page(GFP_KERNEL);
    if (!path_buffer)
        goto out_file;

    path = d_path(&exe_file->f_path, path_buffer, PAGE_SIZE);
    if (!IS_ERR(path) && strcmp(path, DFM_SF_EXE_PATH) == 0)
        allowed = true;

    free_page((unsigned long)path_buffer);
out_file:
    fput(exe_file);
    return allowed;
}

bool dfm_is_surfaceflinger_caller(void)
{
    return caller_has_system_uids(current_cred()) &&
           caller_has_surfaceflinger_identity();
}

/* DAC checks use fsgid plus supplementary groups. */
static bool cred_has_access_gid(const struct cred *cred, kgid_t gid)
{
    return gid_eq(cred->fsgid, gid) ||
           groups_search(cred->group_info, gid);
}

static uint32_t required_group_mask(const struct cred *cred)
{
    uint32_t mask = 0;

    if (cred_has_access_gid(cred, KGIDT_INIT(DFM_AID_INPUT)))
        mask |= DFM_SF_GROUP_INPUT;
    if (cred_has_access_gid(cred, KGIDT_INIT(DFM_AID_INET)))
        mask |= DFM_SF_GROUP_INET;
    return mask;
}

static int append_required_groups(uint32_t missing)
{
    const struct cred *cred = current_cred();
    const struct group_info *old_groups = cred->group_info;
    struct group_info *new_groups;
    int add_count = 0;
    int index;
    int ret;

    if (missing & DFM_SF_GROUP_INPUT)
        ++add_count;
    if (missing & DFM_SF_GROUP_INET)
        ++add_count;
    if (add_count == 0)
        return 0;
    if (old_groups->ngroups > NGROUPS_MAX - add_count)
        return -E2BIG;

    new_groups = groups_alloc(old_groups->ngroups + add_count);
    if (!new_groups)
        return -ENOMEM;

    for (index = 0; index < old_groups->ngroups; ++index)
        new_groups->gid[index] = old_groups->gid[index];
    if (missing & DFM_SF_GROUP_INPUT)
        new_groups->gid[index++] = KGIDT_INIT(DFM_AID_INPUT);
    if (missing & DFM_SF_GROUP_INET)
        new_groups->gid[index++] = KGIDT_INIT(DFM_AID_INET);

    /* groups_search() is a binary search and set_current_groups() does not
     * sort on this kernel; the setgroups syscall normally does this step. */
    groups_sort(new_groups);

    /* set_current_groups() uses prepare_creds()/commit_creds() for current;
     * unlike the setgroups syscall wrapper it does not require CAP_SETGID.
     * Never mutate another task's immutable cred pointer in place. */
    ret = set_current_groups(new_groups);
    put_group_info(new_groups);
    return ret;
}

long dfm_sf_groups_acquire(void __user *arg)
{
    struct dfm_sf_groups_req req;
    uint32_t before;
    uint32_t missing;
    int ret;

    if (!arg)
        return -EFAULT;
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.abi_version != DFM_SF_GROUPS_ABI_VERSION || req.reserved != 0 ||
        req.out_present != 0 || req.out_added != 0 ||
        req.out_group_count != 0 || req.out_reserved[0] != 0 ||
        req.out_reserved[1] != 0 || req.out_reserved[2] != 0)
        return -EINVAL;

    if (!caller_has_system_uids(current_cred()) ||
        !caller_has_surfaceflinger_identity())
        return -EACCES;

    before = required_group_mask(current_cred());
    missing = DFM_SF_GROUP_REQUIRED & ~before;
    ret = append_required_groups(missing);
    if (ret)
        return ret;

    req.out_present = required_group_mask(current_cred());
    req.out_added = req.out_present & ~before;
    req.out_group_count = current_cred()->group_info->ngroups;
    if (req.out_present != DFM_SF_GROUP_REQUIRED)
        return -EIO;
    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    if (req.out_added)
        pr_info("tgid=%d tid=%d added=0x%x groups=%u\n",
                task_tgid_nr(current), task_pid_nr(current), req.out_added,
                req.out_group_count);
    return 0;
}
