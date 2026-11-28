// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/kernfs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include "module_sysfs.h"

#if defined(CONFIG_SYSFS) && defined(CONFIG_MODULE_UNLOAD) && defined(CONFIG_TASKS_RCU)
/* Follow kernel_draw/debug/control.c: keep the loader-owned kobjects and
 * attributes alive, and restore their directories only for normal unloading.
 * main.c owns the lifetime reference until unload preparation completes. */
static DEFINE_MUTEX(module_sysfs_lock);
static bool module_sysfs_detached;

/* kernel/params.c keeps this prefix in module_kobject.mp on the supported KMIs. */
struct dfm_module_param_attrs {
    unsigned int num;
    struct attribute_group group;
};

#ifdef CONFIG_KALLSYMS
static struct kobject *module_notes_dir;
struct dfm_module_notes_attrs {
    struct kobject *dir;
    unsigned int count;
    struct bin_attribute attrs[];
};
#endif

int dfm_module_sysfs_detach(void)
{
    struct module *mod = THIS_MODULE;
    struct kobject *kobj = &mod->mkobj.kobj;
    int ret = 0;

    mutex_lock(&module_sysfs_lock);
    if (module_sysfs_detached)
        goto out;
    if (!kobj->state_in_sysfs) {
        ret = -ENOENT;
        goto out;
    }
#ifdef CONFIG_KALLSYMS
    if (mod->notes_attrs) {
        struct kernfs_node *notes = kernfs_find_and_get(kobj->sd, "notes");

        if (!notes) {
            ret = -ENOENT;
            goto out;
        }
        if (notes->priv != kobj)
            module_notes_dir = notes->priv;
        kernfs_put(notes);
    }
#endif
    kobject_del(&THIS_MODULE->mkobj.kobj);
    module_sysfs_detached = true;
out:
    mutex_unlock(&module_sysfs_lock);
    return ret;
}

static int restore_child(struct kobject *child, struct kobject *parent)
{
    if (!child)
        return -EOPNOTSUPP;
    /* Removing the parent unlinked this child without clearing its state. */
    if (child->state_in_sysfs)
        kobject_del(child);
    return kobject_add(child, parent, NULL);
}

static int restore_parameters(struct module *mod, struct kobject *kobj)
{
    const struct dfm_module_param_attrs *params = (const void *)mod->mkobj.mp;

    if (!params)
        return 0;
    if (!params->num || params->num > mod->num_kp || !params->group.name ||
        strcmp(params->group.name, "parameters") || !params->group.attrs)
        return -EOPNOTSUPP;
    return sysfs_create_group(kobj, &params->group);
}

#ifdef CONFIG_KALLSYMS
static int restore_notes(struct module *mod, struct kobject *kobj)
{
    const struct dfm_module_notes_attrs *notes;
    unsigned int i;
    int ret;

    if (!mod->notes_attrs)
        return 0;
    if (!module_notes_dir)
        return sysfs_create_group(kobj, (const struct attribute_group *)mod->notes_attrs);
    notes = (const void *)mod->notes_attrs;
    if (notes->dir != module_notes_dir)
        return -EOPNOTSUPP;
    ret = restore_child(module_notes_dir, kobj);
    if (ret)
        return ret;
    for (i = 0; i < notes->count; ++i) {
        ret = sysfs_create_bin_file(module_notes_dir, &notes->attrs[i]);
        if (ret)
            return ret;
    }
    return 0;
}
#endif

int dfm_module_sysfs_restore_for_unload(void)
{
    struct module *mod = THIS_MODULE;
    struct kobject *kobj = &mod->mkobj.kobj;
    struct module_attribute *attr;
    int ret = 0;

    mutex_lock(&module_sysfs_lock);
    if (!module_sysfs_detached)
        goto out;
    /* Existing name and module kset belong to the kernel module loader. */
    ret = kobject_add(kobj, NULL, NULL);
    if (ret)
        goto out;
    for (attr = mod->modinfo_attrs; attr && attr->attr.name; ++attr) {
        ret = sysfs_create_file(kobj, &attr->attr);
        if (ret)
            goto rollback;
    }
    ret = restore_parameters(mod, kobj);
    if (ret)
        goto rollback;
#ifdef CONFIG_KALLSYMS
    if (mod->sect_attrs) {
        ret = sysfs_create_group(kobj, (const struct attribute_group *)mod->sect_attrs);
        if (ret)
            goto rollback;
    }
    ret = restore_notes(mod, kobj);
    if (ret)
        goto rollback;
#endif
    ret = restore_child(mod->holders_dir, kobj);
    if (ret)
        goto rollback;
    kobj->state_remove_uevent_sent = 0;
    kobject_uevent(kobj, KOBJ_ADD);
    module_sysfs_detached = false;
    goto out;
rollback:
    /* Keep the lifetime reference and permit a later unload request to retry. */
    kobject_del(kobj);
out:
    mutex_unlock(&module_sysfs_lock);
    return ret;
}
#else
int dfm_module_sysfs_detach(void) { return -EOPNOTSUPP; }
int dfm_module_sysfs_restore_for_unload(void) { return -EOPNOTSUPP; }
#endif
