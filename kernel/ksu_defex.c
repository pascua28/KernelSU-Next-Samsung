/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "ksu_kallsyms.h"
#include "ksu_defex.h"
#include <linux/kprobes.h>

static int defex_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    regs->regs[0] = 0;
    regs->pc = regs->regs[30];
    return 1;
}

static struct kprobe kp_user_exec = {
    .pre_handler = defex_pre_handler,
};

static struct kprobe kp_check_creds = {
    .pre_handler = defex_pre_handler,
};

static struct kprobe kp_creds_ready = {
    .pre_handler = defex_pre_handler,
};

static struct kprobe kp_dc_path = {
    .pre_handler = defex_pre_handler,
};

int ksu_init_defex_bypass(void)
{
    int ret;

    kp_user_exec.addr = (kprobe_opcode_t *)ksu_syms.task_defex_user_exec;
    kp_check_creds.addr = (kprobe_opcode_t *)ksu_syms.task_defex_check_creds;
    kp_creds_ready.addr = (kprobe_opcode_t *)ksu_syms.is_task_creds_ready;
    kp_dc_path.addr = (kprobe_opcode_t *)ksu_syms.get_dc_target_dpath;

    if (!kp_user_exec.addr || !kp_check_creds.addr) {
        pr_warn("ksu: DEFEX bypass - critical symbols missing\n");
        return -ENOENT;
    }

    ret = register_kprobe(&kp_user_exec);
    if (ret) {
        pr_err("ksu: failed to register task_defex_user_exec kprobe: %d\n", ret);
        return ret;
    }

    ret = register_kprobe(&kp_check_creds);
    if (ret) {
        pr_err("ksu: failed to register task_defex_check_creds kprobe: %d\n", ret);
        goto unregister_user;
    }

    ret = register_kprobe(&kp_creds_ready);
    if (ret) {
        pr_err("ksu: failed to register is_task_creds_ready kprobe: %d\n", ret);
        goto unregister_creds;
    }

    ret = register_kprobe(&kp_dc_path);
    if (ret) {
        pr_err("ksu: failed to register get_dc_target_dpath kprobe: %d\n", ret);
        goto unregister_ready;
    }

    pr_info("ksu: DEFEX functions hooked successfully\n");
    return 0;

unregister_ready:
    unregister_kprobe(&kp_creds_ready);
unregister_creds:
    unregister_kprobe(&kp_check_creds);
unregister_user:
    unregister_kprobe(&kp_user_exec);
    return ret;
}

void ksu_exit_defex_bypass(void)
{
    unregister_kprobe(&kp_dc_path);
    unregister_kprobe(&kp_creds_ready);
    unregister_kprobe(&kp_check_creds);
    unregister_kprobe(&kp_user_exec);
}
