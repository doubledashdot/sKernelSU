// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#pragma once
#ifndef __KSU_H_TEMP_PATCH_SETGROUPS
#define __KSU_H_TEMP_PATCH_SETGROUPS

#define __AARCH64_setgroups	159
#define __ARMEABI_setgroups	206
#define __ARMEABI_setgroups16	81	// CONFIG_UID16

static __always_inline void setgroups_mutate_gid_3009(int gidsetsize, void **grouplist_pptr)
{
	int i = 0;
	gid_t user_gid;
	gid_t __user *grouplist = (gid_t __user *)untagged_addr(*(void **)grouplist_pptr);

start:
	if (!!get_user(user_gid, &grouplist[i]))
		goto increment;

	if (user_gid != 3009)
		goto increment;

	pr_info("ksu_setgroups: %s: prevent gid 3009 assignment\n", current->comm);
	put_user(9997, &grouplist[i]);

increment:
	i++;
	if (gidsetsize > i)
		goto start;

}

#ifdef CONFIG_UID16
static __always_inline void setgroups16_mutate_gid_3009(int gidsetsize, void **grouplist_pptr)
{
	int i = 0;
	old_gid_t user_gid;
	old_gid_t __user *grouplist = (old_gid_t __user *)untagged_addr(*(void **)grouplist_pptr);

start:
	if (!!get_user(user_gid, &grouplist[i]))
		goto increment;

	if (user_gid != 3009)
		goto increment;

	pr_info("ksu_setgroups: %s: prevent gid 3009 assignment\n", current->comm);
	put_user(9997, &grouplist[i]);

increment:
	i++;
	if (gidsetsize > i)
		goto start;

}
#endif

#ifdef CONFIG_ARM64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static syscall_fn_t aarch64_setgroups __read_mostly = NULL;
asmlinkage long hook_aarch64_setgroups(const struct pt_regs *regs)
{
	int gidsetsize = (int)regs->regs[0];
	void **grouplist_pptr = (void **)&regs->regs[1];

	setgroups_mutate_gid_3009(gidsetsize, grouplist_pptr);
	return __arm64_sys_setgroups(regs);
}

#ifdef CONFIG_COMPAT
static syscall_fn_t armeabi_setgroups __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups(const struct pt_regs *regs)
{
	int gidsetsize = (int)regs->regs[0];
	void **grouplist_pptr = (void **)&regs->regs[1];

	setgroups_mutate_gid_3009(gidsetsize, grouplist_pptr);
	return __arm64_sys_setgroups(regs);
}

#ifdef CONFIG_UID16
static syscall_fn_t armeabi_setgroups16 __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups16(const struct pt_regs *regs)
{
	int gidsetsize = (int)regs->regs[0];
	void **grouplist_pptr = (void **)&regs->regs[1];

	setgroups16_mutate_gid_3009(gidsetsize, grouplist_pptr);
	return __arm64_sys_setgroups16(regs);
}
#endif // UID16
#endif // COMPAT

#else /* < 4.19 */

static void *aarch64_setgroups __read_mostly = NULL;
asmlinkage long hook_aarch64_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	setgroups_mutate_gid_3009(gidsetsize, (void **)&grouplist);
	return sys_setgroups(gidsetsize, grouplist);
}

#ifdef CONFIG_COMPAT
extern const void *compat_sys_call_table[];

static void *armeabi_setgroups __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	setgroups_mutate_gid_3009(gidsetsize, (void **)&grouplist);
	return sys_setgroups(gidsetsize, grouplist);
}

#ifdef CONFIG_UID16
static void *armeabi_setgroups16 __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups16(int gidsetsize, old_gid_t __user *grouplist)
{
	setgroups16_mutate_gid_3009(gidsetsize, (void **)&grouplist);
	return sys_setgroups16(gidsetsize, grouplist);
}
#endif // UID16
#endif // COMPAT

#endif /* < 4.19 */

#elif defined(CONFIG_ARM)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static syscall_fn_t armeabi_setgroups __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups(const struct pt_regs *regs)
{
	int gidsetsize = (int)regs->regs[0];
	void **grouplist_pptr = (void **)&regs->regs[1];

	setgroups_mutate_gid_3009(gidsetsize, grouplist_pptr);
	return sys_setgroups(regs);
}

#ifdef CONFIG_UID16
static syscall_fn_t armeabi_setgroups16 __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups16(const struct pt_regs *regs)
{
	int gidsetsize = (int)regs->regs[0];
	void **grouplist_pptr = (void **)&regs->regs[1];

	setgroups16_mutate_gid_3009(gidsetsize, grouplist_pptr);
	return sys_setgroups16(regs);
}
#endif // UID16

#else /* < 4.19 */

extern void *sys_call_table[];

static void *armeabi_setgroups __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	setgroups_mutate_gid_3009(gidsetsize, (void **)&grouplist);
	return sys_setgroups(gidsetsize, grouplist);
}

#ifdef CONFIG_UID16
static void *armeabi_setgroups16 __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups16(int gidsetsize, old_gid_t __user *grouplist)
{
	setgroups16_mutate_gid_3009(gidsetsize, (void **)&grouplist);
	return sys_setgroups16(gidsetsize, grouplist);
}
#endif // UID16
#endif  /* < 4.19 */
#endif // ARM

static void ksu_init_setgroups_patch()
{
	pr_info("%s: patching setgroups()\n", __func__);

#ifdef CONFIG_ARM64
	read_and_replace_syscall((void *)&aarch64_setgroups, __AARCH64_setgroups, (void *)hook_aarch64_setgroups, (void *)sys_call_table);
#ifdef CONFIG_COMPAT
	read_and_replace_syscall((void *)&armeabi_setgroups, __ARMEABI_setgroups, (void *)hook_armeabi_setgroups, (void *)compat_sys_call_table);
#ifdef CONFIG_UID16
	read_and_replace_syscall((void *)&armeabi_setgroups16, __ARMEABI_setgroups16, (void *)hook_armeabi_setgroups16, (void *)compat_sys_call_table);
#endif // uid16
#endif // compat

#elif defined(CONFIG_ARM)
	read_and_replace_syscall((void *)&armeabi_setgroups, __ARMEABI_setgroups, (void *)hook_armeabi_setgroups, (void *)sys_call_table);
#ifdef CONFIG_UID16
	read_and_replace_syscall((void *)&armeabi_setgroups16, __ARMEABI_setgroups16, (void *)hook_armeabi_setgroups16, (void *)sys_call_table);
#endif	// uid16

#endif
}

#endif // __KSU_H_TEMP_PATCH_SETGROUPS
