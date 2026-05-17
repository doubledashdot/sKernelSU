#if !defined(CONFIG_ARM64)
#error "automated LSM hooking on 6.8+ is only for ARM64!"
#endif

#if !defined(CONFIG_KALLSYMS)
#error "automated LSM hooking on 6.8+ requires kallsyms!"
#endif

#include <asm/insn.h>

// security.c hijack for 6.8+
// however this requires kallsyms
// TODO: refine, try to lessen kallsyms dependence further

/*

https://godbolt.org/z/Eh8vfrdns

__attribute__((noinline)) 
void target_fn() {
    volatile int x = 0;
}

int main() {
    target_fn();
    return 0;
}

target_fn:
        sub     sp, sp, #16
        str     wzr, [sp, 12]
        nop
        add     sp, sp, 16
        ret
main:
        stp     x29, x30, [sp, -16]!
        mov     x29, sp
        bl      target_fn   << hunt for this!
        mov     w0, 0
        ldp     x29, x30, [sp], 16
        ret
*/

// bl is 94 ~ 97
// so we can do this like on x86 where 74 xx to 74 yy
// bl is call+ret equivalent on x86 though


// rename
extern int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags);
__attribute__((hot))
static __nocfi int ksu_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

// setuid
extern int security_task_fix_setuid(struct cred *new, const struct cred *old, int flags);
__attribute__((hot))
static __nocfi int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return security_task_fix_setuid(new, old, flags);
}

// bprm
extern int security_bprm_check(struct linux_binprm *bprm);
__attribute__((hot))
static __nocfi int ksu_bprm_check(struct linux_binprm *bprm)
{
#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit_bprm((const char *)bprm->filename);
#endif
	return security_bprm_check(bprm);
}

// vfs_read, as security_file_permission is a bit spotty to hook!
extern ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos);
__attribute__((hot))
static __nocfi ssize_t ksu_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (static_branch_likely(&ksud_vfs_read_key))
		ksu_install_rc_hook(file);
#else
	if (unlikely(ksu_vfs_read_hook))
		ksu_install_rc_hook(file);
#endif
#endif

	return vfs_read(file, buf, count, pos);
}

// setprocattr
extern int security_setprocattr(int lsmid, const char *name, void *value, size_t size);
__attribute__((hot))
static __nocfi int ksu_setprocattr(int lsmid, const char *name, void *value, size_t size)
{
	ksu_hide_setprocattr(name, value, size);
	return security_setprocattr(lsmid, name, value, size);
}

static int lsm_hunt_symbol_callsite(uintptr_t target_callsite, ptrdiff_t target_width, uintptr_t symbol_addr, uintptr_t hook_addr)
{
	if (!target_callsite || !symbol_addr) {
		pr_info("lsm_hijack: no vallsite or symbol addr specified!\n");
		return 1;
	}

	uintptr_t start_addr = (uintptr_t)target_callsite;
	uintptr_t end_addr = start_addr + target_width;
	uintptr_t curr_addr = start_addr;
	uint32_t raw_instruction; // arm64 wordsize

start_scan:
	if (curr_addr >= end_addr)
		goto bail;

	if (copy_from_kernel_nofault(&raw_instruction, (void *)curr_addr, sizeof(uint32_t)))
		goto step_up;

	// bl
	if ((raw_instruction & 0xFC000000) != 0x94000000)
		goto step_up;

	// 26-bit signed relative jump offset
	// FC, D, E, F, so 3
	int32_t imm26 = raw_instruction & 0x03FFFFFF;

	// in case of backward jumps
	if (imm26 & 0x02000000)
		imm26 |= 0xFC000000;

	long byte_delta = (long)imm26 * 4;
	uintptr_t calculated_destination = curr_addr + byte_delta;

	if (calculated_destination != symbol_addr)
		goto step_up;

	pr_info("lsm_hijack: found call site at 0x%lx\n", curr_addr);

	u32 insn = aarch64_insn_gen_branch_imm(curr_addr, hook_addr, AARCH64_INSN_BRANCH_LINK);
	void *arr_addr[] = { (void*)curr_addr };
	uint32_t arr_insn[] = { insn };

	int res = aarch64_insn_patch_text(arr_addr, arr_insn, 1);
	pr_info("lsm_hijack: patched callsite: 0x%lx ret: %d\n", curr_addr, res);

	return 0;

step_up:
	curr_addr = curr_addr + sizeof(uint32_t);
	goto start_scan;

bail:
	pr_info("lsm_hijack: callsite scan done!\n");
	return 1;
}

static void __init ksu_core_init(void)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

	// rename
	extern int vfs_rename(struct renamedata *rd);
	target_callsite = (uintptr_t)&vfs_rename;
	symbol_addr = (uintptr_t)&security_inode_rename;

	ret = lsm_hunt_symbol_callsite(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_inode_rename);
	pr_info("lsm_hijack: security_inode_rename: ret %d \n", ret);
	symbol_addr = NULL;

	// setuid
	extern long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);
	target_callsite = (uintptr_t)&__sys_setresuid;
	symbol_addr = (uintptr_t)&security_task_fix_setuid;

	ret = lsm_hunt_symbol_callsite(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_task_fix_setuid);
	pr_info("lsm_hijack: security_task_fix_setuid: ret %d \n", ret);
	symbol_addr = NULL;

#ifdef CONFIG_KSU_FEATURE_SULOG
	// bprm, TODO: refine
	target_callsite = (uintptr_t)kallsyms_lookup_name("bprm_execve");
	symbol_addr = (uintptr_t)&security_bprm_check;
	
	ret = lsm_hunt_symbol_callsite(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_bprm_check);
	pr_info("lsm_hijack: security_bprm_check: ret %d \n", ret);
	symbol_addr = NULL;
#endif

	// read
	extern ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count);
	target_callsite = (uintptr_t)&ksys_read;
	symbol_addr = (uintptr_t)&vfs_read;

	ret = lsm_hunt_symbol_callsite(target_callsite, 64 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_read);
	pr_info("lsm_hijack: ksys_read: ret %d \n", ret);
	symbol_addr = NULL;

	// TODO: traverse proc_pid_attr_operations
	target_callsite = (uintptr_t)kallsyms_lookup_name("proc_pid_attr_write");
	symbol_addr = (uintptr_t)&security_setprocattr;

	ret = lsm_hunt_symbol_callsite(target_callsite, 64 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_setprocattr);
	pr_info("lsm_hijack: security_setprocattr: ret %d \n", ret);
	symbol_addr = NULL;

}
