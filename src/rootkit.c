#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int rootkit_init(void) {
    printk(KERN_INFO "Rootkit has been loaded\n");
    return 0;
}

static void rootkit_exit(void) {
    printk(KERN_INFO "Rootkit has been unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");