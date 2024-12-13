#include "rootkit.h"


asmlinkage long myRead(const struct pt_regs *regs) {
	printk(KERN_INFO "Hello read\n");
	return g_original_read(regs);
}
