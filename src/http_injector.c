#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "http_injector.h"

/*
 * Replace "Hello world" in HTTP request by "Malicious"
 */

static int replace(unsigned char *data, unsigned char *tail) {
    unsigned char *i;

    char *search  = "Hello world";
    char *replace = "Malicious  ";
    
    unsigned int len = strlen(search);

    for (i = data; i != tail; ++i) {
        if (memcmp(search, i, len) == 0) {
            memcpy(i, replace, len);
            i += len;
        }
    }
    
    return 0;
}

unsigned int my_nf_hookfn(void *priv,
                struct sk_buff *skb,
                const struct nf_hook_state *state)
{    
    (void)state;
    // char *ip_source;
    // char *ip_dest;

    unsigned char *user_data;   /* TCP data begin pointer */
    unsigned char *tail;        /* TCP data end pointer */

    struct iphdr  *iph = ip_hdr(skb);
    struct tcphdr *tcph;      

    // ip_source = (char *)&iph->saddr;
    // ip_dest   = (char *)&iph->daddr;

    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    tcph = tcp_hdr(skb);

    // printk(KERN_INFO "IP Source : %i.%i.%i.%i", ip_source[0], ip_source[1], ip_source[2], ip_source[3]);
    // printk(KERN_INFO "IP Dest   : %i.%i.%i.%i", ip_dest[0], ip_dest[1], ip_dest[2], ip_dest[3]);

    user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
    tail = skb_tail_pointer(skb);

    replace(user_data, tail);

    return NF_ACCEPT;
}