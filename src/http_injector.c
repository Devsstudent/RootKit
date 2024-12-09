#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "http_injector.h"
#include "fast_search.h"

/*
 * Replace "Hello world" in HTTP request by "Malicious"
 */

static int replace(struct sk_buff *skb, const char *data, const char *tail, search_map_t *map) {
    char *i;
    long diff;
    char *start;
    char *end;

    search_list_item_t *search_list = init_search_list(map);
    search_list_item_t *result;
    item_t *item;

    for (i = (char *)data; i != tail; ++i) {
        result = update_search_list(map, search_list, *i, i);
        // Result can be a chain but we take only the first item
        if (result != NULL) {
            item = result->item_location;
            diff = item->key_length - item->value_length;
            start = result->head + item->value_length;
            end   = result->head + item->key_length;
            printk(KERN_INFO "Diff : %li", diff);
            if (diff == 0) {
                memcpy(result->head, item->value, item->value_length);
            }
            else if (diff > 0) {
                memcpy(result->head, item->value, item->value_length);
                memcpy(start, end, tail - end);
                memset((void *)(tail - diff), ' ', diff);
                i -= diff;
                tail -= diff;
                printk(KERN_INFO "?????");
                // skb_pull(skb, diff);
            }
            // else {
            //     diff = -diff;
            //     if (pskb_expand_head(skb, 0, diff, GFP_ATOMIC)) {
            //         printk(KERN_INFO "Nope...");
            //         continue;
            //     }
            //     skb_push(skb, diff);
            //     memcpy(start, end, tail - end);
            //     memcpy(result->head, item->value, item->value_length);
            //     i += diff;
            //     tail += diff;
            //     printk(KERN_INFO "Done");
            // }
        }
    }

    free_search_list(search_list);
    
    return 0;
}

int fill_search_dict(search_map_t *map) {
    add_item_to_map(map, "Macron", 6, "Micron", 6);
    add_item_to_map(map, "Hello",  5, "Hello from the other",  20);
    add_item_to_map(map, "1234",   4, "321",   3);
    return 0;
}

unsigned int http_nf_hookfn(  void *priv,
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

    search_map_t *map = (search_map_t *)priv;

    // ip_source = (char *)&iph->saddr;
    // ip_dest   = (char *)&iph->daddr;

    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    tcph = tcp_hdr(skb);

    // printk(KERN_INFO "IP Source : %i.%i.%i.%i", ip_source[0], ip_source[1], ip_source[2], ip_source[3]);
    // printk(KERN_INFO "IP Dest   : %i.%i.%i.%i", ip_dest[0], ip_dest[1], ip_dest[2], ip_dest[3]);

    user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
    tail = skb_tail_pointer(skb);

    replace(skb, user_data, tail, map);

    return NF_ACCEPT;
}