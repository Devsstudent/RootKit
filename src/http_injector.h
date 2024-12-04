#ifndef HTTP_INJECTOR_H
# define HTTP_INJECTOR_H
# include <linux/netfilter.h>
# include <linux/netfilter_ipv4.h>
# include <linux/skbuff.h>
# include "fast_search.h"

# define BLACKLIST_FILE "/lib/secret/blacklist"

# define MAX_IP_COUNT 256
# define MAX_LINE_LENGTH 256


int fill_search_dict(search_map_t *map);
unsigned int http_nf_hookfn(void *priv,
              struct sk_buff *skb,
              const struct nf_hook_state *state);
# endif
