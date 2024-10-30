#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#define BLACKLIST_FILE "/lib/secret/blacklist"

#define MAX_IP_COUNT 256
#define MAX_LINE_LENGTH 256

unsigned int my_nf_hookfn(void *priv,
              struct sk_buff *skb,
              const struct nf_hook_state *state);
