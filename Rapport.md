# Rapport Rootkit

## Création du LFS

Le script `rootkit` permet de manipuler et créer une image Alpine avec le kernel spécifié. Pour créer un nouveau disque, il suffit d'utiliser la commande

```console
rootkit create [-d DISK] [-s SIZE] [-l LINUX_PATH]
```

La commande `rootkit update` permet de synchroniser le filesystem du disque avec le dossier *fs*.
Enfin, la VM peut être lancée avec `rootkit start`.

L'image est créée selon la méthode du TP1:
- Le disque est créé, formaté, puis monté sur un périphérique boucle.
- Une machine Alpine est lancée sur Docker puis son filesystem est copié sur le disque nouvellement créé.
- On copie le kernel Linux sur le disque et on installe Grub.
- On ajoute quelques fichiers suplémentaires

## Injecteur HTTP

Une des fonctionnalités du rootkit est d'intercepter et modifier les paquets HTTP entrants.

Pour cela, nous avons ajouté un hook **netfilter**. Les hooks peuvent se placer à différentes étapes du routage des paquets :

- NF_IP_PRE_ROUTING
- NF_IP_LOCAL_IN
- NF_IP_FORWARD
- NF_IP_LOCAL_OUT
- NF_IP_POST_ROUTING
- NF_IP_NUMHOOKS

Notre hook se place en *NF_IP_LOCAL_IN*, correspondant au moment où le paquet a été identifié comme étant destiné à l'utilisateur.

Lorsqu'un paquet est reçu, on vérifie que le paquet est un paquet TCP, puis que la donnée applicative n'est pas nulle et que le paquet est bien HTTP. 

On recherche ensuite les occurrences de mots clés grâce à l'algorithme défini dans les fichiers *fast_search*, et on les remplace par les valeurs adaptées.

### Hook netfilter

On déclare une instance de la structure nf_hook_ops avec les valeurs ci-dessous.

```c
static struct nf_hook_ops nfho = {
      .hook        = http_nf_hookfn,
      .hooknum     = NF_INET_LOCAL_IN,
      .pf          = PF_INET,
      .priority    = NF_IP_PRI_FIRST
};
```

Avec la valeur *hook* correspondant à la fonction appelée à la réception d'un paquet et *hooknum* est le moment lors du routage du paquet où la fonction précédente doit être appelée.

On peut ensuite facilement ajouter ce hook à Netfilter :

```c
nf_register_net_hook(&init_net, &nfho);
```

On a ainsi notre fonction *http_nf_hookfn* qui est appelée à chaque fois qu'un paquet à destination de la machine est reçu.
Cette fonction retourne l'acceptation du paquet, voici  les valeurs de retour possibles:

- NF_DROP
- NF_ACCEPT
- NF_STOLEN
- NF_QUEUE
- NF_REPEAT
- NF_STOP


La fonction reçoit en paramètre une `struct sk_buff skb`. Cette structure contient un paquet et est définie tel que:

```c
struct sk_buff {
      union {
              struct {
                      /* These two members must be first. */
                      struct sk_buff          *next;
                      struct sk_buff          *prev;

                      union {
                              struct net_device       *dev;
                              /* Some protocols might use this space to store information,
                               * while device pointer would be NULL.
                               * UDP receive path is one user.
                               */
                              unsigned long           dev_scratch;
                      };
              };

              struct rb_node  rbnode; /* used in netem & tcp stack */
      };
      struct sock             *sk;

      union {
              ktime_t         tstamp;
              u64             skb_mstamp;
      };

      /*
       * This is the control buffer. It is free to use for every
       * layer. Please put your private variables there. If you
       * want to keep them across layers you have to do a skb_clone()
       * first. This is owned by whoever has the skb queued ATM.
       */
      char                    cb[48] __aligned(8);

      unsigned long           _skb_refdst;
      void                    (*destructor)(struct sk_buff *skb);
        union {
              struct {
                      unsigned long   _skb_refdst;
                      void            (*destructor)(struct sk_buff *skb);
              };
              struct list_head        tcp_tsorted_anchor;
      };
      /* ... */

      unsigned int            len,
                              data_len;
      __u16                   mac_len,
                              hdr_len;

         /* ... */

      __be16                  protocol;
      __u16                   transport_header;
      __u16                   network_header;
      __u16                   mac_header;

      /* private: */
      __u32                   headers_end[0];
      /* public: */

      /* These elements must be at the end, see alloc_skb() for details.  */
      sk_buff_data_t          tail;
      sk_buff_data_t          end;
      unsigned char           *head,
                              *data;
      unsigned int            truesize;
      refcount_t              users;
};
```

On peut commencer à parser le paquet en récupérant le header IP grâce à la fonction 

```c
struct iphdr ip_hdr(struct sk_buff *skb);
```

Et récupérer le type du header suivant dans le champ *protocol* de la `struct iphdr` obtenu. Si le header suivant n'est pas un header **TCP**, on renvoie **NF_ACCEPT** pour que le paquet soit accepté.

On peut ensuite récupérer le header TCP et en extraire le contenu HTTP. Pour la suite, on utilise les valeurs *head*, *data*, *tail* et *end*, de la structure *sk_buff* qui pointent vers différentes parties du paquet:

```txt
    head  ->    |----------------|
                |   "headroom"   |
    data  ->    |----------------|
                |      MAC       |
                |----------------|
                |       IP       |
                |----------------|
                |      TCP       |
                |----------------|
                |      HTTP      |
    tail  ->    |----------------|
                |   "tailroom"   |
    end   ->    |----------------|
```

### Recherche multiple dans le texte

Le principe est de remplacer certains mots ou phrases par du texte différent. Pour cela il faut trouver les occurrences de ces textes le plus rapidement possible afin de ne pas introduire trop de latence dans le proccessing du paquet et ainsi rester discret.

Pour cela, nous avons mis au point un algorithme inspiré des *Hash Tables*, avec pour objectif de minimiser le temps d'exécution des recherches, au dépend de l'initialisation des tables qui peut être un peu longue.

Pour cela, chaque entrée de la table "*item*" est décomposée en caractères, puis ces caractères sont stockés dans un tableau de 256 cases (l'indice de chaque caractère étant sa valeur ASCII). Chaque case du tableau est une liste de structure `search_tupple_t`, constituée de l'id de l'item auquel le caractère appartient et sa position dans le texte.

Grâce à cette table, lorsqu'on parcoure un texte, il suffit de regarder pour chaque caractère, la liste de `search_tupple_t` associée. Un tableau de `search_list_item_t` est maintenu pour garder en mémoire l'avancement de la recherche pour chaque *item*.

La recherche de tous les éléments se fait ainsi en un unique parcours du texte.