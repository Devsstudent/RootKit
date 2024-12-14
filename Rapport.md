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

## Overwriting des Syscalls avec ftrace

Une des techniques utilisées dans notre rootkit consiste à surcharger les appels systèmes (syscalls). Pour ce faire, nous avons utilisé **ftrace**, un outil intégré au noyau Linux qui permet de rediriger l'exécution des fonctions systèmes vers des versions personnalisées. Cela nous permet de modifier le comportement des syscalls sans nécessiter de modifications profondes du noyau, garantissant ainsi une plus grande furtivité.

### Utilisation de ftrace pour le hook des syscalls

Nous utilisons la structure `ftrace_hook` pour rediriger l'exécution des appels systèmes. Cette structure permet de spécifier le nom de la fonction à surcharger, la fonction de remplacement, et de stocker l'adresse de la fonction originale pour pouvoir y revenir si nécessaire. Concrètement, cela nous permet d'intercepter des appels systèmes comme `getdents` (qui liste les fichiers dans un répertoire) pour masquer certains fichiers ou processus afin de rendre notre rootkit invisible à l'utilisateur.
La fonction kallsyms_lookup_name, nous permet de recupérer le pointeur du syscall originel.

La fonction fh_ftrace_thunk est une handler, qui vas etre appeler lors d'un syscall sur `getdents` dans notre cas.
Ftrace nous permet de manipuler le pointeur d'instruction afin de rediriger l'exécution du programme vers notre function.
Les flags permettent d'autoriser, de definir les besoins de notre `overload`, recursion, passage des registres.

### Fonction `delayed` et vérification de la disponibilité du système

Avant de déployer pleinement notre rootkit, il est crucial de s'assurer que le système est complètement prêt. Pour cela, nous avons implémenté une fonction `delayed` qui s'exécute à intervalles réguliers. Cette fonction vérifie l'état du système et attend que toutes les conditions nécessaires (comme le montage du système de fichiers) soient réunies avant de lancer le rootkit. Cela permet d'éviter toute détection prématurée ou erreur durant le démarrage du système.

### Insertion dans `initttab` pour charger le rootkit au démarrage

Pour que notre rootkit soit chargé automatiquement à chaque démarrage de la machine, nous avons modifié le fichier `inittab`.

### Masquage des fichiers et des PIDs avec `getdents`

L'une des fonctionnalités clés de notre rootkit est le masquage des fichiers et des processus. Pour ce faire, nous avons surchargé l'appel système `getdents`, qui est utilisé pour lister les fichiers dans un répertoire. Lorsque cette fonction est appelée, notre version modifiée filtre certains fichiers et processus en fonction de critères spécifiques, comme l'existence de fichiers ou processus associés à notre rootkit ou à d'autres activités malveillantes. Cela permet de cacher des fichiers comme le binaire du rootkit ou des processus associés.

### En résumé

En résumé, notre rootkit est chargé automatiquement au démarrage du système. Après avoir attendu que le système soit complètement monté et prêt, il compile et exécute le compagnon (le "companion"). Ce dernier est conçu pour être invisible : il est masqué dans la liste des processus en cours d'exécution, et tout fichier ou répertoire associé à notre rootkit est également rendu invisible. Cela garantit que notre rootkit reste furtif tout au long de son exécution.

### Pistes d'amélioration

La meilleure solution serait de télécharger le compagnon sur la machine hôte.
De même, je n'ai pas réussi à cacher la ligne dans le fichier `inittab` lors de la lecture et de l'écriture.
Il y a également un "léger" manque de fonctionnalités au niveau de notre programme compagnon.

