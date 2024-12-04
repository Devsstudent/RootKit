#ifndef FAST_SEARCH_H

# define FAST_SEARCH_H

# define MAX_ITEM_COUNT  256
# define KEY_MAX_LEN     256

typedef struct _item {
    unsigned char key_length;
    unsigned char value_length;
    
    char *key;
    char *value;
    
    struct _item *next;
} item_t;

typedef struct _search_tupple {
    unsigned char item_id;
    unsigned char char_index;    // position of the char

    struct _search_tupple *next;
} search_tupple_t;

typedef struct _search_map {
    unsigned char  item_count;
    item_t *item_list;

    search_tupple_t *tupples[256];
} search_map_t;

typedef struct _search_list_item {
    unsigned char item_length;
    item_t       *item_location;

    char *head;
    unsigned char search_advancement; 
    
    struct _search_list_item *next; // Used for result
} search_list_item_t;

search_map_t   *init_search_map(void);
void            free_search_map(search_map_t *map);
item_t         *add_item_to_map(search_map_t *map, const char *key, unsigned char key_length, const char *value, unsigned char value_length);
void            remove_item_from_map(search_map_t *map, char *key);

search_list_item_t *init_search_list(const search_map_t *map);
void                free_search_list(search_list_item_t *list, unsigned char items_count);
search_list_item_t *update_search_list(const search_map_t *map, search_list_item_t *list, char value, char *position);
#endif
