#include <linux/slab.h>

#include "fast_search.h"

static int _append_item_to_map(search_map_t *map, item_t *item) {
    item_t *current_item;
    unsigned int item_count = 1;
    
    current_item = map->item_list;
    if (current_item == NULL) {
        map->item_count = 1;
        map->item_list  = item;
        item->next = NULL;
        return 0;
    }

    while(current_item != NULL && item_count < MAX_ITEM_COUNT) {
        if (current_item->next == NULL) {
            map->item_count = item_count + 1;
            current_item->next = item;
            return item_count;
        }
        item_count += 1;
        current_item = current_item->next;
    }

    return -1;
}

static search_tupple_t *_add_tupple(search_tupple_t *list, search_tupple_t *tupple) {
    if (list == NULL) {
        return NULL;
    }
    
    if (list->char_index > tupple->char_index) {
        tupple->next = list;
        return tupple;
    }

    while (list->next != NULL && list->next->char_index <= tupple->char_index) {
        list = list->next;
    }
    
    tupple->next = list->next;
    list->next = tupple;

    return list;
}

search_map_t *init_search_map() {
    search_map_t *map;
    unsigned char i;

    map = kmalloc(sizeof(search_map_t), GFP_KERNEL);

    map->item_count = 0;
    map->item_list = NULL;
    for (i = 0; i < 255; i++) {
        map->tupples[i] = NULL;
    }

    return map;
}

void free_search_map(search_map_t *map) {
    return;
}

item_t *add_item_to_map(search_map_t *map, const char *key, unsigned char key_length, const char *value, unsigned char value_length) {
    item_t *new_item;
    search_tupple_t *tupples;

    unsigned char item_id;
    unsigned char i;

    new_item = kmalloc(sizeof(item_t), GFP_KERNEL);
    tupples  = kmalloc(sizeof(search_tupple_t) * key_length, GFP_KERNEL);
    new_item->key   = kmalloc(key_length  , GFP_KERNEL);
    new_item->value = kmalloc(value_length, GFP_KERNEL);

    memcpy(new_item->key  , key  , key_length);
    memcpy(new_item->value, value, value_length);

    new_item->key_length   = key_length;
    new_item->value_length = value_length;

    item_id = _append_item_to_map(map, new_item);
    if (item_id < 0) {
        // TODO : Error -> to many items
        return NULL;
    }

    for (i = 0; i < key_length; i++) {
        tupples->item_id = item_id;
        tupples->char_index = i;

        if (map->tupples[(unsigned char)key[i]] == NULL) {
            map->tupples[(unsigned char)key[i]] = tupples;
            tupples->next = NULL;
        }
        else {
            map->tupples[(unsigned char)key[i]] = _add_tupple(map->tupples[(unsigned char)key[i]], tupples);
        }

        tupples += 1;
    }

    return new_item;
}

void remove_item_from_map(search_map_t *map, char *key) {
    return;
}

search_list_item_t *init_search_list(const search_map_t *map) {
    search_list_item_t *search_list;
    item_t *current_item;

    unsigned char i;

    search_list = kmalloc(sizeof(search_list_item_t) * map->item_count, GFP_KERNEL);
    current_item = map->item_list;

    for (i = 0; i < map->item_count && current_item != NULL; i++) {
        search_list[i].item_length   = current_item->key_length;
        search_list[i].item_location = current_item;

        current_item = current_item->next;
        // if (current_item == NULL) {
        //     // TODO : Error
        //     printk(KERN_INFO "Failed to init List");
        //     return NULL;
        // }
    }

    return search_list;
}

void free_search_list(search_list_item_t *list, unsigned char items_count) {
    return;
}

search_list_item_t *update_search_list(const search_map_t *map, search_list_item_t *list, char value, char *position) {
    search_list_item_t *result = NULL;
    search_list_item_t *current_item;
    search_tupple_t *tupple;

    if (map == NULL || list == NULL) {
        return NULL;
    }

    tupple = map->tupples[(unsigned char)value];
    while (tupple != NULL) {
        current_item = list + tupple->item_id;
        // printk(KERN_INFO "%c -> %i (%i) : %i", value, tupple->item_id, tupple->char_index, current_item->search_advancement);

        if (current_item->head > position) {
            current_item->head = NULL;
        }

        if (current_item->search_advancement != 0 && position - current_item->head > current_item->search_advancement) {
            current_item->search_advancement = 0;
        }

        if (tupple->char_index == current_item->search_advancement) {
            if (current_item->search_advancement == 0) {
                current_item->head = position;
            }
            current_item->search_advancement += 1;
            if (current_item->search_advancement == current_item->item_length) {
                current_item->next = result;
                result = current_item;

                current_item->search_advancement = 0;
            }
        }

        tupple = tupple->next;
    }

    return result;
}