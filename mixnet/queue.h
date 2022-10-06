#ifndef QUEUE_NODE_H
#define QUEUE_NODE_H

#include "address.h"
#include <stdbool.h>


struct path_ele{
    mixnet_address addr;
    struct path_ele* next; //Downstream in the routing path
};
typedef struct path_ele path_t;

struct queue_ele{
    path_t* path; // Topologically connected routing Path  
    struct queue_ele* next;
};
typedef struct queue_ele elem_t;

struct mixnet_queue{
    elem_t* front;
};
typedef struct mixnet_queue queue_t;

queue_t* queue_init();
bool is_empty(queue_t* q);
bool  is_in_queue(queue_t* q, mixnet_address addr);
void print_path(path_t* p);
void print_queue(queue_t* q);

elem_t* pop(queue_t* q);
void add_item(queue_t* q, mixnet_address addr);
void add_path(queue_t* q, path_t* path);
path_t* get_end_of_path(path_t* path);
void extend_path(path_t* path, mixnet_address extension);

path_t* copy_path(path_t* path);


#endif // QUEUE_NODE_H