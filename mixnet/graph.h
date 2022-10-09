#ifndef GRAPH_H
#define GRAPH_H

#include "connection.h"
#include "address.h"
#include "queue.h"

struct adjacency_node {
    mixnet_address addr;
    struct adjacency_node *next;
};
typedef struct adjacency_node adj_node_t;

struct adjacency_vert {
    mixnet_address addr;
    adj_node_t *adj_list; // Node's list of neighbours
    path_t *hop_list; //Path to get to node
    uint16_t num_children;
    struct adjacency_vert *next_vert;
};
typedef struct adjacency_vert adj_vert_t;

typedef struct {
    adj_vert_t *head;
    adj_vert_t *tail;
    uint16_t    num_vert;
} graph_t;

graph_t *graph_init(void);
adj_vert_t *get_adj_vertex(graph_t *net_graph, mixnet_address vert_node);
bool graph_add_neighbors(graph_t *net_graph, mixnet_address vert_node, mixnet_address *node_list, uint16_t node_count);
void print_adj_list(adj_node_t* adj);
void print_graph(graph_t *net_graph);
void verify_graph(graph_t *net_graph);

#endif 