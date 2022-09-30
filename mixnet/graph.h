#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "connection.h"
#include "address.h"

struct adjacency_node {
    mixnet_address vert;
    struct adjacency_node *next;
};
typedef struct adjacency_node* adj_node_t;

typedef struct {
    uint16_t size;
    adj_node_t **adj;
} graph_t;

// for iterating through all of the neighbors of a node
typedef struct {
    adj_node_t *next_neighbor;
} neighbors_t;

const uint8_t max_nodes = 10;

void graph_init(graph_t *graph, uint16_t size);
void graph_free(graph_t *graph);
void graph_add_edge(graph_t *graph, mixnet_address addr_A, mixnet_address addr_B);
neighbors_t *graph_get_neighbors(graph_t *graph, mixnet_address vert);
mixnet_address graph_next_neighbor(neighbors_t *nbors);