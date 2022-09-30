#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "graph.h"
#include "address.h"


void graph_init(graph_t *graph, uint16_t size){
    graph = malloc(sizeof(graph_t));
    graph->size = size;
    graph->adj= malloc(sizeof(adj_node_t*) * max_nodes);
    for(size_t i=0; i<max_nodes; i++){
         graph->adj[i]= malloc(sizeof(adj_node_t));
    }
    return;
}

void graph_free(graph_t *graph){
    for(size_t i=0; i<max_nodes; i++){
        queue_free(graph->adj[i]);
    }
    free(graph);
    return;
}

void graph_add_edge(graph_t *graph, mixnet_address addr_A, mixnet_address addr_B){
    adj_node_t *node;
    size_t idx_A = addr_A % graph->size;
    size_t idx_B = addr_B % graph->size;

    // add B as a neighbor of A
    node = malloc(sizeof(adj_node_t));
    node->vert = addr_B;
    node->next = graph->adj[idx_A];
    graph->adj[idx_A] = node;

    // add A as a neighbor of B
    node = malloc(sizeof(adj_node_t));
    node->vert = addr_A;
    node->next = graph->adj[idx_B];
    graph->adj[idx_B] = node;
}


neighbors_t *graph_get_neighbors(graph_t *graph, mixnet_address vert){
    neighbors_t *nbors = malloc(sizeof(neighbors_t));
    nbors->next_neighbor = graph->adj[vert % graph->size];
    return nbors;
}

// bool graph_hasmore_neighbors(neighbors_t *nbors) {
//     return nbors->next_neighbor != NULL;
// }

mixnet_address graph_next_neighbor(neighbors_t *nbors) {
    mixnet_address v = nbors->next_neighbor->vert;
    nbors->next_neighbor = nbors->next_neighbor->next;
    return v;
}

// void graph_free_neighbors(neighbors_t *nbors) {
//     free(nbors);
// }

