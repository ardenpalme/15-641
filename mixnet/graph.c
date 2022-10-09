#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdbool.h>

#include "connection.h"
#include "address.h"
#include "graph.h"

bool adj_list_has_node(graph_t *net_graph, adj_vert_t *adj_vertex, mixnet_address node_addr);
adj_vert_t *find_vertex(graph_t *net_graph, mixnet_address vert_node);

void print_graph(graph_t *net_graph);

graph_t *graph_init(void) {
    graph_t *graph = malloc(sizeof(graph_t));
    graph->head = NULL;
    graph->tail = NULL;
    graph->num_vert = 0;
    return graph;
}

bool graph_add_neighbors(graph_t *net_graph, mixnet_address vert_node, mixnet_address *node_list, uint16_t node_count) {
    adj_vert_t *adj_vertex = get_adj_vertex(net_graph, vert_node);
    adj_node_t *node;
    adj_node_t *search_node;
    bool node_in_graph = false;
    bool added = false;

    for(uint16_t node_idx=0; node_idx < node_count; node_idx++){
        node_in_graph = adj_list_has_node(net_graph, adj_vertex, node_list[node_idx]);
        
        if(!node_in_graph) {
            adj_vertex->num_children += 1;
            added = true;
            node = malloc(sizeof(adj_node_t));
            node->addr = node_list[node_idx];
            node->next = NULL;

            // Insert neighbour at start of vertex adjacency list
            if(adj_vertex->adj_list == NULL){
                adj_vertex->adj_list = node;

            // Insert neighbour at end of vertex adjacency list
            }else{
                search_node = adj_vertex->adj_list;
                while(search_node->next != NULL){
                    search_node = search_node->next;
                }

                search_node->next = node;
            }
        }
    }
    return added;
}

bool adj_list_has_node(graph_t *net_graph, adj_vert_t *adj_vertex, mixnet_address node_addr) {
    adj_node_t *search_node;
    search_node = adj_vertex->adj_list;
    bool found_node = false;

    while(search_node != NULL) {
        if(search_node->addr == node_addr) {
            found_node = true;
            break;
        }
        search_node = search_node->next;
    }
    
    return found_node;
}

adj_vert_t *get_adj_vertex(graph_t *net_graph, mixnet_address vert_node) {
    adj_vert_t *adj_vertex;
    adj_vert_t *search_vert; 

    // no ele in vert list
    if(net_graph->head == NULL && net_graph->tail == NULL && net_graph->num_vert == 0) {
        adj_vertex = malloc(sizeof(adj_vert_t));
        adj_vertex->addr = vert_node;
        adj_vertex->num_children = 0;
        adj_vertex->adj_list = NULL;
        adj_vertex->next_vert = NULL;

        net_graph->head = adj_vertex;
        net_graph->tail = adj_vertex;
        net_graph->num_vert++;

    // one ele in vert list
    }else if(net_graph->head == net_graph->tail && net_graph->num_vert == 1) {

        // is the vertex we're looking for, the only one that is in the vertex list?
        if(net_graph->head->addr == vert_node) {
            adj_vertex = net_graph->head;

        }else{
            adj_vertex = malloc(sizeof(adj_vert_t));
            adj_vertex->addr = vert_node;
            adj_vertex->num_children = 0;
            adj_vertex->adj_list = NULL;
            adj_vertex->next_vert = NULL;
            
            net_graph->tail = adj_vertex;
            net_graph->head->next_vert = adj_vertex;
            net_graph->num_vert++;
        }
        
    // two or more ele in vert list
    }else{
        search_vert = find_vertex(net_graph, vert_node);
        if(search_vert != NULL && search_vert->addr == vert_node) {
            adj_vertex = search_vert;
        }else{
            adj_vertex = malloc(sizeof(adj_vert_t));
            adj_vertex->addr = vert_node;
            adj_vertex->num_children = 0;
            adj_vertex->adj_list = NULL;
            adj_vertex->next_vert = NULL;

            net_graph->tail->next_vert = adj_vertex;        
            net_graph->tail = adj_vertex;  
            net_graph->num_vert++;      
        }
    }
    return adj_vertex;
}

adj_vert_t *find_vertex(graph_t *net_graph, mixnet_address vert_node) {
    adj_vert_t *search_vert = net_graph->head;

    while(search_vert != NULL){
        if(search_vert->addr == vert_node) {
            return search_vert;
        }
        search_vert = search_vert->next_vert;
    }
    return NULL;
}

void print_adj_list(adj_node_t* adj){
    adj_node_t* curr = adj;
    printf("[");
    while(curr != NULL){
        printf("%u ", curr->addr);
        curr = curr->next;
    }
    printf("]\n");
}


void print_graph(graph_t *net_graph) {
    adj_vert_t *vert = net_graph->head;
    adj_node_t *node;

    while(vert != NULL) {
        node = vert->adj_list;
        printf("%u: [ ", vert->addr);
        while(node != NULL){
            printf("%u ", node->addr);
            node = node->next;
        }

        printf("]; ");
        printf("(%u) ",vert->num_children);
        print_path(vert->hop_list);
        printf("\n");
        vert = vert->next_vert; 
    }
    printf("\n");
}
