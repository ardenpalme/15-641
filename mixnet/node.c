/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the Mixnet course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the Mixnet project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "node.h"
#include "connection.h"
#include "queue.h"
#include "graph.h"

#define DEBUG_FLOOD 0
#define DEBUG_STP 0
#define PRINT_CONV 0

typedef struct{
    mixnet_address root_address;
    uint16_t path_length;      
    mixnet_address next_hop_address;    
} stp_route_t;

// the node's database for current STP path to root node
static stp_route_t stp_route_db;

// STP functions
void broadcast_stp(void *handle, 
                   const struct mixnet_node_config config, 
                   stp_route_t *stp_route_db);
void print_stp(const struct mixnet_node_config config, const char *prefix_str, mixnet_packet *packet);
uint32_t STP_pkt_ct; // Metrics

// FLOOD functions
void broadcast_flood(void *handle, 
                     const struct mixnet_node_config config, 
                     uint8_t *active_ports);

// LSA and DATA functions
void broadcast_lsa(void *handle, 
                     const struct mixnet_node_config config, 
                     uint8_t *active_ports);

void fwd_lsa(void *handle, 
             const struct mixnet_node_config config, 
             uint8_t *active_ports,
             mixnet_address *neighbor_list,
             mixnet_address source,
             uint16_t neighbors_ct);

// maximum number of nodes in CP2 tests
const uint16_t max_test_nodes = 20;

// Generic functions 
void print_packet_header(mixnet_packet *pkt);
int get_port_from_addr(const struct mixnet_node_config config, mixnet_address next_hop_address, uint8_t *stp_ports);

// Port-handling functions
enum port_decision {BLOCK_PORT, OPEN_PORT};
void activate_all_ports(const struct mixnet_node_config config, uint8_t *ports);
void deactivate_all_ports(const struct mixnet_node_config config, uint8_t *ports);
void port_to_neighbor(const struct mixnet_node_config config, 
                            mixnet_address niegbhor_addr, 
                            uint8_t *ports, 
                            enum port_decision decision);
                            
void print_ports(const struct mixnet_node_config config, uint8_t *ports);

bool is_root(const struct mixnet_node_config config, stp_route_t *stp_route_db);

double diff_in_microseconds(struct timeval t0, struct timeval t1);

void get_shortest_paths(const struct mixnet_node_config config, graph_t *net_graph);

void send_packet_from_source(void* handle,
                            const struct mixnet_node_config config,
                            mixnet_packet* recvd_packet,
                            graph_t *net_graph);

void print_routes(graph_t* net_graph);

void fwd_data_packet(void* handle, const struct mixnet_node_config config, 
                    mixnet_packet* recvd_packet, graph_t* net_graph);



void run_node(void *handle,
              volatile bool *keep_running,
              const struct mixnet_node_config config) {

    // STP packet fowarding info (My Root, Path Length, Next Hop)
    // Initially, Node thinks it's the root
    stp_route_db.root_address = config.node_addr;
    stp_route_db.path_length = 0;
    stp_route_db.next_hop_address = config.node_addr;

    uint8_t *stp_ports = malloc(sizeof(uint8_t) * config.num_neighbors);  // ports to send STP route advertisements on during convergence period
    activate_all_ports(config, stp_ports); //Initially assume no ST created

    bool is_hello_root = true;
    bool root_never_broadcast_lsa = true;

    struct timeval root_hello_timer, root_hello_timer_start;
    struct timeval election_timer, election_timer_start;
    gettimeofday(&election_timer_start, NULL); //Initial reference point


                                                  
    mixnet_packet *recvd_packet = NULL;
    mixnet_address stp_parent_addr = -1;
    uint16_t stp_parent_path_length = -1;
    uint8_t recv_port;
    
    const int user_port = config.num_neighbors;
    
    graph_t *net_graph = graph_init();
    (void)graph_add_neighbors(net_graph, config.node_addr, config.neighbor_addrs, config.num_neighbors);
    
    // Broadcast (My Root, Path Length, My ID) initially 
    if (is_root(config, &stp_route_db)){
        broadcast_stp(handle, config, &stp_route_db);
        gettimeofday(&root_hello_timer_start, NULL); //Reset root hello timer start
    }    

    while (*keep_running) {

        // Send Root Hello at regular intervals 
        gettimeofday(&root_hello_timer, NULL);
        
        if(is_root(config, &stp_route_db)){
            if ((diff_in_microseconds(root_hello_timer_start, root_hello_timer) >= config.root_hello_interval_ms * 1000)){
                broadcast_stp(handle, config, &stp_route_db); 
                gettimeofday(&root_hello_timer_start, NULL); //Reset root hello timer start
            } 
        }

        /*** RECEIVE ***/
        int value = mixnet_recv(handle, &recv_port, &recvd_packet);
        if (value != 0) {
            switch (recvd_packet->type){
                
                //Run Spanning Tree Protocol updates. Brodcast root changes to neighbours as necessary
                case PACKET_TYPE_STP: {
                    STP_pkt_ct++;
                    
                    mixnet_packet_stp* recvd_stp_packet = (mixnet_packet_stp*) recvd_packet->payload;
                    is_hello_root = true;

                    // Receive STP message from smaller ID root node
                    // Make him root and increment path length
                    if(recvd_stp_packet->root_address < stp_route_db.root_address) {
                        is_hello_root = false;

                        stp_route_db.root_address = recvd_stp_packet->root_address;
                        stp_route_db.path_length = recvd_stp_packet->path_length + 1;
                        stp_route_db.next_hop_address = recvd_stp_packet->node_address;

                        stp_parent_addr = recvd_stp_packet->node_address;
                        stp_parent_path_length = recvd_stp_packet->path_length;                        

                        stp_ports[recv_port] = 1; //Open parent port

                        // tell everyone but informant about new best root candidate
                        stp_ports[recv_port] = 0;
                        broadcast_stp(handle, config, &stp_route_db);
                        stp_ports[recv_port] = 1;


                    }else if(recvd_stp_packet->root_address == stp_route_db.root_address) {
                        // Recieve from same ID, shorter path root node
                        // Follow his path instead, increment path length
                        if(recvd_stp_packet->path_length + 1 < stp_route_db.path_length) {
                            stp_route_db.next_hop_address = recvd_stp_packet->node_address;
                            stp_route_db.path_length = recvd_stp_packet->path_length + 1;
                                                        
                            stp_parent_addr = recvd_stp_packet->node_address;
                            stp_parent_path_length = recvd_stp_packet->path_length;   
                            
                            stp_ports[recv_port] = 1; //Open parent port
                            is_hello_root = false;   
                        
                        //Tie for ID and path length
                        } else if (stp_parent_addr != -1 && recvd_stp_packet->path_length == stp_parent_path_length){
                            
                            if (recvd_stp_packet->node_address < stp_parent_addr){
                                // Close port for to-be-removed parent. Open port for new parent
                                port_to_neighbor(config, stp_parent_addr, stp_ports, BLOCK_PORT);
                                port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, OPEN_PORT);

                                // choose lesser indexed node to route through
                                stp_route_db.next_hop_address = recvd_stp_packet->node_address;
                                stp_parent_addr = recvd_stp_packet->node_address;         
                                
                                is_hello_root = false;

                            }else if (recvd_stp_packet->node_address > stp_parent_addr){
                                // Close port for failed parent candidate
                                port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, BLOCK_PORT);
                                
                                is_hello_root = false;
                            }
                        } else {
                            is_hello_root = false;
                        }

                        // If path advertised is equal to path length, node must be peer, not {child, parent} 
                        if (recvd_stp_packet->path_length == stp_route_db.path_length){
                                stp_ports[recv_port] = 0;
                        }
                    } else {
                        is_hello_root = false;
                        port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, OPEN_PORT); //Open child port
                    }

                    if (!is_root(config, &stp_route_db) && is_hello_root) {
                        
                        stp_ports[recv_port] = 0;
                        broadcast_stp(handle, config, &stp_route_db);
                        stp_ports[recv_port] = 1;
                        
                        // On STP, convergence start LSA via a non-root node
                        broadcast_lsa(handle, config, stp_ports);

                        gettimeofday(&election_timer_start, NULL); // On receiving hello root, reset election timer
                         
                    }

                    
                } break;

                case PACKET_TYPE_FLOOD: {

                    // Packet received on INPUT port. Flood as is
                    if(recv_port == user_port) {
                        broadcast_flood(handle, config, stp_ports);
                    }

                    if(stp_ports[recv_port] && recv_port != user_port) {

                        // Forward received FLOOD from neighbour via OUTPUT port to user stack
                        int err=0;
                        if( (err = mixnet_send(handle, user_port, recvd_packet)) < 0){
                            printf("Error sending FLOOD pkt to user\n");
                        }

                        // Temporarily block receiving port while broadcasting to other neighbours
                        stp_ports[recv_port] = 0;
                        broadcast_flood(handle, config, stp_ports);
                        stp_ports[recv_port] = 1;
                    }                    
                } break;
                                        
                case PACKET_TYPE_LSA: {
                    //Hack to ensure stable root participates in LSA w/o spamming network
                    if (is_root(config, &stp_route_db) && root_never_broadcast_lsa){
                        broadcast_lsa(handle, config, stp_ports);
                        root_never_broadcast_lsa = false;
                    }

                    mixnet_packet_lsa* recvd_lsa_packet = (mixnet_packet_lsa*) recvd_packet->payload;
                    mixnet_address *neighbor_node_list = (mixnet_address*)(recvd_lsa_packet + 1);

                    
                    // printf("[%u] received LSA from source %u with neighbors {", config.node_addr, recvd_lsa_packet->node_address);
                    // for(int i=0; i<recvd_lsa_packet->neighbor_count; i++) {
                    //     printf("%u", neighbor_node_list[i]);
                    //     if(i < recvd_lsa_packet->neighbor_count -1) 
                    //         printf(", ");
                    // }
                    // printf("}\n");
                    

                    bool updated = graph_add_neighbors(net_graph, recvd_lsa_packet->node_address, 
                                                        neighbor_node_list, recvd_lsa_packet->neighbor_count);
                    // printf("Had an LSA update res %d,  Node %u's Internal Graph:\n", updated, config.node_addr);
                    // print_graph(net_graph);
                    // printf("====================\n");
                    if (updated) get_shortest_paths(config, net_graph);


                    // Temporarily block receiving port while forwarding to other neighbours
                    stp_ports[recv_port] = 0;
                    fwd_lsa(handle, config, stp_ports, neighbor_node_list, recvd_lsa_packet->node_address, recvd_lsa_packet->neighbor_count);
                    stp_ports[recv_port] = 1;

                } break;

                case PACKET_TYPE_DATA: {
                    printf("[%u]", config.node_addr);
                    print_graph(net_graph);
                    // Source route new packet
                    if (recv_port == user_port){
                        // print_routes(net_graph);
                        printf("Entering send packet from source\n");
                        send_packet_from_source(handle, config, recvd_packet, net_graph);

                    // Packet arrived at destination send to user stack
                    } else if (recvd_packet->dst_address == config.node_addr){
                        int err = 0;
                        if( (err = mixnet_send(handle, user_port, recvd_packet)) < 0){
                            printf("Error sending FLOOD pkt to user\n");
                        }

                    // Packet along forwarding route, forward packet
                    } else {
                        // printf("Entering fwding data packet\n");
                        fwd_data_packet(handle, config, recvd_packet, net_graph);
                    }
                } break;
                default: break;
            }
        } else {
            gettimeofday(&election_timer, NULL);
            if ((!is_root(config, &stp_route_db) && diff_in_microseconds(election_timer_start, election_timer) >= config.reelection_interval_ms * 1000)){
                gettimeofday(&election_timer_start, NULL);
                
                // Node thinks it's now the root. Forget about stale spanning tree
                stp_route_db.root_address = config.node_addr;
                stp_route_db.path_length = 0;
                stp_route_db.next_hop_address = config.node_addr;
                activate_all_ports(config, stp_ports);
                stp_parent_addr = -1;
                stp_parent_path_length = -1;

                //Reset hello_timer_start
                broadcast_stp(handle, config, &stp_route_db);
                gettimeofday(&root_hello_timer_start, NULL); 

            }

        }

    }
} 

void broadcast_stp(void *handle, 
                   const struct mixnet_node_config config, 
                   stp_route_t *stp_route_db)
{
    mixnet_packet_stp stp_payload;
    int err=0;
    for (size_t nid = 0; nid < config.num_neighbors; nid++) {
        mixnet_packet* broadcast_packet = malloc(sizeof(mixnet_packet) + sizeof(mixnet_packet_stp));
        broadcast_packet->src_address = config.node_addr;
        broadcast_packet->dst_address = config.neighbor_addrs[nid];
        broadcast_packet->type = PACKET_TYPE_STP;
        broadcast_packet->payload_size = sizeof(mixnet_packet_stp);

        stp_payload.root_address = stp_route_db->root_address;
        stp_payload.path_length = stp_route_db->path_length;
        stp_payload.node_address = config.node_addr;

        memcpy(broadcast_packet->payload, &stp_payload, sizeof(mixnet_packet_stp));

        if( (err = mixnet_send(handle, nid, broadcast_packet)) < 0) {
            printf("Error sending STP pkt\n");
        }
    }
}

void broadcast_flood(void *handle, 
                     const struct mixnet_node_config config, 
                     uint8_t *active_ports) 
{
    int err=0;
    mixnet_packet *flood_pkt;

    for (size_t nid = 0; nid < config.num_neighbors; nid++) {
        if(active_ports[nid]) {
            flood_pkt = malloc(sizeof(mixnet_packet)); // flood packet received to be broadcast across STP tree
            flood_pkt->src_address = 0;
            flood_pkt->dst_address = 0;
            flood_pkt->type = PACKET_TYPE_FLOOD;
            flood_pkt->payload_size = 0;

            if( (err = mixnet_send(handle, nid, flood_pkt)) < 0){
                printf("Error sending FLOOD pkt\n");
            }

            #if DEBUG_FLOOD
            printf("[%u] Broadcast FLOOD to Node %u\n", 
                config.node_addr,
                config.neighbor_addrs[nid]);
            #endif 
        }
    }
}

void broadcast_lsa(void *handle, 
                     const struct mixnet_node_config config, 
                     uint8_t *active_ports) 
{
    int err=0;
    mixnet_packet *lsa_pkt;
    mixnet_packet_lsa lsa_payload;

    mixnet_address neighbor_list[max_test_nodes];
    for (size_t i = 0; i < config.num_neighbors; i++) { 
        neighbor_list[i] = config.neighbor_addrs[i];
    }

    for (size_t nid = 0; nid < config.num_neighbors; nid++) {
        if(active_ports[nid]) {
            lsa_pkt = malloc(sizeof(mixnet_packet) 
                            + sizeof(mixnet_packet_lsa) 
                            + (sizeof(mixnet_address)*config.num_neighbors)); // lsa packet received to be broadcast across STP tree

            lsa_pkt->src_address = config.node_addr;
            lsa_pkt->dst_address = config.neighbor_addrs[nid];
            lsa_pkt->type = PACKET_TYPE_LSA;
            lsa_pkt->payload_size = 4 + (2*config.num_neighbors);

            lsa_payload.node_address = config.node_addr;
            lsa_payload.neighbor_count = config.num_neighbors;
            memcpy(lsa_pkt->payload, &lsa_payload, sizeof(mixnet_packet_lsa));

            mixnet_address* neighbours_start = (mixnet_address*)(((mixnet_packet_lsa*)lsa_pkt->payload) + 1);
            memcpy(neighbours_start, neighbor_list, sizeof(mixnet_address) * config.num_neighbors);

            if( (err = mixnet_send(handle, nid, lsa_pkt)) < 0){
                printf("Error sending LSA pkt\n");
            }

            // printf("[%u] Sent LSA to Node %u\n", 
            //     config.node_addr,
            //     config.neighbor_addrs[nid]);
        }
    }
}

void fwd_lsa(void *handle, 
             const struct mixnet_node_config config, 
             uint8_t *active_ports,
             mixnet_address *neighbor_list,
             mixnet_address source,
             uint16_t neighbors_ct)
{
    for (size_t nid = 0; nid < neighbors_ct; nid++) {
        if(active_ports[nid]) {
            int err=0;

            mixnet_packet *lsa_pkt = malloc(sizeof(mixnet_packet) 
                            + sizeof(mixnet_packet_lsa) 
                            + (sizeof(mixnet_address) * neighbors_ct)); 

            lsa_pkt->src_address = config.node_addr;
            lsa_pkt->dst_address = config.neighbor_addrs[nid];
            lsa_pkt->type = PACKET_TYPE_LSA;
            lsa_pkt->payload_size = 4 + (2*neighbors_ct);

            mixnet_packet_lsa* lsa_payload = (mixnet_packet_lsa*)lsa_pkt->payload;
            lsa_payload->neighbor_count = neighbors_ct;
            lsa_payload->node_address = source;

            mixnet_address* neighbours_start = (mixnet_address*)(lsa_payload + 1);
            memcpy(neighbours_start, neighbor_list, sizeof(mixnet_address) * neighbors_ct);

            if((err = mixnet_send(handle, nid, lsa_pkt)) < 0) {
                printf("Error fwd LSA pkt\n");
            }

            // printf("[%u] Forwaded LSA of source %u to Node %u\n", 
            //     config.node_addr,
            //     source,
            //     config.neighbor_addrs[nid]);
        }
    }
}

void send_packet_from_source(void* handle,
                            const struct mixnet_node_config config,
                            mixnet_packet* recvd_packet,
                            graph_t *net_graph){

    // Get hop length (initially for malloc purposes)                           
    path_t* hop_list = get_adj_vertex(net_graph, recvd_packet->dst_address)->hop_list;
    u_int32_t cnt = 0;
    while (hop_list != NULL){
        if (hop_list->addr == recvd_packet->dst_address) break;    
        hop_list = hop_list->next;
        cnt++;
    }

    size_t tot_size = sizeof(mixnet_packet) +
                                    sizeof(mixnet_packet_routing_header) +
                                    (cnt * sizeof(mixnet_address)) + 
                                    recvd_packet->payload_size; //ED says on testcases payload size == data size
    mixnet_packet* data_packet =  malloc(tot_size);

    //Write Hop path details to data packet
    mixnet_packet_routing_header* rt_header = (mixnet_packet_routing_header*)data_packet->payload;
    rt_header->route_length = cnt;
    rt_header->hop_index = 0;

    //Write data to data packet
    char* orig_data = (char*)(((mixnet_packet_routing_header*)(recvd_packet->payload)) + 1);
    char* copy_data = (char*)(((mixnet_address*)(rt_header + 1)) + cnt);
    memcpy(copy_data, orig_data, sizeof(char) * recvd_packet->payload_size);

    mixnet_address* hop_start = (mixnet_address*)(rt_header + 1);
    hop_list = get_adj_vertex(net_graph, recvd_packet->dst_address)->hop_list;
    cnt = 0;
    while (hop_list != NULL){
        if (hop_list->addr == recvd_packet->dst_address) break;    
        hop_start[cnt] = hop_list->addr;
        hop_list = hop_list->next;
        cnt++;
  
    }

    //Write other info to data packet
    data_packet->src_address = config.node_addr;
    data_packet->dst_address = recvd_packet->dst_address;
    data_packet->payload_size = tot_size - (sizeof(mixnet_packet));
    data_packet->type = PACKET_TYPE_DATA;

    int err = 0;
    for (size_t i=0; i < config.num_neighbors; i++){
        //Consider hop table might be empty. Source route direct to neighbour
        if ((rt_header->route_length == 0 && config.neighbor_addrs[i] == data_packet->dst_address) ||
            (rt_header->route_length != 0 && config.neighbor_addrs[i] == hop_start[rt_header->hop_index])){
            if((err = mixnet_send(handle, i, data_packet)) < 0) {
                printf("Error sending DATA pkt\n");
            }

            printf("[%u] Source began send data packet sequence to Node %u via  hop %u\n", 
                config.node_addr,
                recvd_packet->dst_address,
                config.neighbor_addrs[i]);
            break;
        }           
    }   
}

void fwd_data_packet(void* handle, const struct mixnet_node_config config, 
                    mixnet_packet* recvd_packet, graph_t* net_graph){

    mixnet_packet_routing_header* rcvd_header = (mixnet_packet_routing_header*)recvd_packet->payload;
    size_t tot_size = sizeof(mixnet_packet) +
                                    sizeof(mixnet_packet_routing_header) +
                                    (rcvd_header->route_length * sizeof(mixnet_address)) + 
                                    recvd_packet->payload_size;  //ED says testcases ==> data size
    mixnet_packet* data_packet = malloc(tot_size);
    
    //Copy old values while fwding 
    memcpy(data_packet, recvd_packet, tot_size);

    // Increment hop index
    mixnet_packet_routing_header* rt_header = (mixnet_packet_routing_header*)data_packet->payload;
    rt_header->hop_index++;
    
    int err = 0;
    mixnet_address* hop_start = (mixnet_address*)(rt_header + 1);
    for (size_t i=0; i < config.num_neighbors; i++){
        //Consider hop table might be empty. Source route direct to neighbour
        if ((rt_header->route_length == rt_header->hop_index && config.neighbor_addrs[i] == data_packet->dst_address) ||
            (rt_header->route_length > rt_header->hop_index && config.neighbor_addrs[i] == hop_start[rt_header->hop_index])){
            if((err = mixnet_send(handle, i, data_packet)) < 0) {
                printf("Error sending DATA pkt\n");
            }

            printf("Node [%u] forwaded data packet sent from %u meant for %u to next hop %u \n", 
                config.node_addr,
                recvd_packet->src_address,
                recvd_packet->dst_address,
                config.neighbor_addrs[i]);
            break;        
        }
    }
}



void print_stp(const struct mixnet_node_config config, const char *prefix_str, mixnet_packet *packet){
    mixnet_packet_stp *stp_payload = (mixnet_packet_stp*) packet->payload;
    printf("[%u] %s (%u, %u, %u)\n", config.node_addr, prefix_str, stp_payload->root_address, stp_payload->path_length, stp_payload->node_address);
}

// Consistency check between incoming STP message and maintained stp_route info
bool is_root(const struct mixnet_node_config config, stp_route_t *stp_route_db){
    return config.node_addr == stp_route_db->root_address;
}


void activate_all_ports(const struct mixnet_node_config config, uint8_t *ports){
    for(int nid=0; nid<config.num_neighbors; nid++){
        ports[nid] = 1;
    }
}

void deactivate_all_ports(const struct mixnet_node_config config, uint8_t *ports){
    for(int nid=0; nid<config.num_neighbors; nid++){
        ports[nid] = 0;
    }
}

// Blocks or unblocks a node's neighbour's allocated port
void port_to_neighbor(const struct mixnet_node_config config, 
                        mixnet_address niegbhor_addr, 
                        uint8_t *ports, 
                        enum port_decision decision) {
    
    for(int nid=0; nid<config.num_neighbors; nid++){
        if(config.neighbor_addrs[nid] == niegbhor_addr){

            if(decision == BLOCK_PORT)
                ports[nid] = 0;
            else if(decision == OPEN_PORT)
                ports[nid] = 1;      
            break;
        }
    } 
}

void get_shortest_paths(const struct mixnet_node_config config, graph_t *net_graph){
    queue_t* routes = queue_init();
    queue_t* tmp_routes = queue_init();
    queue_t* seen = queue_init();    
    
    add_item(seen, config.node_addr);
    // Add first level of BFS tree
    for (uint32_t i=0; i < config.num_neighbors; i++){
        add_item(routes, config.neighbor_addrs[i]); 
    }

    // printf("Internal Graph \n");
    // print_graph(net_graph);
    // printf("==================\n");

    while (true){
        // printf("[%u] Current traversal status\n", config.node_addr);
        // print_queue(routes);
        while(!is_empty(routes)){
           
            path_t* popped_path = pop(routes)->path;
            mixnet_address node = get_end_of_path(popped_path)->addr;
            // printf("Routes after popping path with end node %u\n", node);
            // print_queue(routes);

            adj_vert_t* node_info = get_adj_vertex(net_graph, node);
            if(!is_in_queue(seen, node)) {
                add_item(seen, node);

                //First time dst is seen in BFS should be shortest path
                node_info->hop_list = copy_path(popped_path); 
            }
            // printf("Computed route to node %u\n", node);
            // print_path(node_info->hop_list); 
            // printf("\n");
            
            bool single_desc = true;
            adj_node_t* neighbours = node_info->adj_list;
            // printf("Neighbours of end node %u\n", node);
            // print_adj_list(neighbours);
            while(neighbours != NULL){
                if (is_in_queue(seen, neighbours->addr)){
                    neighbours = neighbours->next;
                    continue;
                }

                //Using information of preceeding hop, extend path of route          
                // Create new unique route if parent node splits into multiple children
                path_t* branch_off;
                if (!single_desc){
                    branch_off = copy_path(popped_path);
                }else{
                    single_desc = false;
                    branch_off = popped_path;
                }

                extend_path(branch_off, neighbours->addr);
                add_path(tmp_routes, branch_off);
                // printf("Tmp routes after latest extension\n");
                // print_queue(tmp_routes);

                neighbours = neighbours->next;
            }
        }

        //Add new terminal nodes to queue
        if (is_empty(tmp_routes)) break;
        routes->front = tmp_routes->front;
        tmp_routes->front = NULL;

        // printf("Tmp routes then routes b4 loop again\n");
        // print_queue(tmp_routes);
        // print_queue(routes);
    }
}

void print_ports(const struct mixnet_node_config config, uint8_t *ports){
    printf("[%u] Ports [", config.node_addr);
    for(int nid=0; nid<config.num_neighbors; nid++){
        printf("%u", config.neighbor_addrs[nid]);
        if(nid != config.num_neighbors-1)
            printf(", ");
    }
    printf("]\n");

    printf("[%u]       [", config.node_addr);
    for(int nid=0; nid<config.num_neighbors; nid++){
        printf("%u", ports[nid]);
        if(nid != config.num_neighbors-1)
            printf(", ");
    }
    printf("]\n");
}

void print_packet_header(mixnet_packet *packet) {
    printf("Packet from %u to %u type %u payload_size %u\n",
        packet->src_address,
        packet->dst_address,
        packet->type,
        packet->payload_size);
}

int get_port_from_addr(const struct mixnet_node_config config, mixnet_address next_hop_address, uint8_t *stp_ports){
    for(int nid=0; nid<config.num_neighbors; nid++){
        if(config.neighbor_addrs[nid] == next_hop_address) {
            if(stp_ports[nid]) return nid;
            else               return -1;
        }
    }
    return -1;
}


double diff_in_microseconds(struct timeval b4, struct timeval later){
    return (later.tv_sec - b4.tv_sec) * 1000000 + (later.tv_usec - b4.tv_usec);
}

void print_routes(graph_t* net_graph){

    adj_vert_t* tmp = net_graph->head;
    while (tmp != NULL){
        printf("Routing path for node %u:", tmp->addr);
        print_path(tmp->hop_list);
        printf("\n");
        tmp = tmp->next_vert;
    }
}
