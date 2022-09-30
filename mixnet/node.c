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
//TODO: why create this here. Should be 1 per node right?
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

    struct timeval root_hello_timer, root_hello_timer_start;
    struct timeval election_timer, election_timer_start;
    gettimeofday(&election_timer_start, NULL); //Initial reference point


    struct timeval convergence_timer_start, convergence_timer;
                                                  //
    mixnet_packet *recvd_packet = NULL;
    mixnet_packet_stp *recvd_stp_packet = NULL;
    mixnet_packet_lsa *recvd_lsa_packet = NULL;
    mixnet_address stp_parent_addr = -1;
    uint16_t stp_parent_path_length = -1;
    uint8_t recv_port;
    
    int err=0;
    const int user_port = config.num_neighbors;
    bool printed_convergence= false;
    
    graph_t *net_graph = graph_init();
    
    // Broadcast (My Root, Path Length, My ID) initially 
    if (is_root(config, &stp_route_db)){
        broadcast_stp(handle, config, &stp_route_db);
        gettimeofday(&root_hello_timer_start, NULL); //Reset root hello timer start
    }

    gettimeofday(&convergence_timer_start, NULL); // On receiving hello root, reset election timer
    

    while (*keep_running) {

        // Send Root Hello at regular intervals 
        gettimeofday(&root_hello_timer, NULL);
        if(is_root(config, &stp_route_db) && 
            ((diff_in_microseconds(root_hello_timer_start, root_hello_timer) >= config.root_hello_interval_ms * 1000))) {
            broadcast_stp(handle, config, &stp_route_db); 
            gettimeofday(&root_hello_timer_start, NULL); //Reset root hello timer start
        }

        /*** RECEIVE ***/
        int value = mixnet_recv(handle, &recv_port, &recvd_packet);
        if (value != 0) {
            switch (recvd_packet->type){
                
                //Run Spanning Tree Protocol updates. Brodcast root changes to neighbours as necessary
                case PACKET_TYPE_STP: {
                    STP_pkt_ct++;

                    if (!is_root(config, &stp_route_db) && is_hello_root) {
                        
                        // Convergence Metrics
                        if(!printed_convergence){
                            gettimeofday(&convergence_timer, NULL); 
                            #if PRINT_CONV
                            printf("[%u] @ %lf us: (my_root: %u, path_len: %u, next_hop: %u) -- in %u STP packets\n", 
                                config.node_addr,
                                diff_in_microseconds(convergence_timer_start, convergence_timer) / 1000.0,
                                stp_route_db.root_address,
                                stp_route_db.path_length,
                                stp_route_db.next_hop_address,
                                STP_pkt_ct);
                            #endif
                            printed_convergence = true;
                        }

                        broadcast_lsa(handle, config, stp_ports);
                    }
                    
                    recvd_stp_packet = (mixnet_packet_stp*) recvd_packet->payload;
                    is_hello_root = true;

                    #if DEBUG_STP
                    printf("STP msg from: %u with root: %u, path length: %u, Node [%u] curr root:%u, curr parent %u \n", 
                        recvd_stp_packet->node_address, 
                        recvd_stp_packet->root_address, 
                        recvd_stp_packet->path_length,
                        config.node_addr,
                        stp_route_db.root_address,
                        stp_parent_addr);

                    print_ports(config, stp_ports);
                    #endif

                    // Receive STP message from smaller ID root node
                    // Make him root and increment path length
                    if(recvd_stp_packet->root_address < stp_route_db.root_address) {
                        is_hello_root = false;
                        // printf("New Root node is %d Next hop is %u \n.", 
                        // recvd_stp_packet->root_address, recvd_stp_packet->node_address);
                        // print_ports(config, stp_ports);

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
                            
                            // printf("Found better path to same root %u with node %u pathlen %u \n", recvd_stp_packet->root_address, recvd_stp_packet->node_address, recvd_stp_packet->path_length);
                            // print_ports(config, stp_ports);

                            
                            stp_parent_addr = recvd_stp_packet->node_address;
                            stp_parent_path_length = recvd_stp_packet->path_length;   
                            
                            stp_ports[recv_port] = 1; //Open parent port
                            is_hello_root = false;   
                        
                        //Tie for ID and path length
                        } else if (stp_parent_addr != -1 && recvd_stp_packet->path_length == stp_parent_path_length){
                            // printf("Tied for ID & parent pathlen with node %u pathlen %u \n", recvd_stp_packet->node_address, recvd_stp_packet->path_length);
                            // printf("Parent %u recvd_node_addr %u \n", stp_parent_addr, recvd_stp_packet->node_address);
                            
                            if (recvd_stp_packet->node_address < stp_parent_addr){
                                // Close port for to-be-removed parent. Open port for new parent
                                port_to_neighbor(config, stp_parent_addr, stp_ports, BLOCK_PORT);
                                port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, OPEN_PORT);

                                // printf("Choosing smaller ID path via node %u \n", recvd_stp_packet->node_address);
                                // choose lesser indexed node to route through
                                stp_route_db.next_hop_address = recvd_stp_packet->node_address;
                                stp_parent_addr = recvd_stp_packet->node_address;         
                                
                                is_hello_root = false;

                            }else if (recvd_stp_packet->node_address > stp_parent_addr){
                                // Close port for failed parent candidate
                                // printf("Severing link in other direction \n");
                                port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, BLOCK_PORT);
                                // print_ports(config, stp_ports);
                                
                                is_hello_root = false;
                            }
                        } else {
                            is_hello_root = false;
                        }

                        // If path advertised is equal to path length, node must be peer, not {child, parent} 
                        if (recvd_stp_packet->path_length == stp_route_db.path_length){
                                // printf("Tied for ID & pathlen with node %u pathlen %u \n", recvd_stp_packet->node_address, recvd_stp_packet->path_length);
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

                        gettimeofday(&election_timer_start, NULL); // On receiving hello root, reset election timer
                        
                    }
                    
                    #if DEBUG_STP
                    printf("[%u] STP DB: (my_root: %u, path_len: %u, next_hop: %u)\n", 
                        config.node_addr, 
                        stp_route_db.root_address,
                        stp_route_db.path_length,
                        stp_route_db.next_hop_address);
                    print_ports(config, stp_ports);
                    #endif

                    } break;

                case PACKET_TYPE_FLOOD: {

                    // Packet received on INPUT port. Flood as is
                    if(recv_port == user_port) {
                        #if DEBUG_FLOOD
                        printf("[%u] Received FLOOD packet from user\n", config.node_addr);
                        #endif
                        broadcast_flood(handle, config, stp_ports);
                    }

                    if(stp_ports[recv_port] && recv_port != user_port) {
                        #if DEBUG_FLOOD
                        printf("[%u] Received FLOOD packet from Node %u\n", config.node_addr, config.neighbor_addrs[recv_port]);
                        #endif

                        // Forward received FLOOD from neighbour via OUTPUT port to user stack
                        if( (err = mixnet_send(handle, user_port, recvd_packet)) < 0){
                            printf("Error sending FLOOD pkt to user\n");
                        }

                        // Temporarily block receiving port while broadcasting to other neighbours
                        stp_ports[recv_port] = 0;
                        broadcast_flood(handle, config, stp_ports);
                        stp_ports[recv_port] = 1;

                        #if DEBUG_FLOOD
                        printf("[%u] Delivered FLOOD pkt to user\n", config.node_addr);
                        #endif
                    }                    
                    } break;
                                        
                case PACKET_TYPE_LSA: {
                    recvd_lsa_packet = (mixnet_packet_lsa*) recvd_packet->payload;
                    mixnet_address *neighbor_node_list = (mixnet_address*) ((uint8_t*)&(recvd_packet->payload) + sizeof(mixnet_packet_lsa));

                    
                    printf("[%u] node %u has neighbors {", config.node_addr, recvd_lsa_packet->node_address);
                    for(int i=0; i<recvd_lsa_packet->neighbor_count; i++) {
                        printf("%u", neighbor_node_list[i]);
                        if(i < recvd_lsa_packet->neighbor_count -1) 
                            printf(", ");
                    }
                    printf("}\n");
                    

                    graph_add_neighbors(net_graph, recvd_lsa_packet->node_address, neighbor_node_list, recvd_lsa_packet->neighbor_count);
                    printf("[%u] Internal Graph:\n", config.node_addr);
                    print_graph(net_graph);
                    printf("====================\n");

                    // Temporarily block receiving port while broadcasting to other neighbours
                    stp_ports[recv_port] = 0;
                    fwd_lsa(handle, config, stp_ports, neighbor_node_list, recvd_lsa_packet->neighbor_count);
                    stp_ports[recv_port] = 1;

                } break;
                
                default: break;
            }
        } else {
            gettimeofday(&election_timer, NULL);
            if ((!is_root(config, &stp_route_db) && diff_in_microseconds(election_timer_start, election_timer) >= config.reelection_interval_ms * 1000)){
                gettimeofday(&election_timer_start, NULL);
                // printf("election interval elapsed. Resetting ports. Node %d thinks it's root \n", config.node_addr);
                // print_ports(config, stp_ports);
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

        #if DEBUG_STP
        printf("[%u] Broadcast (%u, %u, %u) to neighbours\n", 
            config.node_addr,
            stp_payload.root_address, stp_payload.path_length, stp_payload.node_address);
        #endif

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
    for (size_t nid = 0; nid < config.num_neighbors; nid++) { 
        neighbor_list[nid] = config.neighbor_addrs[nid];
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

            memcpy((uint8_t*)&(lsa_pkt->payload) + sizeof(mixnet_packet_lsa), 
                neighbor_list, sizeof(mixnet_address)*config.num_neighbors);

            if( (err = mixnet_send(handle, nid, lsa_pkt)) < 0){
                printf("Error sending LSA pkt\n");
            }

            // printf("[%u] Broadcast LSA to Node %u\n", 
            //     config.node_addr,
            //     config.neighbor_addrs[nid]);
        }
    }
}

void fwd_lsa(void *handle, 
             const struct mixnet_node_config config, 
             uint8_t *active_ports,
             mixnet_address *neighbor_list,
             uint16_t neighbors_ct)
{
    int err=0;
    mixnet_packet *lsa_pkt;
    mixnet_packet_lsa lsa_payload;

    for (size_t nid = 0; nid < neighbors_ct; nid++) {
        if(active_ports[nid]) {

            lsa_pkt = malloc(sizeof(mixnet_packet) 
                            + sizeof(mixnet_packet_lsa) 
                            + (sizeof(mixnet_address) * neighbors_ct)); 

            lsa_pkt->src_address = config.node_addr;
            lsa_pkt->dst_address = config.neighbor_addrs[nid];
            lsa_pkt->type = PACKET_TYPE_LSA;
            lsa_pkt->payload_size = 4 + (2*neighbors_ct);

            lsa_payload.node_address = config.node_addr;
            lsa_payload.neighbor_count = neighbors_ct;
            memcpy(lsa_pkt->payload, &lsa_payload, sizeof(mixnet_packet_lsa));

            memcpy((uint8_t*)&(lsa_pkt->payload) + sizeof(mixnet_packet_lsa), 
                neighbor_list, sizeof(mixnet_address)*neighbors_ct);

            if((err = mixnet_send(handle, nid, lsa_pkt)) < 0) {
                printf("Error fwd LSA pkt\n");
            }

            printf("[%u] Fwd LSA to Node %u\n", 
                config.node_addr,
                config.neighbor_addrs[nid]);
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

//TODO: Be careful about thre transformational all-in-one nature of this function. Might overdo certain this we don't want it to as impl expands
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
