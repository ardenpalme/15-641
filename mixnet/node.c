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
#include "node.h"

#include "connection.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define DEBUG_FLOOD 0
#define DEBUG_STP 0

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
                   mixnet_packet *broadcast_packet, 
                   stp_route_t *stp_route_db);
void print_stp(const struct mixnet_node_config config, const char *prefix_str, mixnet_packet *packet);

// FLOOD functions
void broadcast_flood(void *handle, 
                     const struct mixnet_node_config config, 
                     uint8_t *active_ports);

// Generic functions 
void print_packet_header(mixnet_packet *pkt);
int get_port_from_addr(const struct mixnet_node_config config, mixnet_address next_hop_address, uint8_t *stp_ports);

// Port-handling functions
enum portvec_decision {RESTORE_PORTS, SAVE_PORTS, NO_SAVE_PORTS};
enum port_decision {BLOCK_PORT, OPEN_PORT};
void activate_all_ports(const struct mixnet_node_config config, uint8_t *ports);
void deactivate_all_ports(const struct mixnet_node_config config, uint8_t *ports);
void port_to_neighbor(const struct mixnet_node_config config, 
                            mixnet_address niegbhor_addr, 
                            uint8_t *ports, 
                            uint8_t*prev_ports, 
                            enum port_decision decision,
                            enum portvec_decision portvec_decision);
void print_ports(const struct mixnet_node_config config, uint8_t *ports);

bool is_root(const struct mixnet_node_config config, stp_route_t *stp_route_db);

uint32_t diff_in_microseconds(struct timeval t0, struct timeval t1);


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

    mixnet_packet *stp_packet = NULL;
    mixnet_packet *recvd_packet = NULL;
    mixnet_packet_stp *recvd_stp_packet = NULL;
    mixnet_address stp_parent_addr = -1;
    uint16_t stp_parent_path_length = -1;
    uint8_t recv_port;
    
    int err=0;
    const int user_port = config.num_neighbors;

    // Broadcast (My Root, Path Length, My ID) initially 
    if (is_root(config, &stp_route_db)){
        broadcast_stp(handle, config, stp_packet, &stp_route_db);
        gettimeofday(&root_hello_timer_start, NULL); //Reset root hello timer start

    }

    while (*keep_running) {

        // Send Root Hello at regular intervals 
        gettimeofday(&root_hello_timer, NULL);
        if(is_root(config, &stp_route_db) && 
            ((diff_in_microseconds(root_hello_timer_start, root_hello_timer) >= config.root_hello_interval_ms * 1000))) {
            broadcast_stp(handle, config, stp_packet, &stp_route_db); 
            gettimeofday(&root_hello_timer_start, NULL); //Reset root hello timer start
        }

        /*** RECEIVE ***/
        int value = mixnet_recv(handle, &recv_port, &recvd_packet);
        if (value != 0) {
            //print_packet_header(recvd_packet);
            switch (recvd_packet->type){
                
                //Run Spanning Tree Protocol updates. Brodcast root changes to neighbours as necessary
                case PACKET_TYPE_STP: {
                    
                    recvd_stp_packet = (mixnet_packet_stp*) recvd_packet->payload;
                    is_hello_root = true;
                    if(is_root(config, &stp_route_db) || recvd_stp_packet->root_address != recvd_stp_packet->node_address){
                        #if DEBUG_STP
                        print_stp(config, "Received ", recvd_packet);
                        printf("[%u] STP DB: (my_root: %u, path_len: %u, next_hop: %u)\n", 
                            config.node_addr, 
                            stp_route_db.root_address,
                            stp_route_db.path_length,
                            stp_route_db.next_hop_address);
                        #endif
                    }

                    // Receive STP message from smaller ID root node
                    // Make him root and increment path length
                    if(recvd_stp_packet->root_address < stp_route_db.root_address) {
                        is_hello_root = false;
                        // printf("New Root node is %d Next hop is %u \n", recvd_stp_packet->root_address, recvd_stp_packet->node_address);
                        stp_route_db.root_address = recvd_stp_packet->root_address;
                        stp_route_db.path_length = recvd_stp_packet->path_length + 1;
                        stp_route_db.next_hop_address = recvd_stp_packet->node_address;

                        stp_parent_addr = recvd_stp_packet->node_address;
                        stp_parent_path_length = recvd_stp_packet->path_length;                        
                        // port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, NULL, OPEN_PORT, NO_SAVE_PORTS);

                        // tell everyone about new best root candidate
                        broadcast_stp(handle, config, stp_packet, &stp_route_db);


                    }else if(recvd_stp_packet->root_address == stp_route_db.root_address) {
                        // Recieve from same ID, shorter path root node
                        // Follow his path instead, increment path length
                        if(recvd_stp_packet->path_length + 1 < stp_route_db.path_length) {
                            stp_route_db.next_hop_address = recvd_stp_packet->node_address;
                            stp_route_db.path_length = recvd_stp_packet->path_length + 1;
                            
                            // printf("Found better path to same root %u with node %u pathlen %u \n", recvd_stp_packet->root_address, recvd_stp_packet->node_address, recvd_stp_packet->path_length);
                            
                            // port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, NULL, OPEN_PORT, NO_SAVE_PORTS);
                            stp_parent_addr = recvd_stp_packet->node_address;
                            stp_parent_path_length = recvd_stp_packet->path_length;   
                            
                            is_hello_root = false;   
                        
                        //Tie for ID and path length
                        } else if (stp_parent_addr != -1 && recvd_stp_packet->path_length == stp_parent_path_length){
                            // printf("Tied for ID & parent pathlen with node %u pathlen %u \n", recvd_stp_packet->node_address, recvd_stp_packet->path_length);
                            
                            if (recvd_stp_packet->node_address < stp_parent_addr){
                                // Severe link for worse parent candidate
                                port_to_neighbor(config, stp_parent_addr, stp_ports, NULL, BLOCK_PORT, NO_SAVE_PORTS);

                                // choose lesser indexed node to route through
                                stp_route_db.next_hop_address = recvd_stp_packet->node_address;
                                stp_parent_addr = recvd_stp_packet->node_address;         
                                is_hello_root = false;

                            }else if (recvd_stp_packet->node_address > stp_parent_addr){
                                // Severe link for failed parent candidate
                                port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, NULL, BLOCK_PORT, NO_SAVE_PORTS);

                            }
                        }

                        // If path advertised is equal to path length, node must be peer, not {child, parent} 
                        if (recvd_stp_packet->path_length == stp_route_db.path_length){
                                // printf("Tied for ID & pathlen with node %u pathlen %u \n", recvd_stp_packet->node_address, recvd_stp_packet->path_length);
                                port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, NULL, BLOCK_PORT, NO_SAVE_PORTS);
                        }
                    }

                    // if (stp_parent_addr != -1 && recvd_stp_packet->node_address != stp_parent_addr && 
                    //     recvd_stp_packet->path_length == stp_parent_path_length){

                    // }
                        // else if((stp_parent_addr > 0) && (recvd_stp_packet->path_length == stp_parent_path_length)) {
                        //     // same received advertisement has the path length to the stable root as the path that my parent advertises
                        //     port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, NULL, BLOCK_PORT, NO_SAVE_PORTS);

                        // }
                    //     else if(recvd_stp_packet->path_length == stp_route_db.path_length) {
                    //         if((stp_parent_addr > 0) && (recvd_stp_packet->node_address != stp_parent_addr)){
                    //             // same path length to stable root, but the node is not my parent
                    //             port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, NULL, BLOCK_PORT, NO_SAVE_PORTS);

                    //         //Same root, same path length. Choose lesser idexed node to route through
                    //         }else if(recvd_stp_packet->node_address < stp_route_db.next_hop_address) {
                    //             stp_route_db.next_hop_address = recvd_stp_packet->node_address;
                    //             port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, NULL, OPEN_PORT, NO_SAVE_PORTS);
                    //             stp_parent_addr = recvd_stp_packet->node_address;
                    //             stp_parent_path_length = recvd_stp_packet->path_length;

                    //             is_hello_root = false;
                    //         }

                    //     }else{
                    //         // open the port to this neighboring node because it must be your child
                    //         port_to_neighbor(config, recvd_stp_packet->node_address, stp_ports, NULL, OPEN_PORT, NO_SAVE_PORTS);
                    //     }
                    // }

                    if (!is_root(config, &stp_route_db) && is_hello_root){
                        // printf("Received hello root from node %d \n", recvd_stp_packet->node_address);
                        // printf("Port Neighbour status: ");
                        // for (int i=0; i < config.num_neighbors; i++){
                        //     printf("%d ", stp_ports);
                        // }
                        // printf("\n");
                        // print_ports(config, stp_ports);

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
                
                default: break;
            }
        } else {
            gettimeofday(&election_timer, NULL);
            if ((diff_in_microseconds(election_timer_start, election_timer) >= config.reelection_interval_ms * 1000)){
                // printf("election interval elapsed. Node %d thinks it's root \n", config.node_addr);
                // Node thinks it's now the root
                stp_route_db.root_address = config.node_addr;
                stp_route_db.path_length = 0;
                stp_route_db.next_hop_address = config.node_addr;
                // Forget about stale spanning tree
                activate_all_ports(config, stp_ports);

                stp_parent_addr = -1;
                stp_parent_path_length = -1;
                broadcast_stp(handle, config, stp_packet, &stp_route_db);
                gettimeofday(&root_hello_timer_start, NULL); //Reset root hello timer start
            }

        }

    }
} 

void broadcast_stp(void *handle, 
                   const struct mixnet_node_config config, 
                   mixnet_packet *broadcast_packet, 
                   stp_route_t *stp_route_db)
{
    mixnet_packet_stp stp_payload;
    int err=0;
    for (size_t nid = 0; nid < config.num_neighbors; nid++) {
        broadcast_packet = malloc(sizeof(mixnet_packet) + sizeof(mixnet_packet_stp));
        broadcast_packet->src_address = config.node_addr;
        broadcast_packet->dst_address = config.neighbor_addrs[nid];
        broadcast_packet->type = PACKET_TYPE_STP;
        broadcast_packet->payload_size = sizeof(mixnet_packet_stp);

        stp_payload.root_address = stp_route_db->root_address;
        stp_payload.path_length = stp_route_db->path_length;
        stp_payload.node_address = config.node_addr;

        memcpy(broadcast_packet->payload, &stp_payload, sizeof(mixnet_packet_stp));

        #if DEBUG_STP
        printf("[%u] Broadcast (%u, %u, %u)\n", 
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
                        uint8_t*prev_ports, 
                        enum port_decision decision,
                        enum portvec_decision portvec_decision) 
{
    size_t len_port_vec = config.num_neighbors * sizeof(uint8_t); // bytes
    
    if(portvec_decision == RESTORE_PORTS){
        memcpy(ports, prev_ports, len_port_vec);
        
    }else if(portvec_decision == SAVE_PORTS){
        memcpy(prev_ports, ports, len_port_vec);
    }

    for(int nid=0; nid<config.num_neighbors; nid++){
        if(config.neighbor_addrs[nid] == niegbhor_addr){

            if(decision == BLOCK_PORT)
                ports[nid] = 0;

            else if(decision == OPEN_PORT)
                ports[nid] = 1;
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


uint32_t diff_in_microseconds(struct timeval b4, struct timeval later){
    return (later.tv_sec - b4.tv_sec) * 1000000 + (later.tv_usec - b4.tv_usec);
}
