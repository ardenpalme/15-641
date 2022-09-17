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

typedef struct{
    mixnet_address root_address;
    uint16_t path_length;      
    mixnet_address next_hop_address;    
} stp_route_t;

// the node's database for current STP path to root node
static stp_route_t stp_route_db;

void broadcast_stp(void *handle, 
                   const struct mixnet_node_config config, 
                   mixnet_packet *broadcast_packet, 
                   stp_route_t *stp_route_db,
                   uint8_t *active_ports,
                   bool print_en);

void print_stp(const char *prefix_str, mixnet_packet *packet);

void activate_all_ports(const struct mixnet_node_config config, uint8_t *ports);
void block_port_to_neighbor(const struct mixnet_node_config config, uint8_t *ports, mixnet_address niegbhor_addr);
void open_port_to_neighbor(const struct mixnet_node_config config, uint8_t *ports, mixnet_address niegbhor_addr);

void run_node(void *handle,
              volatile bool *keep_running,
              const struct mixnet_node_config config) {

    // Database for STP packet fowarding (My Root, Path Length, Next Hop)
    stp_route_db.root_address = config.node_addr;
    stp_route_db.path_length = 0;
    stp_route_db.next_hop_address = config.node_addr;

    uint8_t *stp_ports = malloc(sizeof(uint8_t) * config.num_neighbors);  // ports to send STP route advertisements on during convergence period
    activate_all_ports(config, stp_ports);

    bool advertise_stp = true;
    bool is_root = true;

    struct timeval root_hello_timer, root_hello_timer_start;
    gettimeofday(&root_hello_timer_start, NULL);

    mixnet_packet *recvd_packet = NULL;
    mixnet_packet_stp *recvd_stp_packet = NULL;
    mixnet_address stp_parent_addr = -1;
    uint16_t stp_parent_path_length = -1;
    uint8_t recv_port;

    while (*keep_running) {
        mixnet_packet *stp_packet = malloc(sizeof(mixnet_packet) + sizeof(mixnet_packet_stp));

        /*** SEND ***/
        // Broadcast (My Root, Path Length, My ID) once 
        if(advertise_stp){
            broadcast_stp(handle, config, stp_packet, &stp_route_db, stp_ports, true);
            advertise_stp=false;
        }
        
        // Send Root Hello at regular intervals 
        gettimeofday(&root_hello_timer, NULL);
        if(is_root && 
            (((root_hello_timer.tv_usec - root_hello_timer_start.tv_usec)*1000) < config.root_hello_interval_ms)) {
            broadcast_stp(handle, config, stp_packet, &stp_route_db, stp_ports, false);
        }

        /*** RECEIVE ***/
        int value = mixnet_recv(handle, &recv_port, &recvd_packet);
        if (value != 0) {
            if (recvd_packet->type == PACKET_TYPE_STP && stp_ports[recv_port]) {
                recvd_stp_packet = (mixnet_packet_stp*) recvd_packet->payload;

                if(is_root || recvd_stp_packet->root_address != recvd_stp_packet->node_address){
                    print_stp("Received ", recvd_packet);
                    printf("[%u] STP DB: (my_root: %u, path_len: %u, next_hop: %u)\n", 
                        config.node_addr, 
                        stp_route_db.root_address,
                        stp_route_db.path_length,
                        stp_route_db.next_hop_address);
                }

                if(recvd_stp_packet->root_address < stp_route_db.root_address) {
                    is_root= false;
                    stp_route_db.root_address = recvd_stp_packet->root_address;
                    stp_route_db.path_length += 1;
                    stp_route_db.next_hop_address = recvd_stp_packet->node_address; 
                    open_port_to_neighbor(config, stp_ports, recvd_stp_packet->node_address);

                    // tell everyone about this
                    broadcast_stp(handle, config, stp_packet, &stp_route_db, stp_ports, false);

                }else if(recvd_stp_packet->root_address == stp_route_db.root_address) {
                    if(recvd_stp_packet->path_length < stp_route_db.path_length) {
                        stp_route_db.next_hop_address = recvd_stp_packet->node_address;
                        open_port_to_neighbor(config, stp_ports, recvd_stp_packet->node_address); // that node is my parent
                        stp_parent_addr = recvd_stp_packet->node_address;
                        stp_parent_path_length = recvd_stp_packet->path_length;
                        // no change in path length b/c we're just routing through a different neighbor

                    }else if(recvd_stp_packet->path_length == stp_route_db.path_length) {
                        if(recvd_stp_packet->node_address < config.node_addr) {
                            stp_route_db.next_hop_address = recvd_stp_packet->node_address;
                            open_port_to_neighbor(config, stp_ports, recvd_stp_packet->node_address); // that node is my parent
                            stp_parent_addr = recvd_stp_packet->node_address;
                            stp_parent_path_length = recvd_stp_packet->path_length;
                        }

                    }else{
                        // open the port to this neighboring node because it must be your child
                        open_port_to_neighbor(config, stp_ports, recvd_stp_packet->node_address);
                    }
                }

                if(is_root || recvd_stp_packet->root_address != recvd_stp_packet->node_address) {
                    printf("[%u] STP DB: (my_root: %u, path_len: %u, next_hop: %u)\n", 
                        config.node_addr, 
                        stp_route_db.root_address,
                        stp_route_db.path_length,
                        stp_route_db.next_hop_address);
                }
            }
        }
    }
} 

void broadcast_stp(void *handle, 
                   const struct mixnet_node_config config, 
                   mixnet_packet *broadcast_packet, 
                   stp_route_t *stp_route_db,
                   uint8_t *active_ports,
                   bool print_en) 
{
    mixnet_packet_stp stp_payload;
    int err=0;
    for (size_t nid = 0; nid < config.num_neighbors; nid++) {
        if(active_ports[nid]) {
            broadcast_packet->src_address = config.node_addr;
            broadcast_packet->dst_address = config.neighbor_addrs[nid];
            broadcast_packet->type = PACKET_TYPE_STP;
            broadcast_packet->payload_size = sizeof(mixnet_packet_stp);

            stp_payload.root_address = stp_route_db->root_address;
            stp_payload.path_length = stp_route_db->path_length;
            stp_payload.node_address = config.node_addr;

            memcpy(broadcast_packet->payload, &stp_payload, sizeof(mixnet_packet_stp));

            if(print_en){
                printf("[%u] Broadcast (%u, %u, %u)\n", 
                    config.node_addr,
                    stp_payload.root_address, stp_payload.path_length, stp_payload.node_address);
            }

            if( (err = mixnet_send(handle, nid, broadcast_packet)) < 0){
                printf("Error sending STP pkt\n");
            }
        }
    }
}

void activate_all_ports(const struct mixnet_node_config config, uint8_t *ports){
    for(int nid=0; nid<config.num_neighbors; nid++){
        ports[nid] = 1;
    }
}

void block_port_to_neighbor(const struct mixnet_node_config config, uint8_t *ports, mixnet_address niegbhor_addr) {
    for(int nid=0; nid<config.num_neighbors; nid++){
        if(config.neighbor_addrs[nid] == niegbhor_addr){
            ports[nid] = 0;
        }
    }
}

void open_port_to_neighbor(const struct mixnet_node_config config, uint8_t *ports, mixnet_address niegbhor_addr) {
    for(int nid=0; nid<config.num_neighbors; nid++){
        if(config.neighbor_addrs[nid] == niegbhor_addr){
            ports[nid] = 1;
        }
    }
}

void print_stp(const char *prefix_str, mixnet_packet *packet){
    mixnet_packet_stp *stp_payload = (mixnet_packet_stp*) packet->payload;
    printf("%s (%u, %u, %u)\n", prefix_str, stp_payload->root_address, stp_payload->path_length, stp_payload->node_address);
}