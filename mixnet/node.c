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

typedef struct{
    mixnet_address root_address;
    uint16_t path_length;      
    mixnet_address next_hop_address;    
} stp_route_t;

// authoritative STP path for this node
static stp_route_t stp_route;

void run_node(void *handle,
              volatile bool *keep_running,
              const struct mixnet_node_config config) {

    int err = 0;
    // (My Root, Path Length, Next Hop)
    stp_route.root_address = config.node_addr;
    stp_route.path_length = 0;
    stp_route.next_hop_address = config.node_addr;

    while (*keep_running) {
        mixnet_packet *broadcast_packet = malloc(sizeof(mixnet_packet) + sizeof(mixnet_packet_stp));
        mixnet_packet_stp *stp_broadcast = malloc(sizeof(mixnet_packet_stp));
        
        uint8_t port = 0;
        mixnet_packet* recvd_packet = NULL;
        mixnet_packet_stp* recvd_stp = NULL;

        /*** SEND ***/
        // Broadcast (My Root, Path Length, My ID)
        for (size_t nid = 0; nid < config.num_neighbors; nid++) {
            broadcast_packet->src_address = config.node_addr;
            broadcast_packet->dst_address = config.neighbor_addrs[nid];
            broadcast_packet->type = PACKET_TYPE_STP;
            broadcast_packet->payload_size = sizeof(mixnet_packet_stp);

            stp_broadcast->root_address = stp_route.root_address;
            stp_broadcast->path_length = stp_route.path_length;
            stp_broadcast->node_address = config.node_addr;

            memcpy(broadcast_packet->payload, stp_broadcast, sizeof(mixnet_packet_stp));

            if( (err = mixnet_send(handle, nid, broadcast_packet)) < 0){
                printf("Error sending STP pkt\n");
            }

            printf("Sent (%u, %u, %u)\n", stp_broadcast->root_address, stp_broadcast->path_length, stp_broadcast->node_address);
        }

        /*** RECEIVE ***/
        int value = mixnet_recv(handle, &port, &recvd_packet);
        if (value != 0) {
            if (recvd_packet->type == PACKET_TYPE_STP) {
                recvd_stp = (mixnet_packet_stp*) recvd_packet->payload;
                printf("Received (%u, %u, %u)\n", recvd_stp->root_address, recvd_stp->path_length, recvd_stp->node_address);

                if(recvd_stp->root_address < stp_route.root_address) {
                        stp_route.root_address = recvd_stp->root_address;

                }else if(recvd_stp->root_address == stp_route.root_address) {
                    if(recvd_stp->path_length < stp_route.path_length){
                        stp_route.next_hop_address = recvd_stp->node_address;    

                    }else if(recvd_stp->path_length == stp_route.path_length){
                        // route through that node if its ID is less than our ID
                        if(recvd_stp->node_address < config.node_addr){
                            stp_route.next_hop_address = recvd_stp->node_address;    
                        }
                    }else{
                        // you know that that node is a child of ours

                    }

                }else{
                        // ignore its root is wrong       
                }
            }
        }
    }
} 