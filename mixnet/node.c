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

void run_node(void *handle,
              volatile bool *keep_running,
              const struct mixnet_node_config config) {

    int err = 0;

    while (*keep_running) {
        mixnet_packet *stp_packet = malloc(sizeof(mixnet_packet) + sizeof(mixnet_packet_stp));
        mixnet_packet_stp *stp_payload = malloc(sizeof(mixnet_packet_stp));
        
        uint8_t port = 0;
        mixnet_packet* packet = NULL;

        // Broadcast (Me, 0, Me) to all neighbors
        for (size_t nid = 0; nid < config.num_neighbors; nid++) {
            stp_packet->src_address = config.node_addr;
            stp_packet->dst_address = config.neighbor_addrs[nid];
            stp_packet->type = PACKET_TYPE_STP;
            stp_packet->payload_size = sizeof(mixnet_packet_stp);

            stp_payload->root_address = config.node_addr;
            stp_payload->path_length = 0;
            stp_payload->node_address = config.node_addr;

            // fill payload of packet
            memcpy(stp_packet->payload, stp_payload, sizeof(mixnet_packet_stp));

            if( (err = mixnet_send(handle, nid, stp_packet)) < 0){
                printf("Error sending STP pkt\n");
            }
            //printf("[%u] sent STP to Node %d\n", config.node_addr, config.neighbor_addrs[nid] );
        }

        int value = mixnet_recv(handle, &port, &packet);
        if (value != 0) {
            if (packet->type == PACKET_TYPE_STP) {
                printf("[%u] Received STP packet from: %u\n", config.node_addr, packet->src_address);
            }
        }
    }
} 