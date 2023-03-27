#include "include/queue.h"
#include "include/skel.h"

// function that returns the best route from the routing table, based on
// a given IP address
struct route_table_entry *get_best_route(u_int32_t ip_addr, int size, 
										struct route_table_entry *rtable) {
	// initializing the entry that will have the result
	struct route_table_entry *bc = NULL;

	// searching for the ip address in the routing table
	for (int i = 0; i < size; i++) {
		// case when we find the wanted ip address
		if ((ip_addr & rtable[i].mask) == rtable[i].prefix) {
			// if it's the first time we find the wanted address we store it in the answer
			if (!bc) {
				bc = &rtable[i];
			// if it's not the first time, we check the masks and we store the address with the bigger mask
			} else if (ntohl(rtable[i].mask) > ntohl(bc->mask)) {
				bc = &rtable[i];
			}
		}
	}

	return bc;
}

// function that builds a icmp header for a packet in order for the packet to be sent
void build_icmp_error(packet *pack) {
	// getting all the necesary headers from the payload
	struct ether_header *ether_head = (struct ether_header *) pack->payload;
	struct iphdr *ip_head = (struct iphdr *) (pack->payload + sizeof(struct ether_header));
	struct icmphdr* icmp_head = (struct icmphdr *) (pack->payload + sizeof(struct ether_header) + sizeof(struct iphdr));
	
	// swapping the source and destination addresses in the ethernet header
	uint8_t aux[ETH_ALEN];
	for (int i = 0; i < 6; i++) {
		aux[i] = ether_head->ether_dhost[i];
		ether_head->ether_dhost[i] = ether_head->ether_shost[i];
		ether_head->ether_shost[i] = aux[i];
	}

	// recalculating the ip check sum incrementally
	uint16_t aux_sum = ~(~(ip_head->check) + ~(ip_head->ttl) + (ip_head->ttl - 1)) - 1; 
	ip_head->check = aux_sum;

	// swapping the source and destination addresses in the IP header
	uint32_t aux2 = ip_head->daddr;
	ip_head->daddr = ip_head->saddr;
	ip_head->saddr = aux2;

	// updating the other fields of the ip header accordingly to the ICMP protocol
	ip_head->ihl = 5;
	ip_head->protocol = 1;

	// updating the size of the ip header(with 8 bytes more), because we added the icmp header
	ip_head->tot_len = htons(28);

	// the icmp code is 0 for all the operations that we want to do, the type is assigned in the main,
	// based on the type of message we want to send
	icmp_head->code = 0;

	// calculating the icmp check sum
	icmp_head->checksum = 0;
	icmp_head->checksum = icmp_checksum((uint16_t*) icmp_head, sizeof(struct icmphdr));

	// updating the size of the packet(with 8 bytes more), because we added the icmp header 
	pack->len = 42;
}


int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// array in which the broadcast address is stored
	uint8_t broadcast[6];
	for (int i = 0; i < 6; i++) {
		broadcast[i] = 0xFF;
	}

	// Do not modify this line
	init(argc - 2, argv + 2);

	// building the arp table, the routing table and the queue of packets
	struct arp_entry* arp_table = calloc(sizeof(struct arp_entry), 80000);
	int arp_table_size = 0;
	struct route_table_entry *rtable = calloc(sizeof(struct route_table_entry), 80000);
	struct queue* queue_of_packets = queue_create();
	int queue_size = 0;

	// populating the routing table
	int rtable_size = read_rtable(argv[1], rtable);
	DIE(rtable_size < 0, "read_rtable");

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		// getting the ethernet header from the packet's payload
		struct ether_header *ether_head = (struct ether_header *) m.payload;
		
		// getting the MAC address of the packet's interface
		uint8_t *mac_addr = malloc(sizeof(u_int8_t));
		get_interface_mac(m.interface, mac_addr);

		// checking if the ethernet destination is broadcast or the mac of the interface
		int ok_broadcast = 1;
		int ok_destination = 1;

		for (int i = 0; i < 6; i++) {
			if (ether_head->ether_dhost[i] != mac_addr[i]) {
				ok_destination = 0;
				break;
			}
		}

		for (int i = 0; i < 6; i++) {
			if (ether_head->ether_dhost[i] != broadcast[i]) {
				ok_broadcast = 0;
				break;
			}
		}

		// if it's neither of them, we send an icmp destination unreachable message
		if (ok_broadcast == 0 && ok_destination == 0) {
			continue;
		}

		// ARP protocol
		if (ntohs(ether_head->ether_type) == 0x0806) {
			struct arp_header *arp_head = (struct arp_header *) (m.payload + 14);
			
			// response to the arp-request
			if (ntohs(arp_head->op) == 1) {	
				uint8_t aux_sha[ETH_ALEN];
				uint32_t aux_spa = arp_head->spa;

				// if the target protocol address the address of the interface
				if (arp_head->tpa == inet_addr(get_interface_ip(m.interface))) {
					for (int i = 0; i < 6; i++) {
						aux_sha[i] = arp_head->sha[i]; 
					}

					// the sha becomes the mac address of the interface
					for (int i = 0; i < 6; i++) {
						arp_head->sha[i] = mac_addr[i];
					}

					// transforming the packet into an ARP reply packet
					arp_head->op = htons(2);

					// the spa becomes the IP address of the interface
					arp_head->spa = inet_addr(get_interface_ip(m.interface));
					// the tpa becomes the request's spa
					arp_head->tpa = aux_spa;
					
					// the tha becomes the request's sha
					for (int i = 0; i < 6; i++) {
						arp_head->tha[i] = aux_sha[i];
					}

					// updating the ethernet header addresses
					for (int i = 0; i < 6; i++) {
						ether_head->ether_dhost[i] = ether_head->ether_shost[i];
						ether_head->ether_shost[i] = mac_addr[i];
					}

					// sending the packet
					int rs = send_packet(&m);
					DIE(rs < 0, "send_packet");
				} else {
					continue;
				}
			// arp-reply
			} else {
				// adding a new pair of IP - MAC address in the ARP table
				for (int i = 0; i < 6; i++) {
					arp_table[arp_table_size].mac[i] = arp_head->sha[i];
				}
				arp_table[arp_table_size].ip = arp_head->spa;
				arp_table_size++;
				int extracted = 0;

				// going through the queue
				for (int i = 0; i < queue_size; i++) {
					// extracting a packet from the queue and its headers
					packet *curr_packet = (packet *) queue_deq(queue_of_packets);

					struct ether_header *curr_ether_head = (struct ether_header *) curr_packet->payload; 
					struct iphdr *curr_ip_head = (struct iphdr *)(curr_packet->payload + sizeof(struct ether_header));
					
					// calculating the best route for the extracted packet
					struct route_table_entry *curr_best_route = get_best_route(curr_ip_head->daddr, rtable_size, rtable);

					// if we didn't get any route then we need to send a Destination Unreachable message
					if (!curr_best_route) {
						struct icmphdr* icmp_head = (struct icmphdr *) (m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
						build_icmp_error(&m);
						
						icmp_head->type = 3;
						int rs = send_packet(&m);
						DIE(rs < 0, "send_packet");

						continue;
					}

					// if the next-hop of the best route is the spa of the arp reply, then we search for it in the arp table
					if (curr_best_route->next_hop == arp_head->spa) {
						int found_entry = 0;
						for (int i = 0; i < arp_table_size; i++) {
							// if we find it in the arp table we update the ethernet destination address with the MAC address
							if (arp_table[i].ip == curr_best_route->next_hop) {
								for (int j = 0; j < 6; j++) {
									curr_ether_head->ether_dhost[j] = arp_table[i].mac[j];
								}

								curr_packet->interface = curr_best_route->interface;
								extracted++;
								found_entry = 1;
							
								// sending the packet
								int rs = send_packet(curr_packet);
								DIE(rs < 0, "send_packet");

								continue;
							}
						}

						if (found_entry == 0) {
							queue_enq(queue_of_packets, curr_packet);
						}
					} else {
						queue_enq(queue_of_packets, curr_packet);
					}
				}

				queue_size -= extracted;
			}
		// IPv4 protocol
		} else if (ntohs(ether_head->ether_type) == 0x0800) {
			// extracting the IP header from the payload
			struct iphdr *ip_head = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			int found_in_arp_table = 0;

			// if the router is the destination(echo request), we send the echo reply
			if (ip_head->daddr == inet_addr(get_interface_ip(m.interface))) {
				if (ip_head->protocol == 1) {
					struct icmphdr* icmp_head = (struct icmphdr *) (m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
					if (icmp_head->type == 8) {
						struct icmphdr* icmp_head = (struct icmphdr *) (m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
						build_icmp_error(&m);
						
						icmp_head->type = 0;
						send_packet(&m);
					}
				}
				continue;
			}

			// if the checksum is wrong then we go to the next packet
			if (ip_checksum((uint8_t *) ip_head, sizeof(struct iphdr)) != 0) {
				continue;
			}

			// if the ttl is lower than 1 then we need to send a Time Exceeded icmp error
			if (ip_head->ttl <= 1) {
				struct icmphdr* icmp_head = (struct icmphdr *) (m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				build_icmp_error(&m);
				
				icmp_head->type = 11;
				send_packet(&m);
				
				continue;
			}

			// getting the best route for our destination address
			struct route_table_entry* best_route = get_best_route(ip_head->daddr, rtable_size, rtable);
			// if we get no best route then we need to send a Destination Unreachable icmp error
			if (!best_route) {
				struct icmphdr* icmp_head = (struct icmphdr *) (m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				build_icmp_error(&m);
				
				icmp_head->type = 3;
				send_packet(&m);
				continue;
			}

			// recalculating the ttl and the checksum incrementally
			uint16_t aux_sum = ~(~(ip_head->check) + ~(ip_head->ttl) + (ip_head->ttl - 1)) - 1; 
			ip_head->ttl--;
			ip_head->check = aux_sum;

			// looking for the next-hop in the arp table
			for (int i = 0; i < arp_table_size; i++) {
				if (best_route->next_hop == arp_table[i].ip) {
					// if we find it then we put the MAC in the ethernet header and then we send the packet
					found_in_arp_table = 1;		
					m.interface = best_route->interface;
					get_interface_mac(best_route->interface, ether_head->ether_shost);

					for (int j = 0; j < 6; j++) {
						ether_head->ether_dhost[j] = arp_table[i].mac[j];
					}

					int rs = send_packet(&m);
					DIE(rs < 0, "send packet");
					
					break;
				}
			}

			// if we don't find the next-hop in the arp table then we need to send an ARP Request so that we 
			// can get the mac of the next-hop
			if (found_in_arp_table == 0) {
				// creating a new packet and sending it to the queue
				packet* m2 = malloc (sizeof(packet));
				memcpy(m2, &m, sizeof(packet));
				queue_enq(queue_of_packets, m2);
				queue_size++;

				// creating the arp request
				packet new_packet;
				struct ether_header *new_ether_head = (struct ether_header *) new_packet.payload;
				struct arp_header *new_arp_head = (struct arp_header *) (new_packet.payload + sizeof(struct ether_header));

				new_packet.interface = best_route->interface;
				new_packet.len = 42;

				uint8_t *new_mac_addr = malloc(sizeof(u_int8_t));
				get_interface_mac(new_packet.interface, new_mac_addr);

				// setting the ethernet addresses accordingly
				for (int i = 0; i < 6; i++) {
					new_ether_head->ether_dhost[i] = broadcast[i];
					new_ether_head->ether_shost[i] = new_mac_addr[i];
				}

				new_ether_head->ether_type = htons(0x0806);

				// setting the arp fields accordingly to the ARP request
				new_arp_head->hlen = 6;
				new_arp_head->op = htons(1);
				new_arp_head->htype = htons(1);
				new_arp_head->plen = 4;
				new_arp_head->ptype = htons(0x0800);

				for (int i = 0; i < 6; i++) {
					new_arp_head->sha[i] = new_mac_addr[i];
					new_arp_head->tha[i] = 0;
				}

				new_arp_head->spa = inet_addr(get_interface_ip(best_route->interface));
				new_arp_head->tpa = best_route->next_hop;

				// sending the arp request
				int rs = send_packet(&new_packet);
				DIE(rs < 0, "send_packet");
			}
		}
	}
}
