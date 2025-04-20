# Dataplane Router Project

This project implements a basic network router capable of handling ARP requests/replies,
forwarding IPv4 packets and generating ICMP messages. The following is an overview of the
functions used and their roles.

## Routing and Trie Functions

- **add_route(struct route_table_entry *route)**  
  Inserts a route into the trie data structure based on the prefix and mask.

- **create_trie()**  
  Builds the trie from the routing table entries. This allows fast longest prefix match.

- **free_trie() / free_trie_node(struct trie *node)**  
  Frees the memory allocated for the trie.

- **get_best_route(uint32_t ip_dest)**  
  Performs a longest prefix match search in the trie for the given destination IP.
  Returns the best matching route.

## ARP Functions

- **get_arp_entry(uint32_t ip)**  
  Searches the ARP table for an entry corresponding to the given IP address.

- **create_arp_req_header(struct route_table_entry *entry)**  
  Creates and returns an ARP request header for the given route entry.  
  The function sets the protocol type, hardware type, lengths, opcode.

- **create_arp_eth_header(struct route_table_entry *entry)**  
  Creates and returns an Ethernet header for an ARP request.  
  This header sets the Ethernet type to ARP and uses the broadcast MAC as destination.

- **send_ARP_request(const char *packet_buf, struct route_table_entry *entry)**  
  Copies the packet to a deferred queue, then builds the ARP request using the above
  header creation functions and sends it out on the specified interface.

- **send_ARP_reply(void *buf, uint8_t router_mac[6], uint32_t router_ip, int interface)**  
  Builds and sends an ARP reply packet. It swaps the source and target addresses from 
  the ARP request, sets the opcode to ARP reply, and updates the Ethernet header.

- **update_arp_table(struct arp_table_entry *arp_table, int *arp_table_len, struct arp_table_entry new_arp_entry)**  
  Updates the ARP table by either updating an existing entry with a new MAC address or 
  appending a new entry if none exists.

- **get_ARP_reply(void *buf, int interface)**  
  Processes an incoming ARP reply. It updates the ARP table and then sends deferred packets that were waiting for ARP resolution.

## ICMP Functions

- **ICMP_echo_reply(char *buf, int interface)**  
  Processes an ICMP echo request by swapping addresses in the Ethernet and IP headers, 
  decrementing TTL and recalculating the checksum, then sending an ICMP echo reply.

- **build_icmp_error_eth_ip(char *buf, int interface, struct ether_hdr *eth_hdr, struct ip_hdr *ip_hdr)**  
  Builds the Ethernet and IP headers for an ICMP error message. The original source address is preserved and used as the destination in the error response.

- **ICMP_error(char *buf, int interface, uint8_t type)**  
  Builds and sends an ICMP error packet of the given type. It uses part of the original packet's payload and sets the correct header fields.

## Utility Functions

- **swap(void *a, void *b, size_t len)**  
  Swaps the contents of two memory areas. Used for exchanging MAC or IP addresses in headers.

- **is_broadcast_address(uint8_t address[6])**  
  Checks if a given MAC address is the broadcast address (all bytes 255).

- **is_equal_address(uint8_t address1[6], uint8_t address2[6])**  
  Compares two MAC addresses to determine if they are the same.

## Requirements

- **Routing Process (30p)**  
  The router processes IPv4 packets by performing the following steps:  
  - Verifying the IP header checksum  
  - Decrementing the TTL and recalculating the checksum  
  - Determining the best route using an efficient Longest Prefix Match.  
    - **get_best_route(uint32_t ip_dest)**: Searches the routing trie to perform a fast longest prefix match.  

- **Efficient Longest Prefix Match (16p)**  
  To replace the linear search, a trie data structure is implemented for the routing table.  
    - **create_trie() / add_route()**: Which build the trie when reading the routing table.  
    - **get_best_route(uint32_t ip_dest)**: Which uses bitwise operations on the destination IP (after converting to host order) to traverse the trie and find the best matching route.

- **ARP Protocol (33p)**  
  The ARP protocol is implemented to dynamically populate the ARP table and cache responses.  
    - **create_arp_req_header(struct route_table_entry *entry)**: Constructs the ARP request header with proper protocol and hardware types, lengths, opcodes and IP addresses.  
    - **create_arp_eth_header(struct route_table_entry *entry)**: Builds the Ethernet header for the ARP request, using a broadcast MAC for the destination.  
    - **send_ARP_request(const char *packet_buf, struct route_table_entry *entry)**: Sends the ARP request and defers packets in a queue until the ARP reply is received.  
    - **update_arp_table(...)** and **get_ARP_reply(void *buf, int interface)**: These functions update the ARP table (cache) when a reply is observed and then process any deferred packets that were awaiting ARP resolution.

- **ICMP Protocol (21p)**  
  The router implements ICMP functionality to handle echo requests and error messages.  
    - **ICMP_echo_reply(char *buf, int interface)**: Processes an incoming ICMP echo request by swapping MAC and IP addresses, decrementing the TTL, recalculating checksums, and sending an echo reply  
    - **build_icmp_error_eth_ip(char *buf, int interface, struct ether_hdr *eth_hdr, struct ip_hdr *ip_hdr)** and **ICMP_error(char *buf, int interface, uint8_t type)**: Build the headers for an ICMP error message and send the error package to the original sender.
