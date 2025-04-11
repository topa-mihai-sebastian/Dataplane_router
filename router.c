#include "protocols.h"
#include "list.h"
#include "queue.h"
#include "lib.h"
#include <string.h>
#include <arpa/inet.h>

#define ARP_LEN 42
#define ICMP_LEN 98

queue packets;

// nu mergeee
//  int queue_size(queue q)
//  {
//  	if (queue_empty(q))
//  	{
//  		return 0; // Coada este goală
//  	}

// 	int size = 0;
// 	list current = q->head; // Începe de la capul listei

// 	// Parcurge lista și numără nodurile
// 	while (current != NULL)
// 	{
// 		size++;
// 		current = current->next;
// 	}

// 	return size;
// }

struct trie
{
	struct route_table_entry *route;
	struct trie *zero, *one;
};

int rtable_len;
struct route_table_entry *rtable;

struct trie *head;

struct arp_table_entry *arp_table;
int arp_table_len;

void add_route(struct route_table_entry *route)
{
	uint32_t mask = 0;
	int pos = 31;
	if (!head)
		head = malloc(sizeof(struct trie));
	struct trie *current = head;

	while (1)
	{
		if (ntohl(route->mask) == mask)
		{
			// s-a gasit
			current->route = route;
			break;
		}
		uint32_t prefix = ntohl(route->prefix);
		uint32_t bit_mask = (1 << pos); // este 1 pe pozitia pos
		uint8_t bit = (prefix & bit_mask) >> pos;
		if (bit == 1)
		{
			if (!current->one)
				current->one = malloc(sizeof(struct trie));
			current = current->one;
		}
		else if (bit == 0)
		{
			if (!current->zero)
				current->zero = malloc(sizeof(struct trie));
			current = current->zero;
		}
		mask = mask >> 1;		 // mut masca cu un bit la dreapta
		mask = mask | (1 << 31); // pun 1 pe cel mai semnificativ bit
		pos--;
	}
}

void create_trie()
{
	for (int i = 0; i < rtable_len; i++)
	{
		add_route(&rtable[i]);
	}
}

int compare_rtable_entries(const void *a, const void *b)
{
	struct route_table_entry *entry1 = (struct route_table_entry *)a;
	struct route_table_entry *entry2 = (struct route_table_entry *)b;

	// Comparăm după mască (în ordine descrescătoare)
	if (ntohl(entry1->mask) > ntohl(entry2->mask))
	{
		return -1;
	}
	else if (ntohl(entry1->mask) < ntohl(entry2->mask))
	{
		return 1;
	}

	// Dacă măștile sunt egale, comparăm după prefix (în ordine crescătoare)
	if (ntohl(entry1->prefix) < ntohl(entry2->prefix))
	{
		return -1;
	}
	else if (ntohl(entry1->prefix) > ntohl(entry2->prefix))
	{
		return 1;
	}

	return 0; // Sunt egale
}

void swap(void *a, void *b, size_t len)
{
	void *aux = malloc(len);
	memcpy(aux, a, len);
	memcpy(a, b, len);
	memcpy(b, aux, len);
	free(aux);
}

int is_broadcast_address(uint8_t address[6])
{
	for (int i = 0; i < 6; i++)
		if (address[i] != 255)
			return 0;
	return 1;
}

int is_equal_address(uint8_t address1[6], uint8_t address2[6])
{
	for (int i = 0; i < 6; i++)
		if (address1[i] != address2[i])
			return 0;
	return 1;
}

// struct route_table_entry *get_best_route(uint32_t ip_dest)
// {
// 	/* TODO 2.2: Implement the LPM algorithm */
// 	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
// 	 * the rtable are in network order already */

// 	for (int i = 0; i < rtable_len; i++)
// 	{
// 		/* Cum tabela este sortată, primul match este prefixul cel mai specific */
// 		if ((rtable[i].prefix & rtable[i].mask) == (ip_dest & rtable[i].mask))
// 		{
// 			return &rtable[i];
// 		}
// 	}
// 	return NULL;
// }

// struct mac_entry *get_mac_entry(uint32_t given_ip)
// {
// 	/* TODO 2.4: Iterate through the MAC table and search for an entry
// 	 * that matches given_ip. */
// 	/* We can iterate thrpigh the mac_table for (int i = 0; i <
// 	 * mac_table_len; i++) */
// 	for (int i = 0; i < mac_table_len; i++)
// 	{
// 		if (mac_table[i].ip == given_ip)
// 		{
// 			/* Returnăm pointerul către intrarea găsită */
// 			return &mac_table[i];
// 		}
// 	}
// 	return NULL;
// }
struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	struct route_table_entry *best_route = NULL;
	struct trie *current = head;

	uint32_t bit_mask;
	uint8_t bit;
	for (int pos = 31; pos >= 0; pos--)
	{
		if (current->route)
			best_route = current->route;

		bit_mask = (1 << pos);
		bit = (ntohl(ip_dest) & bit_mask) >> pos;

		if (bit == 0)
		{
			if (!current->zero)
				break;
			current = current->zero;
		}
		else
		{
			if (!current->one)
				break;
			current = current->one;
		}
	}
	return best_route;
}

struct arp_table_entry *get_arp_entry(uint32_t ip)
{
	for (int i = 0; i < arp_table_len; i++)
	{
		if (ip == arp_table[i].ip)
		{
			return &arp_table[i];
		}
	}
	// daca nu s-a gasit se retuneaza null
	return NULL;
}

/*void send_ARP_request(void *buf, struct route_table_entry *ip_entry)
{
	char request[MAX_PACKET_LEN];
	struct ether_hdr *ether_header;
	struct arp_hdr *arp_header;

	// pun pachetul in coada
	struct ip_hdr *to_send = malloc(ICMP_LEN);
	memcpy(to_send, buf, ICMP_LEN);
	queue_enq(packets, to_send);

	// header pt ethernet
	ether_header = malloc(sizeof(struct ether_hdr));
	ether_header->ethr_type = htons(0x0806);
	get_interface_mac(ip_entry->interface, ether_header->ethr_shost);
	// hwaddr_aton("FF:FF:FF:FF:FF:FF", ether_header->ethr_dhost);
	memset(ether_header->ethr_dhost, 0xff, 6);
	// header arp
	arp_header = malloc(sizeof(struct arp_hdr));
	arp_header->hw_len = 6;
	arp_header->proto_len = 4;
	arp_header->hw_type = htons(1);
	arp_header->proto_type = htons(0x0800);
	arp_header->opcode = htons(1);
	arp_header->sprotoa = inet_addr(get_interface_ip(ip_entry->interface));
	arp_header->tprotoa = ip_entry->next_hop;
	get_interface_mac(ip_entry->interface, arp_header->shwa);

	memcpy(request, ether_header, sizeof(struct ether_hdr));
	memcpy(request + sizeof(struct ether_hdr), arp_header, sizeof(struct arp_hdr));

	send_to_link(ARP_LEN, request, ip_entry->interface);
}*/
void send_ARP_request(void *buf, struct route_table_entry *ip_entry)
{
	char arp_request[MAX_PACKET_LEN];
	struct ip_hdr *stop_packet;
	struct ether_hdr *eth_header;
	struct arp_hdr *arp_header;

	// Oprește pachetul și îl adaugă în coada de pachete amânate
	stop_packet = malloc(ICMP_LEN);
	DIE(stop_packet == NULL, "malloc");
	memcpy(stop_packet, buf, ICMP_LEN);
	struct ip_hdr *ip_header = (struct ip_hdr *)(stop_packet + sizeof(struct ether_hdr));
	ip_header->ver = 4;		  // Version = 4
	ip_header->ihl = 5;		  // IHL = 5
	ip_header->tos = 0;		  // TOS = 0
	ip_header->id = htons(4); // ID = 4
	ip_header->frag = 0;	  // Fragment Offset = 0
	queue_enq(packets, stop_packet);

	// Creează și inițializează header-ul Ethernet
	// eth_hdr = (struct ether_hdr *)arp_request;
	eth_header = malloc(sizeof(struct ether_hdr));
	DIE(eth_header == NULL, "malloc");
	eth_header->ethr_type = htons(0x0806);							// ARP
	get_interface_mac(ip_entry->interface, eth_header->ethr_shost); // MAC sursă
	memset(eth_header->ethr_dhost, 0xff, 6);						// MAC broadcast

	// Creează și inițializează header-ul ARP
	arp_header = malloc(sizeof(struct arp_hdr));
	DIE(eth_header == NULL, "malloc");
	arp_header->hw_type = htons(1);			// Ethernet
	arp_header->proto_type = htons(0x0800); // IPv4
	arp_header->hw_len = 6;					// Lungimea adresei hardware
	arp_header->proto_len = 4;				// Lungimea adresei protocolului
	arp_header->opcode = htons(1);			// ARP Request
	arp_header->sprotoa = inet_addr(get_interface_ip(ip_entry->interface));
	arp_header->tprotoa = ip_entry->next_hop;
	get_interface_mac(ip_entry->interface, arp_header->shwa);

	// creez arp request
	memcpy(arp_request, eth_header, sizeof(struct ether_hdr));
	memcpy(arp_request + sizeof(struct ether_hdr), arp_header, sizeof(struct arp_hdr));

	// Trimite cererea ARP
	send_to_link(ip_entry->interface, arp_request, ARP_LEN);
}

void send_ARP_reply(void *buf, uint8_t target[6], int interface)
{
	struct ether_hdr *eth_header = (struct ether_hdr *)buf;
	struct arp_hdr *arp_header = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

	memcpy(arp_header->thwa, arp_header->shwa, 6);
	memcpy(arp_header->shwa, target, 6);
	arp_header->opcode = htons(2);

	memcpy(eth_header->ethr_dhost, arp_header->thwa, 6);
	memcpy(eth_header->ethr_shost, arp_header->shwa, 6);

	struct ether_hdr *ether_header = (struct ether_hdr *)buf;
	if (ntohs(ether_header->ethr_type != 0x0806))
	{
		perror("Error: send_ARP_reply but it is not ARP");
		return;
	}
	send_to_link(ARP_LEN, buf, interface);
}

void get_ARP_reply(void *buf, int interface)
{
	struct arp_hdr *arp_header = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	if (ntohs(arp_header->opcode) != 2)
	{
		printf("Error: Not an ARP reply\n");
		return;
	}

	//
	struct arp_table_entry new_arp_entry;
	new_arp_entry.ip = arp_header->sprotoa;
	memcpy(new_arp_entry.mac, arp_header->shwa, 6);

	for (int i = 0; i < arp_table_len; i++)
	{
		if (arp_table[i].ip == new_arp_entry.ip)
		{
			memcpy(arp_table[i].mac, new_arp_entry.mac, 6);
			return;
		}
	}
	arp_table[arp_table_len] = new_arp_entry;
	arp_table_len++;
	// coada temporara pentru pachetele ramase
	queue rest = create_queue();

	while (!queue_empty(packets))
	{
		char *popped_packet = queue_deq(packets);
		struct ether_hdr *popped_eth_header = (struct ether_hdr *)(popped_packet);
		struct ip_hdr *popped_ip_header = (struct ip_hdr *)(popped_packet + sizeof(struct ether_hdr));
		struct route_table_entry *best_route = get_best_route(popped_ip_header->dest_addr);
		if (new_arp_entry.ip == best_route->next_hop)
		{
			popped_eth_header->ethr_type = htons(0x0800);
			memcpy(popped_eth_header->ethr_dhost, arp_header->shwa, 6);
			memcpy(popped_eth_header->ethr_shost, arp_header->thwa, 6);

			send_to_link(ICMP_LEN, buf, interface);
		}
		else
		{
			queue_enq(rest, popped_packet);
		}
	}
	packets = rest;
}

void ICMP_echo_reply(char *buf, int interface)
{
	struct ether_hdr *ether_header = (struct ether_hdr *)buf;
	struct ip_hdr *ip_header = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_header = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	swap(&(ether_header->ethr_shost), &(ether_header->ethr_dhost), 6);

	swap(&(ip_header->dest_addr), &(ip_header->source_addr), sizeof(uint32_t));
	ip_header->ttl--;
	ip_header->checksum = 0;
	ip_header->checksum = htons(checksum((uint16_t *)ip_header, sizeof(struct ip_hdr)));
	ip_header->ver = 4;		  // Version = 4
	ip_header->ihl = 5;		  // IHL = 5
	ip_header->tos = 0;		  // TOS = 0
	ip_header->id = htons(4); // ID = 4
	ip_header->frag = 0;	  // Fragment Offset = 0

	icmp_header->mtype = icmp_header->mcode = icmp_header->check = 0;
	icmp_header->check = htons(checksum((uint16_t *)icmp_header, ntohs(ip_header->tot_len) - sizeof(struct ip_hdr)));

	send_to_link(ICMP_LEN, buf, interface);
}

void ICMP_error(char *buf, int interface, uint8_t type)
{
	char packet[MAX_PACKET_LEN];
	struct ether_hdr *eth_hdr;
	struct ip_hdr *ip_hdr;
	struct icmp_hdr *icmp_hdr;
	char *data;

	// Creează header-ele ICMP și adaugă primii 64 de biți din payload-ul pachetului original
	eth_hdr = (struct ether_hdr *)packet;
	ip_hdr = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
	icmp_hdr = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	data = packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
	memcpy(data, buf + sizeof(struct ether_hdr), 64);

	// Inițializează header-ul Ethernet
	memcpy(eth_hdr, buf, sizeof(struct ether_hdr));
	swap(&(eth_hdr->ethr_shost), &(eth_hdr->ethr_dhost), 6);
	eth_hdr->ethr_type = htons(0x0800); // IPv4

	// Inițializează header-ul IP
	memcpy(ip_hdr, buf + sizeof(struct ether_hdr), sizeof(struct ip_hdr));
	ip_hdr->dest_addr = ip_hdr->source_addr;
	ip_hdr->source_addr = inet_addr(get_interface_ip(interface));
	ip_hdr->ttl = 64;
	ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 64);
	ip_hdr->proto = 1; // ICMP
	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
	ip_hdr->ver = 4;	   // Version = 4
	ip_hdr->ihl = 5;	   // IHL = 5
	ip_hdr->tos = 0;	   // TOS = 0
	ip_hdr->id = htons(4); // ID = 4
	ip_hdr->frag = 0;	   // Fragment Offset = 0

	// Inițializează header-ul ICMP
	icmp_hdr->mtype = type;
	icmp_hdr->mcode = 0;
	icmp_hdr->check = 0;
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct ip_hdr)));

	// Trimite pachetul
	size_t len = sizeof(struct ether_hdr) + ntohs(ip_hdr->tot_len);
	printf("Creating ICMP Destination Unreachable packet\n");
	send_to_link(interface, packet, len);
	printf("ICMP packet sent\n");
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	rtable_len = read_rtable(argv[1], rtable);

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_rtable_entries);
	arp_table = malloc(sizeof(struct arp_table_entry) * 100000);
	packets = create_queue();
	create_trie();
	while (1)
	{

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// TODO: Implement the router forwarding logic
		uint32_t interface_ip = inet_addr(get_interface_ip(interface));
		uint8_t mac[6];
		get_interface_mac(interface, mac);

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

		//
		if (!is_broadcast_address(eth_hdr->ethr_dhost) &&
			!is_equal_address(eth_hdr->ethr_dhost, mac))
			continue;
		// ipv4
		if (ntohs(eth_hdr->ethr_type) == 0x0800)
		{
			struct route_table_entry *ip_entry;
			uint16_t old_checksum;
			struct ip_hdr *ip_header = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
			uint32_t d_ip = ntohl(ip_header->dest_addr);
			struct arp_table_entry *mac_entry;
			int is_for_router = 0;
			for (int i = 0; i < argc - 2; i++)
			{
				uint32_t aux_ip = ntohl(inet_addr(get_interface_ip(i)));
				if (aux_ip == d_ip)
				{
					is_for_router = 1;
					break;
				}
			}
			printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->dest_addr));
			if (is_for_router)
			{
				printf("Packet is destined for this router\n");
				ICMP_echo_reply(buf, interface);
				continue;
			}

			old_checksum = ip_header->checksum;
			ip_header->checksum = 0;
			uint16_t new_checksum = htons(checksum((uint16_t *)ip_header, sizeof(struct ip_hdr)));
			if (new_checksum != old_checksum)
			{
				continue;
			}
			if (ip_header->ttl < 2)
			{
				ICMP_error(buf, interface, 11);
				continue;
			}
			ip_header->ttl--;

			ip_entry = get_best_route(ip_header->dest_addr);
			if (!ip_entry)
			{
				printf("Sending ICMP Destination Unreachable for IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->dest_addr));
				ICMP_error(buf, interface, 3);
				continue;
			}

			// update checksum dupa ttl--
			ip_header->checksum = 0;
			ip_header->checksum = htons(checksum((uint16_t *)ip_header, sizeof(struct ip_hdr)));

			// iau adresa mac
			/*Rescriere adrese L2: pentru a forma un cadru corect care să fie transmis
			 la următorul hop, routerul are nevoie să rescrie adresele de L2: adresa sursă va fi
			  adresa interfeței routerului pe care pachetul e trimis mai departe,
			   iar adresa destinație va fi adresa MAC a următorului hop.
			 Pentru a determina adresa următorului hop, routerul folosește protocolul ARP.*/
			get_interface_mac(ip_entry->interface, eth_hdr->ethr_shost);

			mac_entry = get_arp_entry(ip_entry->next_hop);
			if (ip_entry->next_hop == interface_ip)
			{
				// sa nu intre in loop infinit
				// trimte arp tot lui
				continue;
			}
			if (!mac_entry)
			{
				printf("Sending ARP request for IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_entry->next_hop));
				send_ARP_request(buf, ip_entry);
				continue;
			}
			memcpy(eth_hdr->ethr_dhost, mac_entry->mac, 6);
			send_to_link(len, buf, ip_entry->interface);
		}
		// arp
		else if (ntohs(eth_hdr->ethr_type) == 0x0806)
		{
			struct arp_hdr *arp_header = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

			// arp_request
			if (ntohs(arp_header->opcode) == 1)
			{
				uint32_t target = ntohl(arp_header->tprotoa);
				uint32_t interface_ip = ntohl(inet_addr(get_interface_ip(interface)));

				if (target == interface_ip)
				{
					if (is_equal_address(arp_header->thwa, mac))
					{
						printf("Ignoring ARP request sent to itself.\n");
						continue;
					}
					printf("Received ARP request for this router. Sending ARP reply.\n");
					send_ARP_reply(buf, mac, interface);
				}
			}
			else if (ntohs(arp_header->opcode) == 2)
			{
				printf("Received ARP reply. Processing...\n");
				get_ARP_reply(buf, interface);
			}
		}

		/* Note that packets received are in network order,
			any header field which has more than 1 byte will need to be conerted to
			host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
			sending a packet on the link, */
	}
}
