#include "../include/ip4_header.h"
#include <stdio.h>
#include <pcap.h>
#include "../include/addresses.h"
#include "../include/icmp_header.h"

void ipv4_print_message(const u_char* packet)
{
	struct ip4_header* header = (struct ip4_header*)(packet + 14);
        
	printf("IPV4 HEADER: ");
	unsigned char bytes = (header->vihl & 0x0f);
	printf("ihl: %u(%u), ", (unsigned int)(bytes * 4), (unsigned int)(bytes));
        printf("ttl: %u, ", header->ttl);
        printf("check: %hu\n             ", header->check);
	printf("IP send: ");
        print_ip(header->s_addr);
	printf(",IP dest: ");
	print_ip(header->d_addr);
	printf("\n");
} 	
