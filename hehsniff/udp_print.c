#include "../include/udp_header.h"
#include <stdio.h>

void udp_print_message(const u_char* packet, unsigned short liczba)
{
	struct udpheader* udp_header = (struct udpheader*)(packet + liczba);

	printf("UDP HEADER: ");
	printf("src port: %u, dst port: %u, length: %u, check: %u\n", ntohs(udp_header->s_port), ntohs(udp_header->d_port), ntohs(udp_header->length), ntohs(udp_header->check));
}

