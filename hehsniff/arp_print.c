#include "../include/arp_header.h"
#include "../include/addresses.h"
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void arp_print_message(const u_char* packet)
{
	struct arpheader* arp_packet;
	arp_packet = (struct arpheader*)(packet + 14);	
        
	/* Check type of hardware identifiers */

	printf("ARP HEADER: ");

	if(ntohs(arp_packet->htype) == ARP_ETHERNET)
	{
		printf("Ethernet, ");
	}

	if(ntohs(arp_packet->htype) == ARP_FIBRE_CHANNEL)
	{
		printf("Fibre Channel, ");
	}

	if(arp_packet->ptype == 8)
	{
		printf("Ipv4 (0x0800), ");
	}

	if(arp_packet->ptype == 1544)
	{
		printf("ARP (0x0806), ");
	}

	if(arp_packet->ptype == 0x8035)
	{
		printf("RARP (0x8035), ");
	}

	printf("Hardware size: %u, ", arp_packet->hlen);
	printf("Protocol size: %u, ", arp_packet->plen);
        
	switch(ntohs(arp_packet->oper))
	{
		case ARP_REQUEST:
			printf("Request (1).");
			break;

		case ARP_REPLY:
			printf("Reply (2).");
			break;

		default:
			printf("gymno.");
			break;
	}
        
	printf("\n            ");
	printf("Mac send: ");
	print_mac(arp_packet->sha);
	printf(" ,IP send: ");
        print_ip(arp_packet->spa);

        printf("\n            ");
	printf("Mac dest: ");
	print_mac(arp_packet->tha);
	printf(" ,IP dest: ");
	print_ip(arp_packet->tpa);
	printf("\n");
}
