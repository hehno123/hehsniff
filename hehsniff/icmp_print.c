#include <pcap.h>
#include <stdio.h>
#include "../include/icmp_header.h"

void icmp4_print_message(const u_char* packet, unsigned short liczba)
{
	struct icmp4_header* header = (struct icmp4_header*)(packet + liczba);
	printf("ICMP HEADER: ");
	printf("type: ");

	switch(header->type)
	{
		case ICMP_REPLY:
			printf("Reply (0), ");
			break;

		case ICMP_DEST_UN:
			printf("Destination Unreachable (3), ");
			break;
                
		case ICMP_REQUEST:
			printf("Request (8), ");
			break;

		case ICMP_TIME_EXC:
			printf("Time Excceeded (11), ");
		        break;
	}

	printf("code: %u, ", header->code);
	printf("checksum: %hu\n", header->checksum);
}
