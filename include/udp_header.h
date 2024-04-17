#ifndef _UDP_HEADER_H
#define _UDP_HEADER_H

#include <pcap/pcap.h>
void udp_print_message(const u_char* packet, unsigned short liczba);

struct udpheader
{
	unsigned short s_port;
	unsigned short d_port;
	unsigned short length;
	unsigned short check;
};

#endif

