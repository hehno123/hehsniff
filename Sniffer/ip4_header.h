#ifndef _IP4_HEADER_H
#define _IP4_HEADER_H

#include <sys/types.h>
#include <pcap.h>

/* Protocols define in protocol field */
#define ICMP_IPV4 1
#define IGMP_IPV4 2
#define TCP_IPV4  6
#define UDP_IPV4  17

struct ip4_header
{
	unsigned char  vihl;      /* version and internet header length */
	unsigned char  tos;       /* type of service */
        unsigned short length;    /* total length */
	unsigned short iden;      /* identification */
	unsigned short flag_off;  /* flags and offset */
        unsigned char  ttl;	  /* time to live */
	unsigned char  protocol;  /* what protocol is use in transport layer */
	unsigned short check;     /* header checksum */
        unsigned char  s_addr[4];    /* source address */
	unsigned char  d_addr[4];    /* destination address */

	/* Options */
};

void ipv4_print_message(const u_char* packet);
#endif
