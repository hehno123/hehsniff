#ifndef _ICMP_HEADER_H
#define _ICMP_HEADER_H

void icmp4_print_message(const u_char*, unsigned short);

/* ICMP message type */
#define ICMP_REPLY 0
#define ICMP_DEST_UN 3
#define ICMP_REQUEST 8
#define ICMP_TIME_EXC 11

struct icmp4_header
{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
};

#endif
