#ifndef HEHLIB_H
#define HEHLIB_H

#include "arp_header.h"
#include "addresses.h"
#include "ip4_header.h"
#include "dns_header.h"
#include "udp_header.h"
#include "icmp_header.h"

#include <net/if.h>
#include <sys/ioctl.h>
#include <stdbool.h>

void make_dns_header(unsigned char*, u_int16_t, u_int16_t, u_int16_t, u_int16_t, u_int16_t, u_int16_t);
void make_ip4_header(unsigned char*, unsigned char, unsigned char, unsigned short, unsigned short, unsigned short, unsigned char, unsigned char, unsigned short, unsigned char*, unsigned char*);
void make_dns_question(unsigned char*, char*, u_int16_t, u_int16_t);

#define ETHER_SIZE 14
#define ARP_SIZE 28

#endif 

