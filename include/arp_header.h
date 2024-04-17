#ifndef _ARP_HEADER_H
#define _ARP_HEADER_H

#include <pcap/pcap.h>
#include <netinet/if_ether.h>

void arp_print_message(const u_char* packet);
void make_arp_packet(u_char* ,unsigned char* , unsigned char* , unsigned char* , unsigned char* , unsigned char*, unsigned short);
void get_mac_target(pcap_t*, unsigned char*, unsigned char*, unsigned char*, unsigned char*, bpf_u_int32, char*);

/* hardware identifiers */
#define ARP_RESERVED 0
#define ARP_ETHERNET 1
#define ARP_EETHERNET 2     /*expermiental ethernet*/
#define ARP_RADIO_AX25 3
#define ARP_PRONET 4
#define ARP_CHAOS 5
#define ARP_IEEE8002 6
#define ARP_ARCNET 7
#define ARP_HYPERCHANNEL 8
#define ARP_LANSTAR 9
#define ARP_FRAMERELAY 15
#define ARP_HDLC 17
#define ARP_FIBRE_CHANNEL 18
#define ARP_STRIP 23
#define ARP_IEEE1394 24
#define ARP_INFINIBAND 32

/* operation codes */
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ARP_REQUEST_REVERSE 3
#define ARP_REPLY_REVERSE 4
#define DRARP_REQUEST 5
#define DRARP_REPLY 6
#define DRARP_ERROR 7
#define INARP_REQUEST 8
#define INARP_REPLY 9
#define ARP_NAK 10

struct arpheader
{
       unsigned short htype; /* newtork link protocol */
       unsigned short ptype; /* internetwork protocol for arp */
       unsigned char  hlen; /* length of hardware address */
       unsigned char  plen; /* length of internetwork address */
       unsigned short oper; /* operation that the sender is performing */
       unsigned char  sha[6]; /* Mac address of sender */
       unsigned char  spa[4]; /* protocol address of sender */
       unsigned char  tha[6]; /* Mac address of receiver */
       unsigned char  tpa[4]; /* protocol address of receiver */
};

#endif
