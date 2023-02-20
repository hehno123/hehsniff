#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <stdbool.h>
#include "arp_header.h"
#include <errno.h>
#include <sys/ioctl.h>

void make_arp_packet(u_char* packet, unsigned char* mac_eth_dst, unsigned char* sender_mac, unsigned char* sender_ip, unsigned char* dst_ip, unsigned char* mac_dst, unsigned short oper)
{	
        struct ether_header eth_header;
	struct arpheader arphd; 
 
        memcpy(eth_header.ether_dhost, mac_eth_dst, sizeof(eth_header.ether_dhost));
	memcpy(eth_header.ether_shost, sender_mac,  sizeof(eth_header.ether_shost));
        eth_header.ether_type = htons(ETHERTYPE_ARP);
	
	arphd.htype = htons(ARP_ETHERNET);
	arphd.ptype = htons(ETHERTYPE_IP);
	arphd.hlen =  6; 
	arphd.plen =  4;
        arphd.oper =  htons(oper);

	memcpy(arphd.sha, sender_mac, sizeof(arphd.sha));
	memcpy(arphd.spa, sender_ip, sizeof(arphd.spa));
	memcpy(arphd.tha, mac_dst, sizeof(arphd.tha));
	memcpy(arphd.tpa, dst_ip, sizeof(arphd.tpa)); 

	memcpy(packet, &eth_header, ETHER_SIZE);
	memcpy(packet + ETHER_SIZE, &arphd, ARP_SIZE);
}

        	

