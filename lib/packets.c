#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include "../include/hehlib.h"

void make_arp_packet(u_char *packet, unsigned char* mac_eth_dst, unsigned char* sender_mac, unsigned char* sender_ip, unsigned char* dst_ip, unsigned char* mac_dst, unsigned short oper)
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

void make_dns_header(unsigned char *packet, u_int16_t id, u_int16_t flags, u_int16_t qdcount, u_int16_t ancount, u_int16_t nscount, u_int16_t arcount)
{
	struct dns_header dns_hdr;
        dns_hdr.id = htons(id);
	dns_hdr.flags = htons(flags);
	dns_hdr.qdcount = htons(qdcount);
	dns_hdr.ancount = ancount;
	dns_hdr.nscount = nscount;
	dns_hdr.arcount = arcount;

	memcpy(packet, &dns_hdr, sizeof(struct dns_header));
}

void make_dns_question(unsigned char* packet, char* qname, u_int16_t qtype, u_int16_t qclass)
{
        int loop_counter = 0;	
       	
	packet[strlen(qname) + 1] = '\0';

	for (int i = strlen(qname) - 1; i >= 0; i--) {
		if (qname[i] == '.')
		{
			 packet[i + 1] = (unsigned char)(loop_counter);
		         loop_counter = 0;
		}

		else
		{
			 packet[i + 1] = (unsigned char)(qname[i]);
			 loop_counter++;
	        }
	}

	packet[0] = (unsigned char)(loop_counter);
      	
	qtype = htons(qtype);
	qclass = htons(qclass);

        memcpy(packet + strlen(qname) + 2, &qtype, 2);
        memcpy(packet + strlen(qname) + 4, &qclass, 2);	
}

void make_ip4_header(unsigned char *packet, unsigned char vihl, unsigned char tos, unsigned short length, unsigned short iden, unsigned short flag_off, unsigned char ttl, unsigned char protocol, unsigned short check, unsigned char* s_addr, unsigned char *d_addr)
{
	struct ip4_header ip4_hdr;
	ip4_hdr.vihl = vihl;
	ip4_hdr.tos = tos;
	ip4_hdr.length = length;
	ip4_hdr.iden = htonl(iden);
        ip4_hdr.flag_off = flag_off;
	ip4_hdr.ttl = ttl;
	ip4_hdr.protocol = protocol;
	ip4_hdr.check = check;

	memcpy(ip4_hdr.s_addr, s_addr, IP_SIZE);
	memcpy(ip4_hdr.d_addr, d_addr, IP_SIZE);
	memcpy(packet, &ip4_hdr, length);
}
