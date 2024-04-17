#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <stdbool.h>
#include "../include/hehlib.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char* packet);

int main(int argc, char **argv)
{
	pcap_if_t *devices;
	char ip[13];
	char subnet_mask[13];

	struct in_addr address;
	struct sockaddr* sockaddr_struct;
	char error_buffer[PCAP_ERRBUF_SIZE];
	int status  = pcap_findalldevs(&devices, error_buffer);
	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr packet_header;
        const char* filter = "";

	if(status != 0)
	{
		printf("Error finding device: %s\n", error_buffer);
		return 1;
	}

        for(pcap_if_t *d=devices; d != NULL; d=d->next)
	{
		printf("+ - - - - - - - - - - - - - - - - - - - - - - - - - -+\n");
	        printf("| Device name: %s", d->name);
		int name_of_device_len = strlen(d->name);

		for(int i = 1; i <= 53 - name_of_device_len - 15; i++)
		{
			printf(" ");
		}

		printf("|\n");
                
		for(pcap_addr_t *a=d->addresses;a != NULL;a=a->next)
		{
			if(a->addr->sa_family == AF_INET)
			{
				printf("| Ip of device: %s", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
                                 
                                for(int i = 1; i <= 53 - 16 - strlen(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr)); i++)
		                {
			                printf(" ");
		                }

		                printf("|\n");

				printf("| Netmask of device network: %s", inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));

                                for(int i = 1; i <= 53 - 29 - strlen(inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr)); i++)
		                {
			                printf(" ");
		                }

		                printf("|\n");

			}
		}
	 }

	printf("+ - - - - - - - - - - - - - - - - - - - - - - - - - -+\n\n");
	char device_name[80]; 
	printf("On what device you want to capture: ");
	scanf("%s", device_name);

	bpf_u_int32 ip_address_of_device;
	bpf_u_int32 netmask_device;
	struct bpf_program prg;
       
	for(pcap_if_t *d = devices; d != NULL; d=d->next)
	{
		bool isFind = false;

		if(strcmp(d->name, device_name) == 0)
		{
			for(pcap_addr_t *a = d->addresses; a != NULL; a=a->next)
			{
			        if(a->addr->sa_family == AF_INET)
				{
				      struct sockaddr_in* temp_ip = (struct sockaddr_in*)a->addr;
				      struct in_addr temp_ip2 = (struct in_addr)(temp_ip->sin_addr);
				      ip_address_of_device = temp_ip2.s_addr;
                                      
				      struct sockaddr_in* temp_mask = (struct sockaddr_in*)a->netmask;
				      struct in_addr temp_mask2 = (struct in_addr)(temp_mask->sin_addr);
				      netmask_device = temp_mask2.s_addr;

				      isFind = true;
				      break;
			        }
			}
		}

		if(isFind)
		{
		     break;
		}
	}

	handle = pcap_open_live(device_name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, error_buffer);
	
        if(handle == NULL) 
        {
             fprintf(stderr, "%s: %s\n", device_name, error_buffer);
             return 1;
        }

	if(pcap_compile(handle, &prg, filter, 1, netmask_device) != 0)
	{
	     fprintf(stderr, "%s", pcap_geterr(handle));
             return 1;
	}
        
        if(pcap_setfilter(handle, &prg) != 0)
	{
	     fprintf(stderr, "%s", pcap_geterr(handle));
             return 1;
        }

        pcap_freecode(&prg);
        pcap_freealldevs(devices);
        int return_pcap_loop = 0;

        return_pcap_loop = pcap_loop(handle, 0, packet_handler, NULL);

	if(return_pcap_loop == -1)
	{
		fprintf(stderr, "%s", pcap_geterr(handle));
		return 1;
	}
       
        return 0;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char* packet)
{
        struct ether_header* eptr;
	eptr = (struct ether_header*) packet;
       
	
        printf("2 LAYER: ");	
	printf("Dest address: ");
        print_mac(eptr->ether_dhost);
	
        printf("Send address: ");
        print_mac(eptr->ether_shost);
  	printf(", ");
        
	if(ntohs(eptr->ether_type) == 0x0806)
	{
		printf("Packet type: ARP\n");
		arp_print_message(packet);
	}

	if(ntohs(eptr->ether_type) == ETH_P_IP)
	{
		printf("Packet type: IPv4\n");
		ipv4_print_message(packet);

		struct ip4_header* header = (struct ip4_header*)(packet + 14);

		if(header->protocol == ICMP_IPV4)
		{
			icmp4_print_message(packet, 14 + sizeof(struct ip4_header));
		}
		
		if(header->protocol == UDP_IPV4)
		{
			udp_print_message(packet, 14 + sizeof(struct ip4_header));
			struct udpheader* udp_header = (struct udpheader*)(packet + 14 + sizeof(struct ip4_header));

			if(ntohs(udp_header->d_port) == 53 || ntohs(udp_header->s_port) == 53)
			{
				dns_print_message(packet, 14 + sizeof(struct ip4_header) + sizeof(struct udpheader));
				printf("\n");
			}

		}

		printf("\n");
	}

	printf("\n");
}


