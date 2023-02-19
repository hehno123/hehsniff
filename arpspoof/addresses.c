#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include "arp_header.h"
#include <pthread.h>

void get_attacker_mac(char* interface_name, unsigned char* mac_addr)
{
	struct ifreq get_mac_struct;
        int socket_to_get_mac = socket(AF_INET, SOCK_DGRAM, 0);
        
	get_mac_struct.ifr_addr.sa_family = AF_INET;
        strncpy(get_mac_struct.ifr_name, interface_name, IFNAMSIZ - 1);
        
        ioctl(socket_to_get_mac, SIOCGIFHWADDR, &get_mac_struct);
        close(socket_to_get_mac);
        
	memcpy(mac_addr, (unsigned char*)get_mac_struct.ifr_hwaddr.sa_data, 6);	
}

void *timer(void* arg)
{
	 int timer = 0;

	 /* after 20 seconds, when host doesn't reply, program exit */
	 while(timer < 20)
	 {
		  sleep(1);
		  timer++;
	 }

	 printf("Couldn't get arp reply, or host doesn't exist");
	 exit(0);
}

void get_mac_target(pcap_t *handle, unsigned char* victim_mac, unsigned char* attacker_mac, unsigned char* victim_ip, unsigned char* attacker_ip, bpf_u_int32 netmask_device, char* target_ip)
{
	const u_char *packet;
	struct pcap_pkthdr* packet_header;
        const char* filter_first_words = "arp and host ";
	struct bpf_program prg;

        int result_of = 0; 
        unsigned char broadcast_dst[6];

	/* make packet for arp request */
        u_char arp_send[ETHER_SIZE + ARP_SIZE];
        memset(broadcast_dst, 0, MAC_SIZE); 
        make_arp_packet(arp_send, get_broadcast(), attacker_mac, attacker_ip, victim_ip, broadcast_dst, ARP_REQUEST);
       
        /* appends target_ip to filter_first_words. It's needed to filter arp packets that's sender is ip_target. For more information see pcap-filter(7) man page.*/	
	char* filter = (char*)(malloc(strlen(filter_first_words) + strlen(target_ip) + 1));
	filter[0] = '\0';
	strcat(filter, filter_first_words);
	strcat(filter, target_ip);

	/* next to if condition, sets filter */
        if(pcap_compile(handle, &prg, filter, 1, netmask_device) != 0)
        {
             fprintf(stderr, "%s", pcap_geterr(handle));
             exit(1);
        }
        
        if(pcap_setfilter(handle, &prg) != 0)
        {
             fprintf(stderr, "%s", pcap_geterr(handle));
             exit(1);
        }

	pcap_freecode(&prg);

	/* send arp request to get mac address */
        if(pcap_sendpacket(handle, arp_send, ETHER_SIZE + ARP_SIZE) != 0)
        {
                fprintf(stderr, "Error: ", pcap_geterr(handle));
        }


	pthread_t clock_thread;
        pthread_create(&clock_thread, NULL, timer, NULL);

	/* sniff for arp reply */
        while((result_of = pcap_next_ex(handle, &packet_header, &packet)) >= 0)
        {
		if(result_of == 0)
                {
                        printf("Can't get arp reply");
                        exit(0);
                }
                
                struct ether_header* get_mac_struct = (struct ether_header*)(packet);
                memcpy(victim_mac, get_mac_struct->ether_shost, 6);
		pthread_cancel(clock_thread);
                break;
        }
}

void get_ip_interface(pcap_if_t *devices, char* interface_name, bpf_u_int32* ip_address_of_device, bpf_u_int32* netmask_device)
{
	/* this loop is searching all interfaces. If interface name is equal to interface that is used in program, we can get ip address and subnet mask */
        for(pcap_if_t *d = devices; d != NULL; d=d->next)
        {
                bool isFind = false;

                if(strcmp(d->name, interface_name) == 0)
                {
                        for(pcap_addr_t *a = d->addresses; a != NULL; a=a->next)
                        {
                                if(a->addr->sa_family == AF_INET)
                                {
				      /* make sockaddr_in struct to get ip address, see pcap_addr_t struct */
                                      struct sockaddr_in* temp_ip = (struct sockaddr_in*)a->addr;
                                      struct in_addr temp_ip2 = (struct in_addr)(temp_ip->sin_addr);
                                      *ip_address_of_device = temp_ip2.s_addr;
                                      
                                      struct sockaddr_in* temp_mask = (struct sockaddr_in*)a->netmask;
                                      struct in_addr temp_mask2 = (struct in_addr)(temp_mask->sin_addr);
                                      *netmask_device = temp_mask2.s_addr;

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
}

unsigned char* get_broadcast()
{
	 unsigned char broadcast[6];

	 for(int i = 0; i < 6; i++)
	 {
		 broadcast[i] = 0xff;
	 }

	 unsigned char* returned_value = (unsigned char*)(broadcast);
	 return returned_value;
}

