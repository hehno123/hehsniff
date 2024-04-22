#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../include/hehlib.h"
#include <cstdlib>

void print_mac(unsigned char* mac)
{
	for (int i = 0; i < MAC_SIZE; i++) {
		const char* character = (i == 5) ? " " : ":"; 
		printf("%x%s", mac[i], character);
	}
}

void print_ip(unsigned char* ip)
{
	for (int i = 0; i < IP_SIZE; i++) {
                const char* character = (i == 3) ? " " : "."; 
		printf("%u%s", ip[i], character);
	}
}

void print_ip6(unsigned short* ip)
{
	for(int i = 0; i < 8; i++) {
		const char* character = (i == 7) ? " " : ":";
		printf("%x%s", ip[i], character);
	}
}

void get_broadcast_mac(unsigned char* mac)
{
	 memset(mac, 0xff, MAC_SIZE);
}

void get_ip_interface(pcap_if_t *devices, char* interface_name, bpf_u_int32* ip_address_of_device, bpf_u_int32* netmask_device)
{
        /* this loop is searching all interfaces. If interface name is equal to interface that is used in program, we can get ip address and subnet mask */
        for (pcap_if_t *d = devices; d != NULL; d=d->next) {
                bool isFind = false;
		
                if (strcmp(d->name, interface_name) == 0) {
                        for (pcap_addr_t *a = d->addresses; a != NULL; a=a->next) {
                                if (a->addr->sa_family == AF_INET) {
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

                if (isFind) {
                     break;
                }
        }
}

void get_mac_interface(char* interface_name, unsigned char* mac_addr)
{
        struct ifreq get_mac_struct;
        int socket_to_get_mac = socket(AF_INET, SOCK_DGRAM, 0);
        
        get_mac_struct.ifr_addr.sa_family = AF_INET;
        strncpy(get_mac_struct.ifr_name, interface_name, IFNAMSIZ - 1);
        
        ioctl(socket_to_get_mac, SIOCGIFHWADDR, &get_mac_struct);
        close(socket_to_get_mac);
        
        memcpy(mac_addr, (unsigned char*)get_mac_struct.ifr_hwaddr.sa_data, MAC_SIZE);
}


