#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "../include/hehlib.h"

void *timer(void* arg)
{
	 int timer = 0;

	 /* after 20 seconds, when host doesn't reply, program exit */
	 while (timer < 20) {
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
        unsigned char broadcast_dst[MAC_SIZE];

	/* make packet for arp request */
        u_char arp_send[ETHER_SIZE + ARP_SIZE];
	get_broadcast_mac(broadcast_dst);
        make_arp_packet(arp_send, broadcast_dst, attacker_mac, attacker_ip, victim_ip, broadcast_dst, ARP_REQUEST);
       
        /* appends target_ip to filter_first_words. It's needed to filter arp packets that's sender is ip_target. For more information see pcap-filter(7) man page.*/	
	char* filter = (char*)(malloc(strlen(filter_first_words) + strlen(target_ip) + 1));
	filter[0] = '\0';
	strcat(filter, filter_first_words);
	strcat(filter, target_ip);

	/* next to if condition, sets filter */
        if (pcap_compile(handle, &prg, filter, 1, netmask_device) != 0) {
             fprintf(stderr, "%s", pcap_geterr(handle));
             exit(1);
        }
        
        if (pcap_setfilter(handle, &prg) != 0) {
             fprintf(stderr, "%s", pcap_geterr(handle));
             exit(1);
        }

	pcap_freecode(&prg);

	/* send arp request to get mac address */
        if (pcap_sendpacket(handle, arp_send, ETHER_SIZE + ARP_SIZE) != 0) {
                fprintf(stderr, "Error: ", pcap_geterr(handle));
        }


	pthread_t clock_thread;
        pthread_create(&clock_thread, NULL, timer, NULL);

	/* sniff for arp reply */
        while ((result_of = pcap_next_ex(handle, &packet_header, &packet)) >= 0) {
		if (result_of == 0) {
                        printf("Can't get arp reply");
                        exit(0);
                }
                
                struct ether_header* get_mac_struct = (struct ether_header*)(packet);
                memcpy(victim_mac, get_mac_struct->ether_shost, MAC_SIZE);
		pthread_cancel(clock_thread);
                break;
        }
}
