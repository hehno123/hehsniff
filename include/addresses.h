#ifndef ADDRESSES_H
#define ADDRESSES_H

#define MAC_SIZE 6
#define IP_SIZE 4

void get_ip_interface(pcap_if_t*, char*, bpf_u_int32*, bpf_u_int32*);
void get_mac_interface(char*, unsigned char*);
void get_broadcast_mac(unsigned char*);
void print_mac(unsigned char*);
void print_ip(unsigned char*);
void print_ip6(unsigned short*);

#endif

