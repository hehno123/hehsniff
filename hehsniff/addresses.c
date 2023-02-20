#include <stdio.h>
#include "addresses.h"

void print_mac(unsigned char mac[6])
{
	for(int i = 0; i < 6; i++)
	{
		const char* character = (i == 5) ? " " : ":"; 
		printf("%x%s", mac[i], character);
	}
}

void print_ip(unsigned char ip[4])
{
	for(int i = 0; i < 4; i++)
	{
                const char* character = (i == 3) ? " " : "."; 
		printf("%u%s", ip[i], character);
	}
}

