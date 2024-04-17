#include "../include/dns_header.h"
#include <stdio.h>
#include <cstdlib>
#include <string.h>
#include "../include/addresses.h"

void get_name(unsigned char* buff, int name_size, unsigned char* ptr)
{
			int temp = (int)(*ptr);
			ptr++;

			for(int index = 0; index < name_size; index++)
			{
				if(temp == 0)
				{
					temp = (int)(*ptr);
					buff[index] = '.';
				}

				else
				{
					buff[index] = (int)(*ptr);
					temp--;
				}

				ptr++;
			}
}


void dns_print_message(const u_char* packet, unsigned short number)
{
	struct dns_header* header = (struct dns_header*)(packet + number);

	printf("DNS: message: ");

	if(ntohs(header->flags) & 0x1)
	{
		printf("response, ");
	}

	else
	{
		printf("query, ");
	}

	printf("questions: %hu, answers: %hu, answers_auth %hu, answers_add %hu\n", htons(header->qdcount), htons(header->ancount), htons(header->nscount), htons(header->arcount));
	
	int size_of_name_field = 0;

	if(htons(header->qdcount) > 0)
	{
		for(unsigned short i = 0; i < htons(header->qdcount); i++)
		{
			struct dns_question quest;
			int name_size = 0;
			unsigned char* ptr = (unsigned char*)(packet + number + DNS_HEADER_LEN + size_of_name_field);
			
			while(*ptr != '\0')
			{
				int j = (int)(*ptr);
				name_size += j + 1;
				ptr += j + 1;	
			}

			name_size--;	
			ptr = (unsigned char*)(packet + number + DNS_HEADER_LEN + size_of_name_field);
			quest.name = (unsigned char*)calloc(name_size, 1);

			get_name(quest.name, name_size, ptr);

			size_of_name_field += name_size + 2; //we must add to one byte because of null terminator
			quest.ques = (struct dns_question_without*)(packet + number + DNS_HEADER_LEN + size_of_name_field);

			printf("	QUESTION %hu, name: %s, type: %hu, class: %hu\n", i, quest.name, htons(quest.ques->qtype), htons(quest.ques->qclass));
			
			size_of_name_field += sizeof(dns_question_without); //size of type and class fields
			free(quest.name);
		}
	}

	if(htons(header->ancount) > 0)
	{
		
		for(unsigned short i = 0; i < htons(header->ancount); i++)
		{
			struct dns_answer ans;
			int name_size = 0;
			int is_offset = 0;
			unsigned char* ptr = (unsigned char*)(packet + number + DNS_HEADER_LEN + size_of_name_field);
			if((*ptr & 192) == 192)
			{
				unsigned short* temp_ptr = (unsigned short*)(ptr);
				unsigned short temp_num = htons((*temp_ptr)) & 0x3FFF;
				ptr = (unsigned char*)(packet + number + temp_num);
			
			        	
				while(*ptr != '\0')
				{
					int j = (int)(*ptr);
					name_size += j + 1;
					ptr += j + 1;
				}

				name_size--;
				ptr = (unsigned char*)(packet + number + temp_num);
				ans.name = (unsigned char*)calloc(name_size, 1);
				get_name(ans.name, name_size, ptr);
				size_of_name_field += 2;
			}

			else
			{
				while(*ptr != '\0')
				{
					int j = (int)(*ptr);
					name_size += j + 1;
					ptr += j + 1;	
				}

				name_size--;
				ptr = (unsigned char*)(packet + number + DNS_HEADER_LEN + size_of_name_field);
				ans.name = (unsigned char*)calloc(name_size, 1);
				get_name(ans.name, name_size, ptr);
				size_of_name_field += name_size + 2;
			}

			ans.ans = (struct dns_answer_without*)(packet + number + DNS_HEADER_LEN	+ size_of_name_field);
			size_of_name_field += sizeof(dns_answer_without);
			
			ptr = (unsigned char*)(packet + number + DNS_HEADER_LEN + size_of_name_field);
			
			printf("	ANSWER %hu, type: %hu, name: %s, response: ", htons(ans.ans->rdlength), htons(ans.ans->rtype), ans.name);

			if(htons(ans.ans->rtype) == 1)
			{
				ans.rdata = (unsigned char*)calloc(htons(ans.ans->rdlength), 1);
				for(int k = 0; k < 4; k++)
				{
					ans.rdata[k] = (unsigned int)(*ptr);
					ptr++;
				}

				print_ip(ans.rdata);
				printf("\n");
			}

			else
			{
				ans.rdata = (unsigned char*)calloc(htons(ans.ans->rdlength) - 2, 1);
				get_name(ans.rdata, htons(ans.ans->rdlength) - 2, ptr);
				printf("%s", ans.rdata);
			}

			free(ans.rdata);
			free(ans.name);	

		}
	}
}

