#ifndef _DNS_HEADER_H
#define _DNS_HEADER_H

#include <pcap/pcap.h>

#define DNS_PORT 53
#define DNS_HEADER_LEN 12

/* type field in dns header (see RFC 1035 3.2.2 - 3.2.3) */
#define TYPE_A_DNS 1
#define TYPE_NS_DNS 2
#define TYPE_MD_DNS 3
#define TYPE_MF_DNS 4
#define TYPE_CNAME_DNS 5
#define TYPE_SOA_DNS 6
#define TYPE_MB_DNS 7
#define TYPE_MG_DNS 8
#define TYPE_MR_DNS 9
#define TYPE_NULL_DNS 10
#define TYPE_WKS_DNS 11
#define TYPE_PTR_DNS 12
#define TYPE_HINFO_DNS 13
#define TYPE_MINFO_DNS 14
#define TYPE_MX_DNS 15
#define TYPE_TXT_DNS 16
#define TYPE_AAAA_DNS 28
#define TYPE_AXFR_DNS 252
#define TYPE_MAILB_DNS 253
#define TYPE_MAILA_DNS 254
#define TYPE_ANY_DNS 255

/* class field in dns response header (see RFC 1035 3.2.4) */
#define CLASS_IN_DNS 1
#define CLASS_CS_DNS 2
#define CLASS_CH_DNS 3
#define CLASS_HS_DNS 4
#define CLASS_ANY_DNS 255

#define STANDARD_QUEST_FLAG 0x0100


void dns_print_message(const u_char* packet, unsigned short number);

struct dns_answer_without
{
	unsigned short rtype;
	unsigned short rclass;
	unsigned int ttl;
	unsigned short rdlength;
} __attribute__((packed));


struct dns_question_without
{
	unsigned short qtype;
	unsigned short qclass;
};

struct dns_question
{
	unsigned char* name;
	struct dns_question_without* ques;
};

struct dns_answer
{
	unsigned char* name;
	struct dns_answer_without* ans;
	unsigned char* rdata;
};

struct dns_header
{
	/* header */
	unsigned short id;
	unsigned short flags;
	unsigned short qdcount; /* number of questions */
	unsigned short ancount;	/* number of answers */
	unsigned short nscount;
	unsigned short arcount;
};

#endif
