/*! \file capture.h
*  \brief Hlavi�kov� s�bor pre modul odchyt�vania
*
*/

/*
*    Copyright (c) 2009 Lubos Husivarga
*
*    This file is part of BEEM.
*
*    BEEM is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    BEEM is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with BEEM.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _CAPTURE_H_
#define _CAPTURE_H_

// integer typy
#include <inttypes.h>
// hlavickovy subor pre libpcap
#include <pcap.h>
#include <pthread.h>
// struktura ethernet hlavicky
#include <net/ethernet.h>
// struktura IP hlavicky
#include <netinet/ip.h>
// struktura IPv6 hlavicky
#include <netinet/ip6.h>
// struktura TCP hlavicky
#include <netinet/tcp.h>
// struktura UDP hlavicky
#include <netinet/udp.h>
// struktura ICMP hlavicky
#include <netinet/ip_icmp.h>
// struktura ICMPv6 hlavicky
#include <netinet/icmp6.h>
// struktura IGMP hlavicky
#include <netinet/igmp.h>
// flow cache struktury a funkcie
#include "cache.h"

struct DNS_HEADER {
	unsigned id :16; /* query identification number */
#if defined(WORDS_BIGENDIAN)
	/* fields in third byte */
	unsigned qr: 1; /* response flag */
	unsigned opcode: 4; /* purpose of message */
	unsigned aa: 1; /* authoritive answer */
	unsigned tc: 1; /* truncated message */
	unsigned rd: 1; /* recursion desired */
	/* fields in fourth byte */
	unsigned ra: 1; /* recursion available */
	unsigned unused :1; /* unused bits (MBZ as of 4.9.3a3) */
	unsigned ad: 1; /* authentic data from named */
	unsigned cd: 1; /* checking disabled by resolver */
	unsigned rcode :4; /* response code */
	//#endif
#else
	/* fields in third byte */
	unsigned rd :1; /* recursion desired */
	unsigned tc :1; /* truncated message */
	unsigned aa :1; /* authoritive answer */
	unsigned opcode :4; /* purpose of message */
	unsigned qr :1; /* response flag */
	/* fields in fourth byte */
	unsigned rcode :4; /* response code */
	unsigned cd: 1; /* checking disabled by resolver */
	unsigned ad: 1; /* authentic data from named */
	unsigned unused :1; /* unused bits (MBZ as of 4.9.3a3) */
	unsigned ra :1; /* recursion available */
#endif
	/* remaining bytes */
	unsigned qdcount :16; /* number of question entries */
	unsigned ancount :16; /* number of answer entries */
	unsigned nscount :16; /* number of authority entries */
	unsigned arcount :16; /* number of resource entries */
};

/*
struct DNS_HEADER {
unsigned short	 id;		    // identification number
//	uint8_t		 rd     :1;		// recursion desired
//	uint8_t		 tc     :1;		// truncated message
//	uint8_t		 aa     :1;		// authoritive answer
//	uint8_t		 opcode :4;	    // purpose of message
//	uint8_t		qr     :1;		// query/response flag
//	uint8_t		 rcode  :4;	    // response code
//	uint8_t		 cd     :1;	    // checking disabled
//	uint8_t		 ad     :1;	    // authenticated data
//	uint8_t		 z      :1;		// its z! reserved
//	uint8_t		 ra     :1;		// recursion available
unsigned char	a;
unsigned char	b;

uint16_t	 q_count;	    // number of question entries
uint16_t	 ans_count;	// number of answer entries
uint16_t	 auth_count;	// number of authority entries
uint16_t	 add_count;	// number of resource entries
};
*/

#define SNAP_LEN 1518

/*! 
* Typ pre ethernetov� hlavi�ku
*/
typedef struct ether_header header_ethernet_t;

/*! 
* Typ pre IP hlavi�ku
*/
typedef struct ip header_ip_t;

/*! 
* Typ pre IPv6 hlavi�ku
*/
typedef struct ip6_hdr header_ip6_t;


/*! 
* Typ pre TCP hlavi�ku
*/
typedef struct tcphdr header_tcp_t;

/*! 
* Typ pre UDP hlavi�ku
*/
typedef struct udphdr header_udp_t;

/*! 
* Typ pre ICMP hlavi�ku
*/
typedef struct icmphdr header_icmp_t;

/*! 
* Typ pre ICMPv6 hlavi�ku
*/
typedef struct icmp6_hdr header_icmp6_t;

/*! 
* Typ pre IGMP hlavi�ku
*/
typedef struct igmp header_igmp_t;

struct packet_capturing_thread {
	char		*interface;
	pcap_t		*descr;
	long long int	packet_count;
	pthread_t	thread;
	long int	sampling_param1;
	long int	sampling_param2;
	long int	sampling_type;
	char		*dump_file;
	char		*pcap_filter;
        struct ndpi_detection_module_struct *ndpi_struct;
};

/*!
* Premenna pre ulozenie casu poslednej inicializacie
*/
extern uint64_t init_time;
extern int capture_interrupted;

void startCapture();
void doCallback(u_char *arguments, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void catchInt(int sig_num);
void catchInt2(int sig_num);
void processPacket(struct packet_capturing_thread *t, const u_char *packet, const struct pcap_pkthdr *pkthdr);
void addPacket(packet_info_t *packet_info);
void* threadExport(void *arg);
void* threadTimeExpire(void *arg);
struct ndpi_detection_module_struct *setup_ndpi();
void terminate_ndpi(struct ndpi_detection_module_struct *mod);

#endif //_CAPTURE_H_
