/*! \file cache.h
*  \brief Hlavi�kov� s�bor modulu implementuj�ceho pam� tokov
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

#ifndef _CACHE_H_
#define _CACHE_H_

#include "ipfix_infelems.h"
#include "list.h"
#include "queue.h"
#include "beem.h"
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <libndpi-1.5.2/libndpi/ndpi_api.h>

/*! Maxim�lna ve�kos� pam�te tokov */
#define MAXFLOWCACHE 1000

/*!
* Inform�cie o pakete
*/

//#define	PACKET_CACHE_SIZE	10*1024
//#define	FLOW_CACHE_SIZE		2048

#define HASH_SIZE	128
#define hash_func(i)    (i) & (HASH_SIZE - 1)
#define TRUE_HASH_SIZE ((u_int64_t)10000000000000000000) /* range top plus 1 */

extern int FLOW_CACHE_SIZE;
extern int PACKET_CACHE_SIZE;
extern int FLOW_IN_BUFF_SIZE;
extern int DPI_CACHE_SIZE;

/*!
* pasivny a aktivny timeout
*/
extern uint64_t passive_timeout;
extern uint64_t active_timeout;
extern uint8_t	biflow_support;


#ifdef IPFIX_EXPORTERTRANSPORTPORT
extern int exp_port;
#endif
#ifdef IPFIX_EXPORTERIPV4ADDRESS
extern struct in_addr exp_ip;
#endif
#ifdef IPFIX_EXPORTERIPV6ADDRESS
extern struct in6_addr exp_ip6;
#endif

//	/aggregation

extern volatile uint8_t doAggregation;


// 	\aggregation

typedef struct _packet_info_t {
	struct _packet_info_t	*next;
	unsigned char		direction;
	uint64_t                timestamp;
	uint8_t 			is_sampled;

	/*! 
	* Zdrojov� MAC adresa
	*/
	u_char  ether_smac[ETHER_ADDR_LEN];
	/*! 
	* Cielov� MAX adresa
	*/
	u_char  ether_dmac[ETHER_ADDR_LEN];
	/*! 
	* Verzia IP protokolu
	*/
	uint8_t ip_version;
	/*
	* Zdrojova IPv4 adresa
	*/
	struct in_addr ip_src_addr;
	/*! 
	* Cielov� IPv4 adresa
	*/
	struct in_addr ip_dst_addr;	
	/*!
	 * Zdrojova IPV6 adresa
	 */
	struct in6_addr ip6_src_addr;
	/*! 
	* Cielov� IPv6 adresa
	*/
	struct in6_addr ip6_dst_addr;
	/*! 
	* TimeToLive paketu
	*/
	uint8_t ip_ttl;		
	/*! 
	* Protokol paketu
	*/
	uint8_t ip_protocol;
	/*! 
	* Typ sluzby
	*/
	uint8_t ip_tos;
	/*! 
	* Differnciated code point
	*/
	uint8_t ip_dcp:6, unused1:2;
	/*! 
	* Identifik�tor r�mca
	*/
	uint16_t ip_id;
	/*! 
	* Offset fragment�cie
	*/
	uint16_t ip_offset;
	/*! 
	* Flag fragment�cie
	*/
#define IP_OFFSET_RF 0x8000           
	/*! 
	* Flag don't fragment
	*/
#define IP_OFFSET_DF 0x4000           
	/*! 
	* Flag fragment more
	*/
#define IP_OFFSET_MF 0x2000           
	/*! 
	* Offset
	*/
#define IP_OFFSET_OFFMASK 0x1fff      
	/*! 
	* Dlzka IP hlavicky
	*/
	uint8_t ip_hlength;
	/*! 
	* Dlzka IP paketu
	*/
	uint16_t ip_length;
	/*! 
	* Dlzka n�kladu paketu
	*/
	uint32_t ip_plength;
	/*! 
	* Zdrojov� port protokolu
	*/
	uint16_t srcport;
	/*! 
	* Cielov� port protokolu
	*/
	uint16_t dstport;    
	/*! 
	* Dlzka UDP hlavicky
	*/
	uint16_t udp_hlength;
	/*! 
	* Sekvencn� c�slo
	*/
	uint32_t tcp_seqnumber;
	/*! 
	* Sekvencn� ACK c�slo
	*/
	uint32_t tcp_acknumber;

	uint8_t tcp_flags;

	/*! 
	* C�slo r�mca
	*/
	uint16_t tcp_window;
	/*! 
	* Smern�k na urgent bity
	*/
	uint16_t tcp_urgent_ptr;
	/*! 
	* Dlzka TCP hlavicky
	*/
	uint16_t tcp_hlength;
	/*! 
	* Typ ICMP spr�vy
	*/
	uint8_t icmp_type;
	/*! 
	* K�d ICMP spr�vy
	*/
	uint8_t icmp_code;
	/*! 
	* Typ ICMPv6 spr�vy
	*/
	uint8_t icmp6_type;
	/*! 
	* K�d ICMPv6 spr�vy
	*/
	uint8_t icmp6_code;
	/*! 
	* Flow label IPv6
	*/
	uint32_t ip6_fl;
	/*! 
	* IPv6 Next Header
	*/
	uint8_t ip6_nh;

	uint16_t	dns_id;
	uint8_t		dns_opcode;
	uint8_t		dns_rd;
	uint8_t		dns_qr;

	uint8_t		layer_3_hlength;
	uint16_t	layer_3_length;
	uint8_t		layer_4_hlength;
	//	uint16_t	layer_4_length; //vieme vypocitat layer_3_length - layer_4_hlength;
	uint8_t	packet_ident[512];
        u_int32_t dpi_protocol;
} packet_info_t;

struct flow_key {
	unsigned char   ip_ver;         //ipVersion
	unsigned char   ip_protocol;    //protocolIdentifier
	unsigned long   ip_src_addr;    //sourceIPv4Address
	unsigned long   ip_dst_addr;    //destinationIPv4Address, isMulticast
	struct in6_addr  ip6_src_addr;  //sourceIPv6Address
	struct in6_addr   ip6_dst_addr; //destinationIPv6Address
	unsigned short  src_port;       //sourceTransportPort
	unsigned short  dst_port;       //destinationTransportPort
	unsigned short	dns_id;
}; //musia sa ulozit, len sa nebudu exportovat

/*
struct packet_info {
struct packet_info 	*next;

unsigned char		ip_ver;
unsigned char		ip_protocol;
uint16_t		ip_length;
unsigned long		ip_src_addr;
unsigned long		ip_dst_addr;
unsigned short		src_port;
unsigned short		dst_port;
unsigned long		sequence;
unsigned long		acknowledgement;
uint16_t		data_length;
unsigned short		flags;
uint64_t		timestamp;
};
*/

//***********************************
//IPFIX_OCTETDELTASUMOFSQUARES
//***********************************

struct cache_item {
	struct cache_item       *next;

#ifdef IPFIX_FLOWID
	uint64_t 		flow_id;                //flowID
#endif
//	int                     flow_type;              //nikde sa nepouziva
	int                     flow_state;             // 0-empty, 1-active, 2-expired
	int                     flow_exp;               // 0-active, 1-expired
	uint8_t                 expiration_reason;	//flowEndReason
        uint8_t                 temp_8;
	struct flow_key         flow_key;
	struct list		packet_cache_fwd;
	struct list		packet_cache_bwd;
	uint8_t 			is_sampled;
    int 				exported_from;
    int 				aggregateExpiredFlow;

#if defined(IPFIX_FLOWSTARTMILLISECONDS) || defined(IPFIX_FLOWSTARTMICROSECONDS) || defined(IPFIX_FLOWSTARTNANOSECONDS) || defined(IPFIX_FLOWSTARTDELTAMICROSECONDS) || defined(IPFIX_FLOWDURATIONMILLISECONDS) || defined(IPFIX_FLOWDURATIONMICROSECONDS)
        uint64_t                flow_start_nano_seconds; 
#endif 
	uint64_t                flow_end_nano_seconds;          
        uint64_t                flow_last_capture_nano_seconds; //pouziva sa na testovanie passivneho timeoutu
#ifdef IPFIX_FLOWSTARTAFTEREXPORT
	uint64_t                flow_start_after_export;
#endif 
	uint64_t		flow_last_exp_nano_seconds;     //pouziva sa na testovanie aktivneho timeoutu
#if defined(IPFIX_OCTETTOTALCOUNT) || defined(IPFIX_OCTETDELTACOUNT)
	uint64_t        octet_total_count; 
	uint64_t		octet_delta_count;
#endif 
#ifdef IPFIX_OCTETTOTALSUMOFSQUARES
	uint64_t                octet_total_sum_of_squares;
#endif         
#if defined(IPFIX_PACKETTOTALCOUNT) || defined(IPFIX_PACKETDELTACOUNT)
	uint64_t                packet_total_count;
	uint64_t		packet_delta_count;
#endif

	// NEMENIT PORADIE!!!
#ifdef IPFIX_ROUNDTRIPTIMENANOSECONDS      
	uint64_t		rtt_avg;        
	uint64_t		rtt_avg_fwd;      
	uint64_t		rtt_avg_bwd;
#endif 
#ifdef IPFIX_PACKETPAIRSTOTALCOUNT  
	uint64_t		rtt_cnt;        
	uint64_t		rtt_cnt_fwd;      
	uint64_t		rtt_cnt_bwd;
#endif         

	uint64_t		layer_3_hlength_fwd;
	uint64_t		layer_3_length_fwd;
	uint64_t		layer_4_hlength_fwd;
	uint64_t		layer_3_hlength_bwd;
	uint64_t		layer_3_length_bwd;
	uint64_t		layer_4_hlength_bwd;
//sa len nastavia v cache.c, nikde sa nepouziva ich hodnota

	uint64_t		tcpFinTotalCount;       //testuje sa flowEndReason 0x03
#ifdef IPFIX_TCPSYNTOTALCOUNT
	uint64_t		tcpSynTotalCount;
#endif 
#ifdef IPFIX_TCPRSTTOTALCOUNT
	uint64_t		tcpRstTotalCount;
#endif 
#ifdef IPFIX_TCPPSHTOTALCOUNT
	uint64_t		tcpPshTotalCount;
#endif 
#ifdef IPFIX_TCPACKTOTALCOUNT
	uint64_t		tcpAckTotalCount;
#endif         
#ifdef IPFIX_TCPURGTOTALCOUNT     
	uint64_t		tcpUrgTotalCount;
#endif         

//v informacnom modeli nie su definovane        
//#ifdef IPFIX_UDPMESSAGELENGTH    
//	uint16_t		layer_4_hlength_udp;
//#endif 
//#ifdef IPFIX_TCPHEADERLENGTH
//	uint8_t			layer_4_hlength_tcp;
//#endif
#ifdef IPFIX_ICMPTYPECODEIPV4
#if !defined(IPFIX_ICMPTYPEIPV4) && !defined(IPFIX_IGMPTYPE)
                uint8_t			icmpTypeIPv4; 
        #endif
        #ifndef IPFIX_ICMPCODEIPV4
                uint8_t			icmpCodeIPv4;
        #endif
#endif        
#if defined(IPFIX_IGMPTYPE) || defined(IPFIX_ICMPTYPEIPV4)
	uint8_t			icmpTypeIPv4; 
#endif 
#ifdef IPFIX_ICMPCODEIPV4
	uint8_t			icmpCodeIPv4;
#endif        
#ifdef IPFIX_TCPURGENTPOINTER
	uint16_t		tcpUrgentPtr;
#endif
#ifdef IPFIX_TCPSEQUENCENUMBER	
        uint32_t		tcpSeqNumber;
#endif        
#ifdef IPFIX_TCPACKNOWLEDGEMENTNUMBER
	uint32_t		tcpAckNumber;
#endif        
#ifdef IPFIX_TCPWINDOWSIZE	
        uint16_t		tcpWindowSize;
#endif        

#if defined(IPFIX_IPCLASSOFSERVICE) || defined(IPFIX_POSTIPCLASSOFSERVICE) || defined(IPFIX_IPDIFFSERVCODEPOINT) || defined (IPFIX_IPPRECEDENCE)
        uint8_t			ToS;
#endif        
#ifdef IPFIX_FRAGMENTIDENTIFICATION	
        uint32_t 		fragmentID;
#endif        
#if defined(IPFIX_FRAGMENTOFFSET) || defined(IPFIX_FRAGMENTFLAGS)
        uint16_t		fragmentOff;
#endif        
#ifdef IPFIX_IPTTL	
        uint8_t			ttl;
#endif        
#if defined(IPFIX_IPHEADERLENGTH) || defined(IPFIX_IPV4IHL)
	uint8_t			ihl;	
#endif        
#if defined(IPFIX_TOTALLENGTHIPV4) || defined(IPFIX_IPTOTALLENGTH) 
	uint64_t		layer_3_length_fst;
#endif        
#if defined(IPFIX_FIRSTPACKETID) || defined(IPFIX_LASTPACKETID )        
	uint8_t			firstPacketID[16];       
	uint8_t			lastPacketID[16];
#endif        
#ifdef IPFIX_ICMPTYPECODEIPV6
        #ifndef IPFIX_ICMPTYPEIPV6
                uint8_t			icmpTypeIPv6;
        #endif
        #ifndef IPFIX_ICMPCODEIPV6
                uint8_t			icmpCodeIPv6;
        #endif
#endif        
#ifdef IPFIX_ICMPTYPEIPV6
	uint8_t			icmpTypeIPv6;
#endif        
#ifdef IPFIX_ICMPCODEIPV6
	uint8_t			icmpCodeIPv6;
#endif        
#ifdef IPFIX_NEXTHEADERIPV6
        uint8_t		    	ipv6NextHeader;
#endif        
#ifdef IPFIX_FLOWLABELIPV6
	uint32_t		ip6_fl;
#endif        
#ifdef IPFIX_EXPORTERIPV4ADDRESS
	struct in_addr		exporter_ipv4;
#endif
#ifdef IPFIX_EXPORTERIPV6ADDRESS
	struct in6_addr		exporter_ipv6;
#endif
#ifdef IPFIX_FLOWKEYINDICATOR
	uint64_t 		flowKey_in;
#endif        
#ifdef IPFIX_IPPAYLOADLENGTH        
	uint32_t		ip_pl;
#endif
#if defined(IPFIX_COLLECTORIPV6ADDRESS) || defined(IPFIX_COLLECTORIPV4ADDRESS)
	struct in_addr		collector_ipv4;
	struct in6_addr		collector_ipv6;
#endif
#ifdef IPFIX_EXPORTINTERFACE
	uint32_t		export_i;
#endif
#ifdef IPFIX_EXPORTPROTOCOLVERSION
	uint8_t			export_protVer;
#endif
#ifdef IPFIX_EXPORTTRANSPORTPROTOCOL
	uint8_t			export_protocol;
#endif
#ifdef IPFIX_COLLECTORTRANSPORTPORT
	uint16_t		collector_port;
#endif
#ifdef IPFIX_EXPORTERTRANSPORTPORT
	uint16_t		exporter_port;
#endif  
#ifdef IPFIX_DROPPEDPACKETDELTACOUNT
	uint64_t		dropped_packet_delta;   
	#ifndef IPFIX_TCPSEQUENCENUMBER
                uint32_t			tcpSeqNumber;
        #endif
        #ifndef IPFIX_TCPACKNOWLEDGEMENTNUMBER
                uint32_t			tcpAckNumber;
        #endif
        #ifndef IPFIX_IPPAYLOADLENGTH
                uint32_t			ip_pl;
        #endif
#endif
#ifdef IPFIX_DROPPEDOCTETDELTACOUNT
	uint64_t		dropped_octet_delta;   
        #if !defined(IPFIX_TCPSEQUENCENUMBER) && !defined(IPFIX_DROPPEDPACKETDELTACOUNT)
                uint32_t			tcpSeqNumber;
        #endif
        #if !defined(IPFIX_TCPACKNOWLEDGEMENTNUMBER) && !defined(IPFIX_DROPPEDPACKETDELTACOUNT)
                uint32_t			tcpAckNumber;
        #endif
        #if !defined(IPFIX_IPPAYLOADLENGTH) && !defined(IPFIX_DROPPEDPACKETDELTACOUNT)
                uint32_t			ip_pl;
		#endif
#endif
#ifdef IPFIX_ORIGINALFLOWSPRESENT
    uint64_t 		originalFlowsPresent;
#endif
#ifdef IPFIX_ORIGINALFLOWSINITIATED
    uint64_t		originalFlowsInitiated;
#endif
#ifdef IPFIX_ORIGINALFLOWSCOMPLETED   
    uint64_t		originalFlowsCompleted;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFSOURCEIPADDRESS   
    uint64_t    	distCntOfSrcIPAddr;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFDESTINATIONIPADDRESS   
    uint64_t    	distCntOfDstIPAddr;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFSOURCEIPV4ADDRESS   
    uint32_t	    distCntOfSrcIPv4Addr;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFDESTINATIONIPV4ADDRESS   
    uint32_t	    distCntOfDstIPv4Addr;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFSOURCEIPV6ADDRESS   
    uint64_t 	   	distCntOfSrcIPv6Addr;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFDESTINATIONIPV6ADDRESS   
    uint64_t    	distCntOfDstIPv6Addr;
#endif
#ifdef IPFIX_SOURCEMACADDRESS
	u_char source_mac[ETHER_ADDR_LEN];
#endif
#ifdef IPFIX_DESTINATIONMACADDRESS
	u_char destination_mac[ETHER_ADDR_LEN];
#endif
#ifdef IPFIX_APPLICATIONID
        unsigned char appId[4];
#endif
#ifdef IPFIX_APPLICATIONNAME
      unsigned char appName[32];  
#endif
};

struct dpi_item {
    struct dpi_item *next;
    uint64_t flowid;
//    struct flow_key flow_key;
    struct ndpi_flow_struct ndpi_flow;
    struct ndpi_id_struct src;
    struct ndpi_id_struct dst;
};

extern struct list		pcache_free_list;
extern struct queue		pcache_input_queue;

extern struct list dpicache_free_list;
extern struct list dpicache_hash_list[HASH_SIZE];

#define cache_list_add(l, i)            list_add_first((struct list *)(l), (struct list_item *)(i))
#define cache_list_remove(l, i)         (struct cache_item *)list_remove_item((struct list *)(l), (struct list_item *)(i))
#define cache_list_get(l)               (struct cache_item *)list_remove_first((struct list *)(l))

#define pcache_list_add(l, i)           list_add_first((struct list *)(l), (struct list_item *)(i))
#define pcache_list_remove(l, i)        (struct _packet_info_t *)list_remove_item((struct list *)(l), (struct list_item *)(i))
#define pcache_list_get(l)              (struct _packet_info_t *)list_remove_first((struct list *)(l))

#define pqueue_put(l, i)		queue_add_last((struct queue *)(l), (struct list_item *)(i))
#define pqueue_get(l)			(struct _packet_info_t *)queue_remove_first((struct queue *)(l))
#define pqueue_empty(l)			(((struct queue *)(l))->last == NULL)

void flowCacheExport(void);
void flowCachePacketProcessing(void);
uint64_t getCurrentTime(int precision);
void debugFlowCache(void);
void flowCacheTimeExpire(struct cache_item *item, int i, int mark);
void flowCacheTimeExpireInit(void);
int flowCacheInit(void);
struct cache_item *cache_get_item(packet_info_t *packet);
struct dpi_item *dpi_get_item(packet_info_t *packet, uint64_t key);
void cache_status(void);
uint64_t flow_identificator(struct flow_key *fk);
void flowAggregationProcess(void);

#endif //_CACHE_H_
