/*! \file cache.c
*  \brief Modul implementuj�ci pam� tokov.
* 
*  Tento modul m� na starosti kompletn� obsluhu pam�te tokov (FlowCache). Zabezpe�uje jej inicializ�ciu a management (v s��innosti s meracim procesom).
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


//#include <libndpi-1.5.2/libndpi/ndpi_api.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
//#include <bits/string3.h>
#include "cache.h"
#include "config.h"
#include "debug.h"
#include "export.h"
#include "sync.h"
#include "packetIdent.h"
#include "MurmurHash.h"
#include "aggregation.h"
//#include "dpi_def.h"

// pole DPI funkcii
//SearchFunctionPtr searchfunctions[] = {&search_http};

extern pthread_mutex_t flow_cache_mutex;
extern pthread_mutex_t pcache_input_mutex;
extern pthread_cond_t	pcache_input_wait;
extern int capture_interrupted;
extern pthread_mutex_t dpi_cache_mutex;

extern struct packet_capturing_thread *pcts;

#ifdef IPFIX_EXPORTERTRANSPORTPORT
int exp_port;
#endif
#ifdef IPFIX_EXPORTERIPV4ADDRESS
struct in_addr exp_ip;
#endif
#ifdef IPFIX_EXPORTERIPV6ADDRESS
struct in6_addr exp_ip6;
#endif

#if defined(IPFIX_COLLECTORIPV6ADDRESS) || defined(IPFIX_COLLECTORIPV4ADDRESS)
struct addrinfo hint, *info;
#endif

#ifdef IPFIX_EXPORTTRANSPORTPROTOCOL
struct protoent *proto;
#endif

#ifdef IPFIX_EXPORTINTERFACE
char *errbuff;
#endif

int FLOW_CACHE_SIZE = 0;
int PACKET_CACHE_SIZE = 0;
int FLOW_IN_BUFF_SIZE = 0;
uint64_t AGGREGATION_TRIGGER = 0;
int DPI_CACHE_SIZE = 0;

struct cache_item	*cache_base;
void			*pcache_base;
struct dpi_item         *dpicache_base;
//struct cache_item	cache_items[FLOW_CACHE_SIZE];
//struct _packet_info_t	pcache_items[PACKET_CACHE_SIZE];

struct list		cache_hash_list[HASH_SIZE];
struct list		cache_free_list;
struct list		cache_expired_list;
struct list		pcache_free_list;
struct list 		cache_remove_list;
struct queue		pcache_input_queue;
struct list             dpicache_free_list;
struct list             dpicache_hash_list[HASH_SIZE];

//aggregation
volatile  uint8_t doAggregation;
uint8_t			automaticAggregation = 0;
int 			AGGREGATION_CONDITION = 0;
struct list		aggreg_cache_hash_list_first[HASH_SIZE];
struct list		aggreg_cache_hash_list_second[HASH_SIZE];
struct list		aggreg_cache_hash_list_third[HASH_SIZE];
struct list		aggreg_cache_hash_list_fourth[HASH_SIZE]; 

int first_aggreg_value;
int second_aggreg_value;
int third_aggreg_value;
int fourth_aggreg_value;

uint64_t 		aggreg_timestamp = 0;

/*!
* pasivny a aktivny timeout
*/
uint64_t		passive_timeout;
uint64_t		active_timeout;
uint64_t		packet_timeout;
uint8_t			biflow_support;




// return
// 0 - packet does not match flow key
// 1 - packet matches flow key, direction forward
// 2 - packet matches flow key, direction backward
int compare_keys(struct flow_key *fk, packet_info_t *pkt){
	if(fk->ip_ver != pkt->ip_version)
		return 0;
	else if(fk->ip_ver == 4)
	{
	if(fk->ip_protocol != pkt->ip_protocol)
		return 0;
	if(fk->ip_src_addr == pkt->ip_src_addr.s_addr)
		if(fk->src_port == pkt->srcport)
			if(fk->ip_dst_addr == pkt->ip_dst_addr.s_addr)
				if(fk->dst_port == pkt->dstport){
					if(fk->ip_protocol == IPPROTO_UDP && (fk->src_port == 53 || fk->dst_port == 53)){
						if(fk->dns_id == pkt->dns_id){
							return 1;
						}else{	
							return 0;
						}
					}else{
						return 1;
					}
				}
	if(biflow_support)
	if(fk->ip_protocol == IPPROTO_TCP || fk->ip_protocol == IPPROTO_ICMP || (fk->ip_protocol == IPPROTO_UDP && (fk->dst_port == 53 || fk->src_port == 53)))
		if(fk->ip_src_addr == pkt->ip_dst_addr.s_addr)
			if(fk->src_port == pkt->dstport)
				if(fk->ip_dst_addr == pkt->ip_src_addr.s_addr)
					if(fk->dst_port == pkt->srcport){
						if(fk->ip_protocol == IPPROTO_UDP && (fk->src_port == 53 || fk->dst_port == 53)){
							if(fk->dns_id == pkt->dns_id){
								return 2;
							}else{    
								return 0;
							}
						}else{
							return 2;
						}
					}
					return 0;
	} else if(fk->ip_ver == 6)
	{
	if(fk->ip_protocol != pkt->ip_protocol)
		return 0;
	if((fk->ip6_src_addr.s6_addr32[0] == pkt->ip6_src_addr.s6_addr32[0]) && (fk->ip6_src_addr.s6_addr32[1] == pkt->ip6_src_addr.s6_addr32[1])
		&& (fk->ip6_src_addr.s6_addr32[2] == pkt->ip6_src_addr.s6_addr32[2]) && (fk->ip6_src_addr.s6_addr32[3] == pkt->ip6_src_addr.s6_addr32[3]))
		if(fk->src_port == pkt->srcport)
			if((fk->ip6_dst_addr.s6_addr32[0] == pkt->ip6_dst_addr.s6_addr32[0]) && (fk->ip6_dst_addr.s6_addr32[1] == pkt->ip6_dst_addr.s6_addr32[1])
				&& (fk->ip6_dst_addr.s6_addr32[2] == pkt->ip6_dst_addr.s6_addr32[2]) && (fk->ip6_dst_addr.s6_addr32[3] == pkt->ip6_dst_addr.s6_addr32[3]))
				if(fk->dst_port == pkt->dstport){
					if(fk->ip_protocol == IPPROTO_UDP && (fk->src_port == 53 || fk->dst_port == 53)){
						if(fk->dns_id == pkt->dns_id){
							return 1;
						}else{	
							return 0;
						}
					}else{
						return 1;
					}
				}
		
	if(biflow_support)
	if(fk->ip_protocol == IPPROTO_TCP || fk->ip_protocol == IPPROTO_ICMPV6 || (fk->ip_protocol == IPPROTO_UDP && (fk->dst_port == 53 || fk->src_port == 53)))
		if((fk->ip6_src_addr.s6_addr32[0] == pkt->ip6_dst_addr.s6_addr32[0]) && (fk->ip6_src_addr.s6_addr32[1] == pkt->ip6_dst_addr.s6_addr32[1])
			&& (fk->ip6_src_addr.s6_addr32[2] == pkt->ip6_dst_addr.s6_addr32[2]) && (fk->ip6_src_addr.s6_addr32[3] == pkt->ip6_dst_addr.s6_addr32[3])) 
			if(fk->src_port == pkt->dstport)
				if((fk->ip6_dst_addr.s6_addr32[0] == pkt->ip6_src_addr.s6_addr32[0]) && (fk->ip6_dst_addr.s6_addr32[1] == pkt->ip6_src_addr.s6_addr32[1])
					&& (fk->ip6_dst_addr.s6_addr32[2] == pkt->ip6_src_addr.s6_addr32[2]) && (fk->ip6_dst_addr.s6_addr32[3] == pkt->ip6_src_addr.s6_addr32[3]))
					if(fk->dst_port == pkt->srcport){
						if(fk->ip_protocol == IPPROTO_UDP && (fk->src_port == 53 || fk->dst_port == 53)){
							if(fk->dns_id == pkt->dns_id){
								return 2;
							}else{    
								return 0;
							}
						}else{
							return 2;
						}
					}
					return 0;
		}			
	return 0;
}

uint64_t flow_identificator(struct flow_key *fk){

	char string_for_hash[300];
	//uint64_t hash;

	if(fk->ip_ver == 4){

		sprintf(string_for_hash,"%d%lu%lu%d%d",
			fk->ip_protocol,
			fk->ip_src_addr,
			fk->ip_dst_addr,
			fk->src_port,
			fk->dst_port);
	
//	printf("Out of IPV4: %s | %llu\n",string_for_hash, hashes(string_for_hash));
	}

	else if(fk->ip_ver == 6){
		
		sprintf(string_for_hash,"%d%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x%d%d",
			fk->ip_protocol,
			fk->ip6_src_addr.s6_addr[0], fk->ip6_src_addr.s6_addr[1],
			fk->ip6_src_addr.s6_addr[2], fk->ip6_src_addr.s6_addr[3],
			fk->ip6_src_addr.s6_addr[4], fk->ip6_src_addr.s6_addr[5],
			fk->ip6_src_addr.s6_addr[6], fk->ip6_src_addr.s6_addr[7],
			fk->ip6_src_addr.s6_addr[8], fk->ip6_src_addr.s6_addr[9],
			fk->ip6_src_addr.s6_addr[10], fk->ip6_src_addr.s6_addr[11],
			fk->ip6_src_addr.s6_addr[12], fk->ip6_src_addr.s6_addr[13],
			fk->ip6_src_addr.s6_addr[14], fk->ip6_src_addr.s6_addr[15],
			fk->ip6_dst_addr.s6_addr[0], fk->ip6_dst_addr.s6_addr[1],
			fk->ip6_dst_addr.s6_addr[2], fk->ip6_dst_addr.s6_addr[3],
			fk->ip6_dst_addr.s6_addr[4], fk->ip6_dst_addr.s6_addr[5],
			fk->ip6_dst_addr.s6_addr[6], fk->ip6_dst_addr.s6_addr[7],
			fk->ip6_dst_addr.s6_addr[8], fk->ip6_dst_addr.s6_addr[9],
			fk->ip6_dst_addr.s6_addr[10], fk->ip6_dst_addr.s6_addr[11],
			fk->ip6_dst_addr.s6_addr[12], fk->ip6_dst_addr.s6_addr[13],
			fk->ip6_dst_addr.s6_addr[14], fk->ip6_dst_addr.s6_addr[15],
			fk->src_port,
			fk->dst_port);			
	}
	//printf("STRING FOR HASH FLOW ID :%s\n",string_for_hash);
	//printf("SIZE OF:%d\n",sizeof(string_for_hash));
	//hash = MurmurHash64B (string_for_hash,sizeof(string_for_hash),(unsigned int)2);
	

	//printf("HASHAA FLOW ID:%llu\n",hash);
	return (hashes(string_for_hash));
}
struct cache_item *cache_get_item(packet_info_t *packet){
    int hash, direction;
    struct cache_item *item;

    if(doAggregation){
        item = packet_to_flow(packet);
    }
    else{
        hash = hash_func(packet->srcport + packet->dstport);
        item = (struct cache_item *)cache_hash_list[hash].first;
        while(item){
            direction = compare_keys(&item->flow_key, packet);
            if(direction){
                packet->direction = direction;
                break;
            }
            item = item->next;
        }
        return item;
    }
    
    return item;
}

struct dpi_item *dpi_get_item(packet_info_t *packet, uint64_t key) {
    int hash, direction;
    struct dpi_item *item;
    
    hash = hash_func(packet->srcport + packet->dstport);
    item = (struct dpi_item *)dpicache_hash_list[hash].first;
    while (item) {
        if (key == item->flowid);
            break;
        item = item->next;
    }
    
    return item;
}

struct _packet_info_t *find_packet_pair(struct list *list, struct _packet_info_t *packet){
	struct _packet_info_t *item;

	item = (struct _packet_info_t *)list->first;

	switch(packet->ip_protocol){
		case IPPROTO_TCP:
			while(item){
				if(item->srcport == packet->dstport)
					if(item->dstport == packet->srcport)
						if(packet->tcp_seqnumber == item->tcp_acknumber){
							return item;
						}
						item = item->next;
			}
			break;
		case IPPROTO_UDP:
			if(packet->srcport != 53 && packet->dstport != 53)
				return 0;
			while(item){
				if(item->dns_id == packet->dns_id)
					if(item->dns_opcode == packet->dns_opcode)
						if(item->dns_rd == packet->dns_rd)
							if(item->dns_qr == 0)
								if(packet->dns_qr == 1)
									return item;
				item = item->next;
			}
			break;
		case IPPROTO_ICMP:
			if(packet->icmp_type == 8)
				return 0;
			while(item){
				if(item->tcp_seqnumber == packet->tcp_seqnumber)
					return item;
				item = item->next;
			}
			break;
		case IPPROTO_ICMPV6:
			if(packet->icmp6_type == 128)
				return 0;
			while(item){
				if(item->tcp_seqnumber == packet->tcp_seqnumber)
					return item;
				item = item->next;
			}
			break;
	}
	return 0;
}

//int deepPacketInspection(u_char *payload, uint32_t size) {
//    int result = 0;
//    
//    result = searchfunctions[0](payload, size);
//    
//    return result;
//}

void add_packet_to_flow(struct cache_item *item, struct _packet_info_t *packet){
    char message[LOG_MESSAGE_SIZE];
    uint64_t aptf_s = getCurrentTime(3);
    int hash,i;
    char* tmp = NULL;
    uint64_t current_time;
    struct _packet_info_t *pair;
    struct ndpi_detection_module_struct *ndpi_struct = NULL;
    unsigned int prot_id = 0;
    
	if(!item){
		item = cache_list_get(&cache_free_list);
		if(item){
			if(doAggregation)
				hash = hash_func(fwd_packet_flow_identificator(packet));
			else
				hash = hash_func(packet->srcport + packet->dstport);
			item->flow_state = 0;
			cache_list_add(&cache_hash_list[hash], item);
		}else{
			strcpy(message,"Flow Cache Full");			
			log_message(message,3);
			pcache_list_add(&pcache_free_list, packet);
			return;
		}
	}

	if(!doAggregation && automaticAggregation){
		
		if(list_size((struct list *)&cache_free_list) < FLOW_CACHE_SIZE/4){
			
			doAggregation = 1;

			strcpy(message,"[CACHE.C] STARTING AUTOMATIC AGGREGATION !!!!");			
			log_message(message,1);
                        tmp = getConfigElement(configData, "/configuration/aggregation/aggregationTrigger");
			AGGREGATION_TRIGGER = atol(tmp);
                        free(tmp);
                        tmp = NULL;
			AGGREGATION_TRIGGER *= 1000000;
                        tmp = getConfigElement(configData, "/configuration/aggregation/octetTotalCountForAggregation");
			AGGREGATION_CONDITION = atoi(tmp);
                        free(tmp);
                        tmp = NULL;


			for(i=0;i<HASH_SIZE;i++){		//memset(cache_hash, 0, 128);
				aggreg_cache_hash_list_first[i].first = 0;
				aggreg_cache_hash_list_second[i].first = 0;
				aggreg_cache_hash_list_third[i].first = 0;
				aggreg_cache_hash_list_fourth[i].first = 0;		
			}
		}
	}

	current_time = getCurrentTime(3);

	if(aggreg_timestamp == 0)
		aggreg_timestamp = current_time;
        
	switch(item->flow_state){
		case 0:				//uninitialized packet flow
			item->flow_state = 1;
			//tok nie je prave po exporte
			item->flow_exp = 0;
			item->exported_from = 0;
			item->originalFlowsPresent = 1;
			item->aggregateExpiredFlow = 0;

			item->originalFlowsPresent = 0;
			item->originalFlowsInitiated = 0;
			item->originalFlowsCompleted = 0;
   			item->distCntOfSrcIPAddr = 0;
			item->distCntOfDstIPAddr = 0;
 			item->distCntOfSrcIPv4Addr = 0;
 			item->distCntOfDstIPv4Addr = 0;
			item->distCntOfSrcIPv6Addr = 0;
			item->distCntOfDstIPv6Addr = 0;
			
			item->packet_cache_fwd.first = 0;
			item->packet_cache_bwd.first = 0;

			item->flow_key.ip_ver = packet->ip_version;
			item->flow_key.ip_protocol = packet->ip_protocol;
			item->flow_key.ip_src_addr = packet->ip_src_addr.s_addr;
			item->flow_key.ip_dst_addr = packet->ip_dst_addr.s_addr;
			item->flow_key.ip6_src_addr = packet->ip6_src_addr;
			item->flow_key.ip6_dst_addr = packet->ip6_dst_addr;
			item->flow_key.src_port = packet->srcport;
			item->flow_key.dst_port = packet->dstport;
			item->flow_key.dns_id = packet->dns_id;
#ifdef IPFIX_FLOWID

			item->flow_id = flow_identificator(&(item->flow_key));

#endif
#ifdef IPFIX_PACKETDELTACOUNT                        		
			item->packet_delta_count = 0;
#endif
#ifdef IPFIX_OCTETDELTACOUNT                        		                        			
			item->octet_delta_count = 0;
#endif
#ifdef IPFIX_FLOWLABELIPV6                        
            item->ip6_fl = packet->ip6_fl;
#endif                        
#ifdef IPFIX_PACKETTOTALCOUNT                        
			item->packet_total_count = 1;
#endif
#ifdef IPFIX_OCTETTOTALCOUNT                        
			item->octet_total_count = packet->ip_length;
#endif
#ifdef IPFIX_OCTETTOTALSUMOFSQUARES                        
			item->octet_total_sum_of_squares = (packet->ip_length * packet->ip_length);
#endif
#if defined(IPFIX_FLOWSTARTMILLISECONDS) || defined(IPFIX_FLOWSTARTMICROSECONDS) || defined(IPFIX_FLOWSTARTNANOSECONDS) || defined(IPFIX_FLOWSTARTDELTAMICROSECONDS)                        
			item->flow_start_nano_seconds = packet->timestamp;
#endif
			item->flow_end_nano_seconds = packet->timestamp;
                        item->flow_last_capture_nano_seconds = current_time;
#ifdef IPFIX_FLOWSTARTAFTEREXPORT                        
			item->flow_start_after_export = packet->timestamp;
#endif
			item->flow_last_exp_nano_seconds = current_time;
#ifdef IPFIX_ROUNDTRIPTIMENANOSECONDS                        
			item->rtt_avg = 0;
			item->rtt_avg_fwd = 0;
			item->rtt_avg_bwd = 0;
#endif
#ifdef IPFIX_PACKETPAIRSTOTALCOUNT                        
			item->rtt_cnt = 0;
			item->rtt_cnt_fwd = 0;
			item->rtt_cnt_bwd = 0;
#endif

			item->layer_3_hlength_fwd = packet->layer_3_hlength;
			item->layer_3_length_fwd = packet->layer_3_length;
			item->layer_4_hlength_fwd = packet->layer_4_hlength;
			item->layer_3_hlength_bwd = 0;
			item->layer_3_length_bwd = 0;
			item->layer_4_hlength_bwd = 0;
                        
			item->tcpFinTotalCount = 0;
                        
			if(packet->ip_protocol == IPPROTO_TCP){
				item->temp_8 = packet->tcp_flags;
				if(item->temp_8 & 1){
					item->tcpFinTotalCount++;
                                }
#ifdef IPFIX_TCPSYNTOTALCOUNT                                
				if(item->temp_8 & 2) 
					item->tcpSynTotalCount++;
#endif
#ifdef IPFIX_TCPRSTTOTALCOUNT                                
				if(item->temp_8 & 4)
					item->tcpRstTotalCount++;
#endif
#ifdef IPFIX_TCPPSHTOTALCOUNT                                
				if(item->temp_8 & 8)
					item->tcpPshTotalCount++;
#endif
#ifdef IPFIX_TCPACKTOTALCOUNT                                
				if(item->temp_8 & 16)
					item->tcpAckTotalCount++;
#endif
#ifdef IPFIX_TCPURGTOTALCOUNT                                
				if(item->temp_8 & 32)
					item->tcpUrgTotalCount++;
#endif                                
			}

//			item->layer_4_hlength_udp = packet->udp_hlength;        //v informacnom modeli sa nenachadza
//			item->layer_4_hlength_tcp = packet->layer_4_hlength;    //v informacnom modeli sa nenachadza
#if defined(IPFIX_IGMPTYPE) || defined(IPFIX_ICMPTYPEIPV4) || defined(IPFIX_ICMPTYPECODEIPV4)                       
			item->icmpTypeIPv4 = packet->icmp_type;
#endif
#if defined(IPFIX_ICMPCODEIPV4) || defined(IPFIX_ICMPTYPECODEIPV4)
			item->icmpCodeIPv4 = packet->icmp_code;
#endif
#if defined(IPFIX_ICMPTYPEIPV6) || defined(IPFIX_ICMPTYPECODEIPV6)
			item->icmpTypeIPv6 = packet->icmp6_type;
#endif
#if defined(IPFIX_ICMPCODEIPV6) || defined(IPFIX_ICMPTYPECODEIPV6)
			item->icmpCodeIPv6 = packet->icmp6_code;
#endif
#ifdef IPFIX_NEXTHEADERIPV6
			item->ipv6NextHeader = packet->ip6_nh;
#endif                        

#if defined(IPFIX_IPCLASSOFSERVICE) || defined(IPFIX_POSTIPCLASSOFSERVICE) || defined(IPFIX_IPDIFFSERVCODEPOINT) || defined (IPFIX_IPPRECEDENCE)                        
			item->ToS = packet->ip_tos;
#endif                        

//			item->icmpTypeIPv4 = packet->icmp_type;         //duplicate instruction

//			item->icmpCodeIPv4 = packet->icmp_code;         //duplicate instruction
#ifdef IPFIX_TCPURGENTPOINTER                        
			item->tcpUrgentPtr = packet->tcp_urgent_ptr;
#endif
#ifdef IPFIX_DROPPEDPACKETDELTACOUNT
			item->dropped_packet_delta = 0;
#endif
#ifdef IPFIX_DROPPEDOCTETDELTACOUNT
                        item->dropped_octet_delta = 0;
#endif
#if defined(IPFIX_IPPAYLOADLENGTH) || defined(IPFIX_DROPPEDPACKETDELTACOUNT) || defined(IPFIX_DROPPEDOCTETDELTACOUNT) 
                        item->ip_pl = packet->ip_plength;
#endif
#if defined(IPFIX_TCPSEQUENCENUMBER) || defined(IPFIX_DROPPEDPACKETDELTACOUNT) || defined(IPFIX_DROPPEDOCTETDELTACOUNT) 
                        item->tcpSeqNumber = packet->tcp_seqnumber;
#endif
#if defined(IPFIX_TCPACKNOWLEDGEMENTNUMBER) || defined(IPFIX_DROPPEDPACKETDELTACOUNT) || defined(IPFIX_DROPPEDOCTETDELTACOUNT)			
			item->tcpAckNumber = packet->tcp_acknumber;
#endif
#ifdef IPFIX_TCPWINDOWSIZE                        
			item->tcpWindowSize = packet->tcp_window;
#endif

//			item->ToS = packet->ip_tos;     //duplicate instruction
#if defined(IPFIX_IPHEADERLENGTH) || defined(IPFIX_IPV4IHL)                        
			item->ihl = packet->ip_hlength/4;
#endif
#if defined(IPFIX_TOTALLENGTHIPV4) || defined(IPFIX_IPTOTALLENGTH)                         
			item->layer_3_length_fst = packet->ip_length;			
#endif                        
#ifdef IPFIX_FRAGMENTIDENTIFICATION
			item->fragmentID = packet->ip_id;
#endif
#if defined(IPFIX_FRAGMENTOFFSET) || defined(IPFIX_FRAGMENTFLAGS)                        
			item->fragmentOff = packet->ip_offset;
#endif                        
#ifdef IPFIX_IPTTL                        
			item->ttl = packet->ip_ttl;
#endif                        
			pcache_list_add(&item->packet_cache_fwd, packet);                        

#ifdef IPFIX_COLLECTORTRANSPORTPORT
                        if (strlen(config_option.port_number) == 0) {
                            tmp = getConfigElement(configData, "/configuration/collector/port");
                            item->collector_port = atoi(tmp);
                            free(tmp);
                            tmp = NULL;
                        }
                        else
                            item->collector_port = atoi(config_option.port_number);
#endif                        
                        
#if defined(IPFIX_COLLECTORIPV6ADDRESS) || defined(IPFIX_COLLECTORIPV4ADDRESS)
                        if (strlen(config_option.host_IP) == 0) {
                            if (info->ai_family == AF_INET) {
                                tmp = getConfigElement(configData, "/configuration/collector/host");
                                inet_aton(tmp, &(item->collector_ipv4));
                                inet_pton(AF_INET6, "::", &(item->collector_ipv6));
                                free(tmp);
                                tmp = NULL;
                            }
                            else if (info->ai_family == AF_INET6) {
                                tmp = getConfigElement(configData, "/configuration/collector/host");
                                inet_pton(AF_INET6, tmp, &(item->collector_ipv6));
                                inet_aton("0.0.0.0", &(item->collector_ipv4));
                                free(tmp);
                                tmp = NULL;
                            }
                        }
                        else {
                            if (info->ai_family == AF_INET) {
                                inet_aton(config_option.host_IP, &(item->collector_ipv4));
                                inet_pton(AF_INET6, "::", &(item->collector_ipv6));
                            }
                            else if (info->ai_family == AF_INET6) {
                                inet_pton(AF_INET6, config_option.host_IP, &(item->collector_ipv6));
                                inet_aton("0.0.0.0", &(item->collector_ipv4));
                            }
                        }
#endif                        
                        
#ifdef IPFIX_EXPORTINTERFACE
                        tmp = getConfigElement(configData, "/configuration/collector/host");
                        if ((strcmp("127.0.0.1", tmp) == 0) || (strcmp("127.0.0.1", config_option.host_IP) == 0)) {
                            item->export_i = if_nametoindex("lo");
                            free(tmp);
                            tmp = NULL;
                        }
			else if (strlen(config_option.interface_type) == 0) {
                            free(tmp);
                            tmp = getConfigElement(configData,"/configuration/interfaces/interface/name");
                            item->export_i = if_nametoindex(tmp);
                            free(tmp);
                            tmp = NULL;
                        }
			else {
			    item->export_i = if_nametoindex(config_option.interface_type);
                            free(tmp);
                            tmp = NULL;
                        }
#endif                        
                   
#ifdef IPFIX_EXPORTPROTOCOLVERSION
                        tmp = getConfigElement(configData, "/configuration/collector/version");
                        item->export_protVer = atoi(tmp);
                        free(tmp);
                        tmp = NULL;
#endif                        
                        
#ifdef IPFIX_EXPORTTRANSPORTPROTOCOL
                        item->export_protocol = proto->p_proto;
#endif                        
                       
#ifdef IPFIX_EXPORTERIPV4ADDRESS
                        item->exporter_ipv4 = exp_ip;
#endif                        
                         
#ifdef IPFIX_EXPORTERIPV6ADDRESS
                        item->exporter_ipv6 = exp_ip6;
#endif                        
                        
#ifdef IPFIX_EXPORTERTRANSPORTPORT                     
                        item->exporter_port = exp_port;
#endif
						
#ifdef IPFIX_FLOWKEYINDICATOR
                        memset(&(item->flowKey_in), 0, sizeof(item->flowKey_in));
                        item->flowKey_in = 1ULL << 3;
                        item->flowKey_in = (item->flowKey_in | 1ULL << 6);                       
	                item->flowKey_in = (item->flowKey_in | 1ULL << 11);
			if (item->flow_key.ip_ver == 4) {
				item->flowKey_in = (item->flowKey_in | 1ULL << 7);
	                        item->flowKey_in = (item->flowKey_in | 1ULL << 10); 
			}
			else if (item->flow_key.ip_ver == 6) {                 
				item->flowKey_in = (item->flowKey_in | 1ULL << 26);
	                        item->flowKey_in = (item->flowKey_in | 1ULL << 27);
			}
                        item->flowKey_in = (item->flowKey_in | 1ULL << 59);
#endif
                        
#if defined(IPFIX_LASTPACKETID) && defined(IPFIX_FIRSTPACKETID)                        
			ip_packet_identificator_MD5(item->firstPacketID, packet->packet_ident);
			memcpy(item->lastPacketID, item->firstPacketID, 16);
#endif                  

			if(packet->is_sampled)
				item->is_sampled = packet->is_sampled;
                        
#ifdef IPFIX_SOURCEMACADDRESS
                        memcpy(item->source_mac, packet->ether_smac, sizeof(packet->ether_smac));
#endif
#ifdef IPFIX_DESTINATIONMACADDRESS            
                        memcpy(item->destination_mac, packet->ether_dmac, sizeof(packet->ether_dmac));
#endif         
                        
#ifdef IPFIX_APPLICATIONID
//                        item->app_inf = deepPacketInspection(packet->payload, packet->layer_7_length);
//                        free(packet->payload);
//                        packet->payload = NULL;
//                        printf("Flow %llu (1st): %d\n", item->flow_id, packet->dpi_protocol);
                        memset(item->appId, 0, 4);
                        item->appId[0] = 6;
//                        item->appId[3] = packet->dpi_protocol;
                        memcpy(item->appId + 1, &(packet->dpi_protocol), 3);
//                        printf("%d | %d %d %d %d\n", packet->dpi_protocol, item->appId[0], item->appId[1], item->appId[2], item->appId[3]);
#endif     
                        
#ifdef IPFIX_APPLICATIONNAME
                        if (DPI_CACHE_SIZE > 0) {
//                            ndpi_struct = setup_ndpi();
                            memcpy(&prot_id, item->appId + 1, 3);
                            memset(item->appName, '\0', sizeof(item->appName));
                            strcpy(item->appName, ndpi_get_proto_name(pcts[0].ndpi_struct, prot_id));
//                            terminate_ndpi(ndpi_struct);
                        } else {
                            memset(item->appName, '\0', sizeof(item->appName));
                            strcpy(item->appName, "Unknown");
                        }
#endif
   
			break;
                        
//******************************************************************************************************************
                        
		case 1:				//initialized packet flow
#ifdef IPFIX_PACKETTOTALCOUNT                    
			item->packet_total_count++;
#endif
#ifdef IPFIX_OCTETTOTALCOUNT                        
			item->octet_total_count += packet->ip_length;
#endif
#ifdef IPFIX_OCTETTOTALSUMOFSQUARES                        
			item->octet_total_sum_of_squares += (packet->ip_length * packet->ip_length);
#endif
			item->flow_end_nano_seconds = packet->timestamp;
                        item->flow_last_capture_nano_seconds = current_time;
                        
#ifdef IPFIX_DROPPEDPACKETDELTACOUNT
			if ((packet->ip_protocol == IPPROTO_TCP) && (item->tcpSeqNumber == packet->tcp_seqnumber) && (item->tcpAckNumber == packet->tcp_acknumber) && !(strncmp("192.168.0.0", inet_ntoa(packet->ip_src_addr), 8)) && (item->ip_pl == packet->ip_plength) && (item->temp_8 == packet->tcp_flags)) {
                            item->dropped_packet_delta++;
			}
#endif
#ifdef IPFIX_DROPPEDOCTETDELTACOUNT
                        if ((packet->ip_protocol == IPPROTO_TCP) && (item->tcpSeqNumber == packet->tcp_seqnumber) && (item->tcpAckNumber == packet->tcp_acknumber) && !(strncmp("192.168.0.0", inet_ntoa(packet->ip_src_addr), 8)) && (item->ip_pl == packet->ip_plength) && (item->temp_8 == packet->tcp_flags)) {
                            item->dropped_octet_delta += packet->ip_length;
			}
                        
#endif
                        
			if(packet->ip_protocol == IPPROTO_TCP){
				item->temp_8 = packet->tcp_flags;
				if(item->temp_8 & 1) {
					item->tcpFinTotalCount++;
                                }
#ifdef IPFIX_TCPSYNTOTALCOUNT                                
				if(item->temp_8 & 2)
					item->tcpSynTotalCount++;
#endif
#ifdef IPFIX_TCPRSTTOTALCOUNT                                
				if(item->temp_8 & 4)
					item->tcpRstTotalCount++;
#endif
#ifdef IPFIX_TCPPSHTOTALCOUNT                                
				if(item->temp_8 & 8)
					item->tcpPshTotalCount++;
#endif
#ifdef IPFIX_TCPACKTOTALCOUNT                                
				if(item->temp_8 & 16)
					item->tcpAckTotalCount++;
#endif
#ifdef IPFIX_TCPURGTOTALCOUNT                                
				if(item->temp_8 & 32)
					item->tcpUrgTotalCount++;
#endif                                
			}

#if defined(IPFIX_IPPAYLOADLENGTH) || defined(IPFIX_DROPPEDPACKETDELTACOUNT) || defined(IPFIX_DROPPEDOCTETDELTACOUNT)                        
                        item->ip_pl = packet->ip_plength;
#endif                        
#if defined(IPFIX_TCPSEQUENCENUMBER) || defined(IPFIX_DROPPEDPACKETDELTACOUNT) || defined(IPFIX_DROPPEDOCTETDELTACOUNT)
                        item->tcpSeqNumber = packet->tcp_seqnumber;
#endif
#if defined(IPFIX_TCPACKNOWLEDGEMENTNUMBER)  || defined(IPFIX_DROPPEDPACKETDELTACOUNT) || defined(IPFIX_DROPPEDOCTETDELTACOUNT)			
			item->tcpAckNumber = packet->tcp_acknumber;
#endif                        
                        
			if(packet->ip_protocol == IPPROTO_UDP && (packet->srcport != 53 || packet->dstport != 53)){
				item->layer_3_hlength_fwd += packet->layer_3_hlength;
				item->layer_3_length_fwd += packet->layer_3_length;
				item->layer_4_hlength_fwd += packet->layer_4_hlength;

				pcache_list_add(&pcache_free_list, packet);
			}else{
				if(packet->direction == 1){
					item->layer_3_hlength_fwd += packet->layer_3_hlength;
					item->layer_3_length_fwd += packet->layer_3_length;
					item->layer_4_hlength_fwd += packet->layer_4_hlength;

					pair = find_packet_pair(&item->packet_cache_bwd, packet);
					if(pair){
#if defined(IPFIX_PACKETPAIRSTOTALCOUNT) && defined(IPFIX_ROUNDTRIPTIMENANOSECONDS)                                            
						item->rtt_avg_fwd = ((item->rtt_avg_fwd * item->rtt_cnt_fwd) 
							+ (packet->timestamp - pair->timestamp)) / (item->rtt_cnt_fwd + 1);
						item->rtt_cnt_fwd++;
#endif
//						pcache_list_add(&pcache_free_list, pcache_list_remove(&item->packet_cache_bwd, pair));
						while(item->packet_cache_bwd.first)
							pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache_bwd));

					}
					pcache_list_add(&item->packet_cache_fwd, packet);
				}else{
					item->layer_3_hlength_bwd += packet->layer_3_hlength;
					item->layer_3_length_bwd += packet->layer_3_length;
					item->layer_4_hlength_bwd += packet->layer_4_hlength;

					pair = find_packet_pair(&item->packet_cache_fwd, packet);
					if(pair){
#if defined(IPFIX_LASTPACKETID) && defined(IPFIX_FIRSTPACKETID)                                            
						item->rtt_avg_bwd = ((item->rtt_avg_bwd * item->rtt_cnt_bwd) 
							+ (packet->timestamp - pair->timestamp)) / (item->rtt_cnt_bwd + 1);
						item->rtt_cnt_bwd++;
#endif
//						pcache_list_add(&pcache_free_list, pcache_list_remove(&item->packet_cache_fwd, pair));
						while(item->packet_cache_fwd.first)
							pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache_fwd));
					}
					pcache_list_add(&item->packet_cache_bwd, packet);
				}
			}

#if defined(IPFIX_LASTPACKETID) && defined(IPFIX_FIRSTPACKETID)
			ip_packet_identificator_MD5(item->lastPacketID, packet->packet_ident);
#endif                        
			if(item->flow_exp == 1) {
#ifdef IPFIX_FLOWSTARTAFTEREXPORT                            
				item->flow_start_after_export = packet->timestamp;
#endif
#if defined(IPFIX_LASTPACKETID) && defined(IPFIX_FIRSTPACKETID)                                
				memcpy(item->firstPacketID, item->lastPacketID, 16);
#endif                                
				item->flow_exp = 0;
			}

			if(packet->is_sampled)
				item->is_sampled = packet->is_sampled;

                        memcpy(&prot_id, item->appId + 1, 3);
                        
#ifdef IPFIX_APPLICATIONID
//                        printf("Flow %llu (nth): %d\n", item->flow_id, packet->dpi_protocol);
//                        item->appId[3] = packet->dpi_protocol;
                        if (packet->dpi_protocol != 0)
                            memcpy(item->appId + 1, &(packet->dpi_protocol), 3);
#endif      
                        
#ifdef IPFIX_APPLICATIONNAME
                        if (DPI_CACHE_SIZE > 0) {
//                            ndpi_struct = setup_ndpi();
                            memset(item->appName, '\0', sizeof(item->appName));
                            strcpy(item->appName, ndpi_get_proto_name(pcts[0].ndpi_struct, prot_id));
//                            terminate_ndpi(ndpi_struct);
                        } else {
                            memset(item->appName, '\0', sizeof(item->appName));
                            strcpy(item->appName, "Unknown");
                        }
#endif                        

			break;
		default:			//expired packet flow
			strcpy(message,"Addpacket function failed");			
			log_message(message,3);
			pcache_list_add(&pcache_free_list, packet);
			break;
	}
        
//        sprintf(message,"[add_packet_to_flow] %llu nSec (flow ID: %llu)", getCurrentTime(3)-aptf_s, item->flow_id);
//        log_message(message,6);
}

int flowCacheInit(void){
        char message[LOG_MESSAGE_SIZE];
	int i;
	struct cache_item *ci;
	struct _packet_info_t *pi;
	struct flow_in_buff 	*fib;
        
	FLOW_CACHE_SIZE = atoi(getConfigElement(configData,"/configuration/flows/flowCacheSize"));
	PACKET_CACHE_SIZE = atoi(getConfigElement(configData, "/configuration/flows/packetCacheSize"));
	FLOW_IN_BUFF_SIZE = FLOW_CACHE_SIZE * 2;
        if (!strcmp("true",getConfigElement(configData,"/configuration/dpi/doDpi"))) {
            pthread_mutex_init(&dpi_cache_mutex, NULL);
            DPI_CACHE_SIZE = FLOW_CACHE_SIZE;
        }

	if((!strcmp("true",getConfigElement(configData,"/configuration/aggregation/doAggregation")))
			||
		(!strcmp("true",getConfigElement(configData,"/configuration/aggregation/automaticAggregation")))){

		fourth_aggreg_value = atoi(getConfigElement(configData, "/configuration/aggregation/first"));
		third_aggreg_value = atoi(getConfigElement(configData, "/configuration/aggregation/second"));
		second_aggreg_value = atoi(getConfigElement(configData, "/configuration/aggregation/third"));
		first_aggreg_value = atoi(getConfigElement(configData, "/configuration/aggregation/fourth"));
		
		/*
		printf("FIRST VALUE %d\n",first_aggreg_value);
		printf("SECOND VALUE %d\n",second_aggreg_value);
		printf("THIRD VALUE %d\n",third_aggreg_value);
		printf("FORTH VALUE %d\n",fourth_aggreg_value);
		printf("FIFTH VALUE %d\n",fifth_aggreg_value);
		*/
	}

		//aggregation
	if((!strcmp("true",getConfigElement(configData,"/configuration/aggregation/doAggregation")))
			||
	   (!strcmp("true",config_option.aggregation))){
	   	
		doAggregation = 1;
		strcpy(message,"[cache] Aggregation: true");		
		log_message(message,6);	
	}
	else{
		doAggregation = 0;
		strcpy(message,"[cache] Aggregation: false");	
		log_message(message,6);
	}

	if(	(!strcmp("false",getConfigElement(configData,"/configuration/aggregation/doAggregation")))
			&&
		(!strcmp("true",getConfigElement(configData,"/configuration/aggregation/automaticAggregation")))){
			automaticAggregation = 1;
			strcpy(message,"[cache] Automatic Aggregation: true");		
			log_message(message,6);	
	}
	else{
		strcpy(message,"[cache] Automatic Aggregation: false");	
		log_message(message,6);	
	}
	// \\aggregation

	sprintf(message,"[cache] Allocated %i bytes of memory for flow cache", sizeof(struct cache_item)*FLOW_CACHE_SIZE);
	log_message(message,6);
	cache_base = (struct cache_item *)malloc(sizeof(struct cache_item) * FLOW_CACHE_SIZE);
	if(cache_base == 0){
		strcpy(message,"Allocating memory for flow cache FAILED");		
		log_message(message,3);
		return -1;
	}

	ci = (struct cache_item *)cache_base;
	cache_free_list.first = (struct list_item *)ci;
	cache_expired_list.first = 0;
	cache_remove_list.first = 0;

	for(i=1;i<FLOW_CACHE_SIZE;i++){
		memset(ci, 0, sizeof(struct cache_item));
		ci->next = ci + 1;
		ci++;
	}
	memset(ci, 0, sizeof(struct cache_item));


	for(i=0;i<HASH_SIZE;i++)
		cache_hash_list[i].first = 0;	//

	if(doAggregation){

		AGGREGATION_TRIGGER = atol(getConfigElement(configData, "/configuration/aggregation/aggregationTrigger"));
		AGGREGATION_TRIGGER *= 1000000;

		AGGREGATION_CONDITION = atoi(getConfigElement(configData, "/configuration/aggregation/octetTotalCountForAggregation"));


		for(i=0;i<HASH_SIZE;i++){
			aggreg_cache_hash_list_first[i].first = 0;
			aggreg_cache_hash_list_second[i].first = 0;
			aggreg_cache_hash_list_third[i].first = 0;
			aggreg_cache_hash_list_fourth[i].first = 0;		
		}
	}

	//pcache init
	sprintf(message,"[cache] Allocated %i bytes of memory for packet cache",sizeof(struct _packet_info_t) * PACKET_CACHE_SIZE);	
	log_message(message,6);
	pcache_base = (void *)malloc(sizeof(struct _packet_info_t) * PACKET_CACHE_SIZE);
	if(pcache_base == 0){
		strcpy(message,"Allocating memory for packet cache FAILED");		
		log_message(message,3);
		return -1;
	}

	pi = (struct _packet_info_t *)pcache_base;

	pcache_free_list.first = (struct list_item *)pi;
	for(i=1;i<PACKET_CACHE_SIZE;i++){
		memset(pi, 0, sizeof(struct _packet_info_t));
		pi->next = pi + 1;
		pi++;
	}
	memset(pi, 0, sizeof(struct _packet_info_t));

	pcache_input_queue.last = 0;

        //DPI cache init
        if (DPI_CACHE_SIZE > 0) {
            sprintf(message,"[cache] Allocated %i bytes of memory for DPI cache", sizeof(struct dpi_item) * DPI_CACHE_SIZE);	
            log_message(message,6);
            dpicache_base = (struct dpi_item *)malloc(sizeof(struct dpi_item) * DPI_CACHE_SIZE);
            if (!dpicache_base) {
                strcpy(message, "Allocating memory for DPI cache FAILED");		
		log_message(message, 3);
		return -1;
            }
            dpicache_free_list.first = (struct list_item *)dpicache_base;
            for(i = 1; i < DPI_CACHE_SIZE; i++){
		memset(dpicache_base, 0, sizeof(struct dpi_item));
		dpicache_base->next = dpicache_base + 1;
		dpicache_base++;
            }
            memset(dpicache_base, 0, sizeof(struct dpi_item));
            for(i = 0; i < HASH_SIZE; i++)
		dpicache_hash_list[i].first = 0;
        }
        
	cache_status();

	passive_timeout =  atol(getConfigElement(configData, "/configuration/flows/passiveTimeout"));
	active_timeout =  atol(getConfigElement(configData, "/configuration/flows/activeTimeout"));
	if(!strcmp("true", getConfigElement(configData, "/configuration/flows/biflows"))){
		biflow_support = 1;
		strcpy(message,"[cache] Biflow support: true");		
		log_message(message,6);
	}else{
		biflow_support = 0;
		strcpy(message,"[cache] Biflow support: false");	
		log_message(message,6);
	}
	packet_timeout = atol("1000");

	strcpy(message,"[cache] Init ok");
	log_message(message,6);
	return 0;
}

void flowCachePacketProcessing(void){
	struct cache_item *item;
	struct _packet_info_t *packet_info;
        
#if defined(IPFIX_COLLECTORIPV6ADDRESS) || defined(IPFIX_COLLECTORIPV4ADDRESS)
        memset(&hint, 0, sizeof(hint));
        hint.ai_family = AF_UNSPEC;
        
        if (strlen(config_option.host_IP) == 0)
            getaddrinfo(getConfigElement(configData, "/configuration/collector/host"), NULL, &hint, &info);
        else
            getaddrinfo(config_option.host_IP, NULL, &hint, &info);
#endif       
        
#ifdef IPFIX_EXPORTTRANSPORTPROTOCOL
        if (strlen(config_option.protocol_type) == 0)
            proto = getprotobyname((getConfigElement(configData, "/configuration/collector/protocol")));
        else
            proto = getprotobyname(config_option.protocol_type);
#endif            
        //int packets=0;
	while(capture_interrupted < 2){
		pthread_mutex_lock(&pcache_input_mutex);
		do{
			packet_info = pqueue_get(&pcache_input_queue);
			if (!packet_info && capture_interrupted) {
				capture_interrupted = 2;
				break;
			}
			else if(!packet_info && !capture_interrupted)
				pthread_cond_wait(&pcache_input_wait, &pcache_input_mutex);
		}while(!packet_info && (!capture_interrupted || capture_interrupted==1));
		pthread_mutex_unlock(&pcache_input_mutex);

		if(capture_interrupted) {
			//printf("Packets processed: %i\n", packets);
			//printf("Packet_processing_ci -- %i\n", capture_interrupted);
			break;
		}
		if(!packet_info)
			continue;
		//packets++;
		pthread_mutex_lock(&flow_cache_mutex);
		item = cache_get_item(packet_info);
		add_packet_to_flow(item, packet_info);
		pthread_mutex_unlock(&flow_cache_mutex);
	}
}

void flowAggregationProcess(void){

	struct timespec tim;
   		
   	tim.tv_sec = AGGREGATION_TRIGGER / 1000000000;
   	tim.tv_nsec = AGGREGATION_TRIGGER % 1000000000;

	while(capture_interrupted < 3){
		 	
		pthread_mutex_lock(&flow_cache_mutex);
		flow_cache_rework();
        pthread_mutex_unlock(&flow_cache_mutex);
        nanosleep(&tim,NULL);
	}
}

void pcache_list_expire(struct list *pcache, uint64_t current_time){
	struct _packet_info_t *prew, *curr;

	prew = 0;
	curr = (struct _packet_info_t *)pcache->first;
	while(curr){
		if((current_time - curr->timestamp) > packet_timeout){
			if(prew == 0){
				pcache->first = (struct list_item *)curr->next;
				pcache_list_add(&pcache_free_list, curr);
				curr = (struct _packet_info_t *)pcache->first;
			}else{
				prew->next = curr->next;
				pcache_list_add(&pcache_free_list, curr);
				curr = (struct _packet_info_t *)prew->next;
			}
		}else{
			prew = curr;
			curr = curr->next;
		}
	}
}

void flowCacheTimeExpireInit(void){
        char message[LOG_MESSAGE_SIZE];
	passive_timeout =  atol(getConfigElement(configData, "/configuration/flows/passiveTimeout"));
	active_timeout =  atol(getConfigElement(configData, "/configuration/flows/activeTimeout"));

	if(!strcmp("true", getConfigElement(configData, "/configuration/flows/biflows"))){
		biflow_support = 1;
		strcpy(message,"[Flow Expiration] biflow support - true");		
		log_message(message,6);
	}else{
		biflow_support = 0;
		strcpy(message,"[Flow Expiration] biflow support - false");		
		log_message(message,6);
	}
	packet_timeout = atol("1000");
	int i;
	struct cache_item *item;
//	struct _packet_info_t *pitem;

	passive_timeout *= 1000000;
	active_timeout *= 1000000;
	packet_timeout *= 1000000;

	while(capture_interrupted < 3){
		pthread_mutex_lock(&flow_cache_mutex);
		int j = 0;		
		for(i=0;i<128;i++) {
			item = (struct cache_item *)cache_hash_list[i].first;
			if (list_size((struct list *)&cache_free_list) == FLOW_CACHE_SIZE && capture_interrupted == 2) {
				capture_interrupted = 3;
				break;
			}
			flowCacheTimeExpire(item,i,0);
		}

		if(doAggregation){
			for(i=0;i<128;i++){
				item = (struct cache_item *)aggreg_cache_hash_list_first[i].first;
				flowCacheTimeExpire(item,i,1);
				
			}

			for(i=0;i<128;i++){
				item = (struct cache_item *)aggreg_cache_hash_list_second[i].first;
				flowCacheTimeExpire(item,i,2);
			}
			sleep(1);

			for(i=0;i<128;i++){
				item = (struct cache_item *)aggreg_cache_hash_list_third[i].first;
				flowCacheTimeExpire(item,i,3);
			}

			for(i=0;i<128;i++){
				item = (struct cache_item *)aggreg_cache_hash_list_fourth[i].first;
				flowCacheTimeExpire(item,i,4);
				
			}
		}
	pthread_mutex_unlock(&flow_cache_mutex);
			
	if(doAggregation)
		sleep(2);
	else
		sleep(1);
	}
}

void remove_dpi_cache_item(struct cache_item *item, int hash) {
    pthread_mutex_lock(&dpi_cache_mutex);
    struct dpi_item *dpi = dpicache_hash_list[hash].first;
    while (dpi) {
//        printf("DPI cache free: %d\nDPI flowid: %llu | %llu\n", list_size((struct list *)&dpicache_free_list), dpi->flowid, item->flow_id);
        if (dpi->flowid == item->flow_id) {
            cache_list_remove(&dpicache_hash_list[hash], dpi);
            memset(dpi, 0, sizeof(struct dpi_item));
            cache_list_add(&dpicache_free_list, dpi);
//            printf("DPI cache free: %d\n", list_size((struct list *)&dpicache_free_list));
            break;
        }
        dpi = dpi->next;
    }
    pthread_mutex_unlock(&dpi_cache_mutex);
}

void flowCacheTimeExpire(struct cache_item *item, int i, int mark){
	
	int64_t current_time;
	struct cache_item *copy;
	
	current_time = getCurrentTime(3);
	while(item){
            if (capture_interrupted > 1) {
                item->flow_state = 2;
                item->expiration_reason = 4;
                item->flow_exp = 1;
            }
            else if (item->tcpFinTotalCount > 0) {
                item->flow_state = 2;
                item->expiration_reason = 3;
                item->flow_exp = 1;
            }
            else if((current_time - item->flow_last_capture_nano_seconds) > passive_timeout){
                item->flow_state = 2;
                item->expiration_reason = 1;
            }
            else if((current_time - item->flow_last_exp_nano_seconds) > active_timeout){
                item->flow_state = 2;
                item->expiration_reason = 2;
                item->flow_exp = 1;					
            }

            pcache_list_expire(&item->packet_cache_fwd, current_time);

            pcache_list_expire(&item->packet_cache_bwd, current_time);

            if(item->flow_state == 2){
                switch(item->expiration_reason){
                    case 1:
                        if (DPI_CACHE_SIZE > 0)
                            remove_dpi_cache_item(item, i);
                        if(mark == 0)
                            item = cache_list_remove(&cache_hash_list[i], item);
                        else if(mark == 1)
                            item = cache_list_remove(&aggreg_cache_hash_list_first[i],item);
                        else if(mark == 2)
                            item = cache_list_remove(&aggreg_cache_hash_list_second[i],item);
                        else if(mark == 3)
                            item = cache_list_remove(&aggreg_cache_hash_list_third[i],item);
                        else if(mark == 4)
                            item = cache_list_remove(&aggreg_cache_hash_list_fourth[i],item);
                        //TODO treba vycistit pcache..	
                        while(item->packet_cache_fwd.first)
                            pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache_fwd));
                        while(item->packet_cache_bwd.first)
                            pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache_bwd));
                        /*
                        while(item->packet_cache.first)
                        pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache));
                        */
                        //TODO

                        cache_list_add(&cache_expired_list, item);

                        if(mark == 0){
                            item = (struct cache_item *)cache_hash_list[i].first;
                        }
                        else if(mark == 1){
                            item = (struct cache_item *)aggreg_cache_hash_list_first[i].first;
                        }
                        else if(mark == 2)
                            item = (struct cache_item *)aggreg_cache_hash_list_second[i].first;
                        else if(mark == 3)
                            item = (struct cache_item *)aggreg_cache_hash_list_third[i].first;
                        else if(mark == 4)
                            item = (struct cache_item *)aggreg_cache_hash_list_fourth[i].first;
                        continue;
                        break;

                    case 2:	
                        copy = cache_list_get(&cache_free_list);
                        ///////// CONSIDER item->flow_last_exp_nano_seconds = current_time; dat pred alebo po if(!copy) break;
                        if(!copy)
                                break;
                        *copy = *item;
                        //copy->flow_state = 2;
                        copy->packet_cache_fwd.first = 0;
                        copy->packet_cache_bwd.first = 0;
                        cache_list_add(&cache_expired_list, copy);
						//printf("%llu - %llu (%llu)\n", copy->flow_id, copy->packet_total_count, copy->packet_delta_count);

                        item->flow_state = 1;
                        item->packet_delta_count = item->packet_total_count;
                        item->octet_delta_count = item->octet_total_count;
                        item->flow_last_exp_nano_seconds = current_time;
                        item->dropped_packet_delta = 0;
                        item->dropped_octet_delta = 0;

                        break;

                    case 3:
                        if (DPI_CACHE_SIZE > 0)
                            remove_dpi_cache_item(item, i);
                        if(mark == 0){
                            item->aggregateExpiredFlow = 1;
                            item = move_flows_to_next_buff(item,i,1);
                            if(item && !(item->aggregateExpiredFlow))
                                item = cache_list_remove(&cache_hash_list[i], item);
                        }
                        else if(mark == 1)
                            item = cache_list_remove(&aggreg_cache_hash_list_first[i],item);
                        else if(mark == 2)
                            item = cache_list_remove(&aggreg_cache_hash_list_second[i],item);
                        else if(mark == 3)
                            item = cache_list_remove(&aggreg_cache_hash_list_third[i],item);
                        else if(mark == 4)
                            item = cache_list_remove(&aggreg_cache_hash_list_fourth[i],item);
                        if(item){
                            while(item->packet_cache_fwd.first)
                                pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache_fwd));
                            while(item->packet_cache_bwd.first)
                                pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache_bwd));
                        }

                        if(item && !(item->aggregateExpiredFlow))   	
                            cache_list_add(&cache_expired_list, item);

                        if(item && mark == 0 && !(item->aggregateExpiredFlow))
                            item = (struct cache_item *)cache_hash_list[i].first;
                        else if(mark == 1)
                            item = (struct cache_item *)aggreg_cache_hash_list_first[i].first;
                        else if(mark == 2)
                            item = (struct cache_item *)aggreg_cache_hash_list_second[i].first;
                        else if(mark == 3)
                            item = (struct cache_item *)aggreg_cache_hash_list_third[i].first;
                        else if(mark == 4)
                            item = (struct cache_item *)aggreg_cache_hash_list_fourth[i].first;

                        continue;
                        break;

                    case 4:
                        if (DPI_CACHE_SIZE > 0)
                            remove_dpi_cache_item(item, i);
                        if(mark == 0)
                            item = cache_list_remove(&cache_hash_list[i], item);
                        else if(mark == 1)
                            item = cache_list_remove(&aggreg_cache_hash_list_first[i],item);
                        else if(mark == 2)
                            item = cache_list_remove(&aggreg_cache_hash_list_second[i],item);
                        else if(mark == 3)
                            item = cache_list_remove(&aggreg_cache_hash_list_third[i],item);
                        else if(mark == 4)
                            item = cache_list_remove(&aggreg_cache_hash_list_fourth[i],item);
                        //TODO treba vycistit pcache..	
                        while(item->packet_cache_fwd.first)
                            pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache_fwd));
                        while(item->packet_cache_bwd.first)
                            pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache_bwd));
                        /*
                        while(item->packet_cache.first)
                        pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache));
                        */
                        //TODO

                        cache_list_add(&cache_expired_list, item);
                        if(mark == 0){
                            item = (struct cache_item *)cache_hash_list[i].first;
                        }
                        else if(mark == 1){
                            item = (struct cache_item *)aggreg_cache_hash_list_first[i].first;
                        }
                        else if(mark == 2)
                            item = (struct cache_item *)aggreg_cache_hash_list_second[i].first;
                        else if(mark == 3)
                            item = (struct cache_item *)aggreg_cache_hash_list_third[i].first;
                        else if(mark == 4)
                            item = (struct cache_item *)aggreg_cache_hash_list_fourth[i].first;
                        continue;
                        break;
                }
            }

            item = item->next;
        }
}

void flowCacheExport(void){
        char message[LOG_MESSAGE_SIZE];
	struct cache_item *item;
	unsigned long long avg_spd = 1;
	unsigned char *ip;
	//char ip_text[16];

	initExport();
	while(capture_interrupted < 4){
		pthread_mutex_lock(&flow_cache_mutex);
		item = (struct cache_item *)cache_expired_list.first;
		if (!item && capture_interrupted == 3) {
			capture_interrupted = 4;
			break;
		}
		while(item){
			exportFlow(item);

			printf("==================================================================\n");
			sprintf(message,"Flow_ID value: %llu", item->flow_id);
			log_message(message,6);

				
#ifdef IPFIX_PACKETTOTALCOUNT                                
				sprintf(message,"Packet total count -> %llu ",item->packet_total_count);
				log_message(message,6);
#endif
				sprintf(message,"Packet delta count -> %llu ",item->packet_delta_count);
				log_message(message,6);

   //          int i = 0;
			// memcpy(&i, &(item->appId[1]), 3);
			// sprintf(message,"Application ID -> %d | %d", item->appId[0], i);
			// log_message(message, 6);
            sprintf(message,"Application protocol -> %s", item->appName);
//          sprintf(message, "Application protocol -> %d", prot_id);
            log_message(message,6);
                        
			sprintf(message,"Expiration reason value -> %i ",item->expiration_reason);
			log_message(message,6);

			sprintf(message,"Source MAC -> %x:%x:%x:%x:%x:%x", item->source_mac[0], item->source_mac[1], item->source_mac[2], item->source_mac[3], item->source_mac[4], item->source_mac[5]);
			log_message(message,6);

			sprintf(message,"Destination MAC -> %x:%x:%x:%x:%x:%x", item->destination_mac[0], item->destination_mac[1], item->destination_mac[2], item->destination_mac[3], item->destination_mac[4], item->destination_mac[5]);
			log_message(message,6);                        
                        
			//sprintf(message,"Octet total count -> %i ",item->octet_total_count);
			//log_message(message,6);			
                     
                        
//                        char add6[125];
//                        
//                        sprintf(message,"ExporterIPv4Address -> %s", inet_ntoa(item->exporter_ipv4));
//                        log_message(message,6);
//                        inet_ntop(AF_INET6, &(item->exporter_ipv6), add6, 125);
//                        sprintf(message,"ExporterIPv6Address -> %s", add6);
//                        log_message(message,6);
//                        sprintf(message,"ExporterTransportPort -> %i", item->exporter_port);
//                        log_message(message,6);
//                        sprintf(message,"CollectorIPv4Address -> %s", inet_ntoa(item->collector_ipv4));
//                        log_message(message,6);
//                        inet_ntop(AF_INET6, &(item->collector_ipv6), add6, 125);
//			sprintf(message,"CollectorIPv6Address -> %s", add6);
//                        log_message(message,6);
//                        sprintf(message,"ExportInterface -> %i", item->export_i);
//                        log_message(message,6);
//                        sprintf(message,"CollectorProtocolVersion: %i", item->export_protVer);
//                        log_message(message,6);
//                        sprintf(message,"CollectorTransportProtocol -> %i", item->export_protocol);
//                        log_message(message,6);
//                        sprintf(message,"CollectorTransportPort -> %i",item->collector_port);
//                        log_message(message,6);
//                        sprintf(message,"FlowKeyIndicator -> %lli", item->flowKey_in);
//                        log_message(message,6);
                        
//			sprintf(message,"Dropped Packet Delta -> %i", item->dropped_packet_delta);
//                        log_message(message,6);
//			sprintf(message,"Dropped Octet Delta -> %i B", item->dropped_octet_delta);
//                        log_message(message,6);
                        
			//printf("+%i+",item->expiration_reason);
			if(item->flow_key.ip_protocol == 1)
			{
				strcpy(message,"Type of used protocol -> [ICM]");				
				log_message(message,6);
			}			
			else if(item->flow_key.ip_protocol == 6)
			{			
				strcpy(message,"Type of used protocol -> [TCP]");
				log_message(message,6);
			}
			else if(item->flow_key.ip_protocol == 17)
			{
				strcpy(message,"Type of used protocol -> [UDP]");
				log_message(message,6);
			}
			else if(item->flow_key.ip_protocol == 58)
			{
				strcpy(message,"Type of used protocol -> [IC6]");
				log_message(message,6);
			}
			else
			{ 	
				sprintf(message,"Type of used protocol -> [%03i]",item->flow_key.ip_protocol);
				log_message(message,6);
			}
			if(item->flow_key.ip_ver == 4)
			{			
			ip = (unsigned char *) &item->flow_key.ip_src_addr;
			sprintf(message, "Source IP address -> %i.%i.%i.%i",ip[0],ip[1],ip[2],ip[3]);
			log_message(message,6);
			//printf(" %-15s:%-5i -> ",ip_text,item->flow_key.src_port);
			ip = (unsigned char *) &item->flow_key.ip_dst_addr;
			sprintf(message, "Destination IP address -> %i.%i.%i.%i",ip[0],ip[1],ip[2],ip[3]);
			log_message(message,6);
			//printf("%-15s:%-5i",ip_text,item->flow_key.dst_port);
			//printf(" = pkts: %llu ",item->packet_total_count);
#ifdef IPFIX_PACKETTOTALCOUNT
                        sprintf(message,"Packet total count -> %llu ",item->packet_total_count);
			log_message(message,6);
#endif
			}
			if(item->flow_key.ip_ver == 6)
			{
				sprintf(message,"Source IP address -> %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x :%-5i",
																			item->flow_key.ip6_src_addr.s6_addr[0],item->flow_key.ip6_src_addr.s6_addr[1],
																			item->flow_key.ip6_src_addr.s6_addr[2],item->flow_key.ip6_src_addr.s6_addr[3],
																			item->flow_key.ip6_src_addr.s6_addr[4],item->flow_key.ip6_src_addr.s6_addr[5],
																			item->flow_key.ip6_src_addr.s6_addr[6],item->flow_key.ip6_src_addr.s6_addr[7],
																			item->flow_key.ip6_src_addr.s6_addr[8],item->flow_key.ip6_src_addr.s6_addr[9],
																			item->flow_key.ip6_src_addr.s6_addr[10],item->flow_key.ip6_src_addr.s6_addr[11],
																			item->flow_key.ip6_src_addr.s6_addr[12],item->flow_key.ip6_src_addr.s6_addr[13],
																			item->flow_key.ip6_src_addr.s6_addr[14],item->flow_key.ip6_src_addr.s6_addr[15],
																		    item->flow_key.src_port);
				log_message(message,6);
				sprintf(message,"Destination IP address -> %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x :%-5i",
																			item->flow_key.ip6_dst_addr.s6_addr[0],item->flow_key.ip6_dst_addr.s6_addr[1],
																			item->flow_key.ip6_dst_addr.s6_addr[2],item->flow_key.ip6_dst_addr.s6_addr[3],
																			item->flow_key.ip6_dst_addr.s6_addr[4],item->flow_key.ip6_dst_addr.s6_addr[5],
																			item->flow_key.ip6_dst_addr.s6_addr[6],item->flow_key.ip6_dst_addr.s6_addr[7],
																			item->flow_key.ip6_dst_addr.s6_addr[8],item->flow_key.ip6_dst_addr.s6_addr[9],
																			item->flow_key.ip6_dst_addr.s6_addr[10],item->flow_key.ip6_dst_addr.s6_addr[11],
																			item->flow_key.ip6_dst_addr.s6_addr[12],item->flow_key.ip6_dst_addr.s6_addr[13],
																			item->flow_key.ip6_dst_addr.s6_addr[14],item->flow_key.ip6_dst_addr.s6_addr[15],
																		    item->flow_key.dst_port);
				log_message(message,6);
			}
				sprintf(message,"Source port -> %d ",item->flow_key.src_port);
				log_message(message,6);
				
				sprintf(message,"Destination port -> %d ",item->flow_key.dst_port);
				log_message(message,6);
#if defined(IPFIX_FLOWSTARTMILLISECONDS) || defined(IPFIX_FLOWSTARTMICROSECONDS) || defined(IPFIX_FLOWSTARTNANOSECONDS) || defined(IPFIX_FLOWSTARTDELTAMICROSECONDS) || defined(IPFIX_FLOWDURATIONMILLISECONDS) || defined(IPFIX_FLOWDURATIONMICROSECONDS)
			avg_spd = item->flow_end_nano_seconds - item->flow_start_nano_seconds;
#endif
#ifdef IPFIX_OCTETTOTALCOUNT			
                        if(avg_spd != 0){
				avg_spd = (item->octet_total_count * 1000000) / avg_spd;
				sprintf(message,"Speed -> %llu kBps", avg_spd);
				log_message(message,6);
			}
#endif
			//printf(" RTT avg: %llu us, cnt: %llu\n", item->rtt_avg / 1000, item->rtt_cnt);
#if defined(IPFIX_PACKETPAIRSTOTALCOUNT) && defined(IPFIX_ROUNDTRIPTIMENANOSECONDS)
			if(item->rtt_cnt_fwd != 0 || item->rtt_cnt_bwd != 0)
			{
				sprintf(message,"Round-trip delay time -> %llu (%llu + %llu)",(item->rtt_avg_fwd + item->rtt_avg_bwd) / 1000, item->rtt_cnt_fwd, item->rtt_cnt_bwd);
				log_message(message,6);				
			}
#endif			
				sprintf(message,"Amount of DATA sent -> %llu:%llu",item->layer_3_length_fwd, item->layer_3_length_bwd);
				log_message(message,6);
		/*	printf("         %llu, %llu, %llu, %llu, %llu, %llu \n",
				item->tcpUrgTotalCount,
				item->tcpAckTotalCount,
				item->tcpPshTotalCount,
				item->tcpRstTotalCount,
				item->tcpSynTotalCount,
				item->tcpFinTotalCount); */
				sprintf(message,"EXPORTED FROM -> %d",item->exported_from);
				log_message(message,6);

                                sprintf(message,"[cache] Packet cache free: %i", list_size((struct list *)&pcache_free_list));
                                log_message(message,6);
                                sprintf(message,"[cache] Flow cache free: %i", list_size((struct list *)&cache_free_list));
                                log_message(message,6);
                                if (DPI_CACHE_SIZE > 0) {
                                    sprintf(message,"[cache] DPI cache free: %i", list_size((struct list *)&dpicache_free_list));
                                    log_message(message,6);
                                }
                                
				item->exported_from = 0;

			cache_list_add(&cache_free_list, cache_list_remove(&cache_expired_list, item));
					
			break;
			item = item->next;
		}
		pthread_mutex_unlock(&flow_cache_mutex);
		if(!cache_expired_list.first)
			sleep(1);
	}

	closeExport();
}


uint64_t getCurrentTime(int precision)
{
//	struct timespec now;
//	unsigned long long int current_time_sec;
//	unsigned long long int current_time_nsec;
//	clock_gettime(CLOCK_REALTIME,&now);
//	current_time_sec = now.tv_sec;
//	current_time_nsec = now.tv_nsec;
	uint64_t current = getLocalTime(precision);
	//printf("\nCurrent:%llu\n",current);		
	int64_t t3 = (int64_t)current;
	//printf("\n t3:%I64d\n",t3);	    
	int64_t drift = ((int64_t)(slope * ((double)(t3 - mns_dx)))) + (mns_dy + (int64_t)yntercept);

	//printf("\n Drift:%I64d\n",drift);



	switch (precision)
	{
	case 0: return current;
		break;

	case 1: return current;
		break;

	case 2: return current;
		break;

	case 3: return (uint64_t)(((int64_t)current) - drift);
		break;
	}
	return 0;
}


void debugFlowCache(void)
{
        char message[LOG_MESSAGE_SIZE];
	int i;
	unsigned long long avg_spd = 1;
	unsigned char *ip;
	struct cache_item *item;
	for(i=0;i<HASH_SIZE;i++){
		item = (struct cache_item *)cache_hash_list[i].first;
		while(item){
			strcpy(message,"Debug flow cache");
			log_message(message,7);
			if(item->flow_key.ip_protocol == 1){
				strcpy(message,"Type of used protocol -> [ICMP]");				
				log_message(message,7);
			}else if(item->flow_key.ip_protocol == 6){
				strcpy(message,"Type of used protocol -> [TCP]");
				log_message(message,7);
			}else if(item->flow_key.ip_protocol == 17){
				strcpy(message,"Type of used protocol -> [UDP]");
				log_message(message,7);
			}else{
				sprintf(message,"Type of used protocol -> [%02x]",item->flow_key.ip_protocol);
				log_message(message,7);
			}

			ip = (unsigned char *) &item->flow_key.ip_src_addr;
			sprintf(message,"Source IP address -> %i.%i.%i.%i:%i",ip[0],ip[1],ip[2],ip[3],item->flow_key.src_port);
			log_message(message,7);
			ip = (unsigned char *) &item->flow_key.ip_dst_addr;
			sprintf(message,"Destination IP address -> %i.%i.%i.%i:%i",ip[0],ip[1],ip[2],ip[3],item->flow_key.dst_port);			
			log_message(message,7);	
#ifdef IPFIX_PACKETTOTALCOUNT                        
			sprintf(message,"Packet total count -> %llu ",item->packet_total_count);
			log_message(message,7);
#endif

#if defined(IPFIX_FLOWSTARTMILLISECONDS) || defined(IPFIX_FLOWSTARTMICROSECONDS) || defined(IPFIX_FLOWSTARTNANOSECONDS) || defined(IPFIX_FLOWSTARTDELTAMICROSECONDS) || defined(IPFIX_FLOWDURATIONMILLISECONDS) || defined(IPFIX_FLOWDURATIONMICROSECONDS)
			avg_spd = item->flow_end_nano_seconds - item->flow_start_nano_seconds;
#endif

#ifdef IPFIX_OCTETTOTALCOUNT                        
			if(avg_spd != 0){
				avg_spd = (item->octet_total_count * 1000000) / avg_spd;
				sprintf(message,"Average speed -> %llu kBps", avg_spd);
				log_message(message,7);
			}else
			{	
				strcpy(message,"?? kBps");	
				log_message(message,7);
			}
#endif
#if defined(IPFIX_ROUNDTRIPTIMENANOSECONDS) && defined(IPFIX_PACKETPAIRSTOTALCOUNT)                       
			sprintf(message,"Round-trip delay time -> avg: %llu ms, cnt: %llu\n", item->rtt_avg / 1000, item->rtt_cnt);
			log_message(message,7);
#endif                        

			sprintf(message,"List sizes -> %i + %i ", list_size((struct list *)&item->packet_cache_fwd), list_size((struct list *)&item->packet_cache_bwd));
			log_message(message,7);
			item = item->next;
			//printf("==================================================================");
		}
	}
	printf("\n");
}
void cache_status(void){
        char message[LOG_MESSAGE_SIZE];
	//printf("\n<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>");	
	sprintf(message,"[cache] Flow cache free: %i", list_size((struct list *)&cache_free_list));
	log_message(message,6);	
	sprintf(message,"[cache] Packet cache free: %i", list_size((struct list *)&pcache_free_list));
	log_message(message,6);
	sprintf(message,"[cache] Expired cache size: %i", list_size((struct list *)&cache_expired_list));
	log_message(message,6);
        if (DPI_CACHE_SIZE > 0) {
            sprintf(message,"[cache] DPI cache free: %i", list_size((struct list *)&dpicache_free_list));
            log_message(message,6);
        }
}

