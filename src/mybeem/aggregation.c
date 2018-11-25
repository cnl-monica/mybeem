/*! \file aggregation.c
*  \brief Modul implementujuci proces agregacie tokov.
* 
*  Tento modul ma na starosti agregaciu tokov v programe BEEM.
*/

/*
*    Copyright (c) 2014 Samuel Tremko
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



#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include "cache.h"
#include "config.h"
#include "debug.h"
#include "export.h"
#include "sync.h"
#include "packetIdent.h"
#include "MurmurHash.h"
#include "aggregation.h"

int aggregated = 0;



void flow_cache_rework(void){
	struct 	cache_item 	*item;
	struct 	cache_item 	*remove_item;
	int 	i,j=0;

	for(i=0;i<HASH_SIZE;i++){
		item = (struct cache_item *)cache_hash_list[i].first;	
		move_flows_to_next_buff(item,i,1);
	}

	for(i=0;i<HASH_SIZE;i++){
		item = (struct cache_item *)aggreg_cache_hash_list_first[i].first;		
		move_flows_to_next_buff(item,i,2);
	}

	for(i=0;i<HASH_SIZE;i++){
		item = (struct cache_item *)aggreg_cache_hash_list_second[i].first;		
		move_flows_to_next_buff(item,i,3);
	}

	for(i=0;i<HASH_SIZE;i++){
		item = (struct cache_item *)aggreg_cache_hash_list_third[i].first;		
		move_flows_to_next_buff(item,i,4);
	}

	remove_item = (struct cache_item*)cache_remove_list.first;

	while(remove_item){
		cache_list_add(&cache_free_list, cache_list_remove(&cache_remove_list,remove_item));
		remove_item = (struct cache_item*)cache_remove_list.first;
		continue;
	remove_item = remove_item->next;	
	}
}

struct cache_item *packet_to_flow(packet_info_t *packet){
	uint64_t 	fwd_packet_id = 0;
	uint64_t 	bwd_packet_id = 0;
	int 		hash = 0;
	struct 		cache_item *item = 0;


	fwd_packet_id = fwd_packet_flow_identificator(packet);
	hash = hash_func(fwd_packet_id);

	item = (struct cache_item *)cache_hash_list[hash].first;

	if(item){
		while(item){
			if(item->flow_id == fwd_packet_id){
				packet->direction = 1;
				return item;
			}
		item = item->next;
		}
	}	

	if(biflow_support){

		bwd_packet_id = bckwd_packet_flow_identificator(packet);
		hash = hash_func(bwd_packet_id);

		item = (struct cache_item *)cache_hash_list[hash].first;
			
		if(item){
			while(item){
				if(item->flow_id == bwd_packet_id){
					packet->direction = 2;
					return item;
				}
			item = item->next;
			}
		}
	}

	return item;
}

void merge_flows(struct cache_item *from, struct cache_item *to){
	struct packet_info_t *packet;
	uint64_t current_time;


	if(from->distCntOfSrcIPAddr == 1)
		to->distCntOfSrcIPAddr++;
	else
		to->distCntOfSrcIPAddr += from->distCntOfSrcIPAddr;

	if(from->distCntOfDstIPAddr == 1)
		to->distCntOfDstIPAddr++;
	else
		to->distCntOfDstIPAddr += from->distCntOfDstIPAddr;

	if(from->distCntOfSrcIPv4Addr == 1)
		to->distCntOfSrcIPv4Addr++;
	else
		to->distCntOfSrcIPv4Addr += from->distCntOfSrcIPv4Addr;
	
	if(from->distCntOfDstIPv4Addr == 1)
		to->distCntOfDstIPv4Addr++;
	else
		to->distCntOfDstIPv4Addr += from->distCntOfDstIPv4Addr; 
	
	if(from->distCntOfSrcIPv6Addr == 1)
		to->distCntOfSrcIPv6Addr++;
	else
		to->distCntOfSrcIPv6Addr += from->distCntOfSrcIPv6Addr;
	
	if(from->distCntOfDstIPv6Addr == 1)
		to->distCntOfDstIPv6Addr++;
	else
		to->distCntOfDstIPv6Addr += from->distCntOfDstIPv6Addr;

	to->originalFlowsInitiated += from->originalFlowsInitiated;
	to->originalFlowsCompleted += from->originalFlowsCompleted;

	current_time = getCurrentTime(3);

	to->flow_state = 1;

	to->originalFlowsPresent += from->originalFlowsPresent;

	to->packet_total_count += from->packet_total_count;
                        
	to->octet_total_count += from->octet_total_count; 
	to->octet_total_sum_of_squares += from->octet_total_sum_of_squares;
					
	if(to->flow_end_nano_seconds < from->flow_end_nano_seconds)
		to->flow_end_nano_seconds = from->flow_end_nano_seconds; 
		                        
	if(to->flow_start_nano_seconds > from->flow_start_nano_seconds)
		to->flow_start_nano_seconds = from->flow_start_nano_seconds;

	if(to->flow_start_after_export > from->flow_start_after_export)
		to->flow_start_after_export = from->flow_start_after_export;

	if(to->flow_last_exp_nano_seconds < from->flow_last_exp_nano_seconds)
		to->flow_last_exp_nano_seconds = from->flow_last_exp_nano_seconds; 
	

    to->dropped_packet_delta += from->dropped_packet_delta;

    to->dropped_octet_delta += from->dropped_octet_delta;

	if(to->flow_key.ip_protocol == IPPROTO_TCP){
		to->temp_8 = from->temp_8;
		to->originalFlowsCompleted += from->tcpFinTotalCount;

	if(to->temp_8 & 1)
		to->tcpFinTotalCount = 0;
	
	if(to->temp_8 & 2)
		to->tcpSynTotalCount += from->tcpSynTotalCount;
		                        
	if(to->temp_8 & 4)
		to->tcpRstTotalCount += from->tcpRstTotalCount;
		                                
	if(to->temp_8 & 8)
		to->tcpPshTotalCount += from->tcpPshTotalCount;
		                              
	if(to->temp_8 & 16)
		to->tcpAckTotalCount += from->tcpAckTotalCount;
		                               
	if(to->temp_8 & 32)
		to->tcpUrgTotalCount += from->tcpUrgTotalCount;                             
					}

		            
    to->ip_pl = from->ip_pl;
		                      
    to->tcpSeqNumber = from->tcpSeqNumber;
	to->tcpAckNumber = from->tcpAckNumber;                      
		                        
	if(to->flow_key.ip_protocol == IPPROTO_UDP){
		to->layer_3_hlength_fwd += from->layer_3_hlength_fwd;
		to->layer_3_length_fwd += from->layer_3_length_fwd;
		to->layer_4_hlength_fwd += from->layer_4_hlength_fwd;

		to->layer_3_hlength_bwd += from->layer_3_hlength_bwd;
		to->layer_3_length_bwd += from->layer_3_length_bwd;
		to->layer_4_hlength_bwd += from->layer_4_hlength_bwd;
	}
		            

		
		//memcpy(to->firstPacketID, to->lastPacketID, 16);	
}


struct cache_item *move_flows_to_next_buff(struct cache_item *item, int i, int buff_nmbr){
	struct 		cache_item *ci = 0;
	struct 		flow_in_buff *fib;
	struct 		flow_in_buff *old_fib;
	uint64_t 	new_flow_id = 0;
	uint64_t	old_flow_id = 0;
	int 		hash = 0;
	int 		match = 0;


	while(item){
		if(item->octet_total_count < AGGREGATION_CONDITION){
			flow_keys_reduction(item,buff_nmbr);
			new_flow_id = flow_identificator(item);
			old_flow_id = item->flow_id;
			item->flow_id = new_flow_id;
			hash = hash_func(new_flow_id);

			while(item->packet_cache_fwd.first)
        		pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache_fwd));
    		while(item->packet_cache_bwd.first)
        		pcache_list_add(&pcache_free_list, pcache_list_get(&item->packet_cache_bwd));

			if(buff_nmbr == 1)
				ci = (struct cache_item *)aggreg_cache_hash_list_first[hash].first;
			else if(buff_nmbr == 2)
				ci = (struct cache_item *)aggreg_cache_hash_list_second[hash].first;
			else if(buff_nmbr == 3)
				ci = (struct cache_item *)aggreg_cache_hash_list_third[hash].first;
			else if(buff_nmbr == 4)
				ci = (struct cache_item *)aggreg_cache_hash_list_fourth[hash].first;

			if(!ci){
				if(buff_nmbr == 1){
					item = cache_list_remove(&cache_hash_list[i],item);
					item->exported_from = 1;
					aggregated = item->aggregateExpiredFlow;
					cache_list_add(&aggreg_cache_hash_list_first[hash],item);
					item = (struct cache_item *)cache_hash_list[i].first;
					
					if(aggregated){
						aggregated = 0;
						return item;
					}
				}
				if(buff_nmbr == 2){
					item = cache_list_remove(&aggreg_cache_hash_list_first[i],item);
					item->exported_from = 2;
					cache_list_add(&aggreg_cache_hash_list_second[hash],item);
					item = (struct cache_item *)aggreg_cache_hash_list_first[i].first;
				}
				if(buff_nmbr == 3){
					item = cache_list_remove(&aggreg_cache_hash_list_second[i],item);
					item->exported_from = 3;
					cache_list_add(&aggreg_cache_hash_list_third[hash],item);
					item = (struct cache_item *)aggreg_cache_hash_list_second[i].first;
				}
				if(buff_nmbr == 4){
					item = cache_list_remove(&aggreg_cache_hash_list_third[i],item);
					item->exported_from = 4;
					cache_list_add(&aggreg_cache_hash_list_fourth[hash],item);
					item = (struct cache_item *)aggreg_cache_hash_list_third[i].first;
				}
				break;
			}
			else if(ci){
				while(ci){
					if(ci->flow_id == new_flow_id){
						merge_flows(item,ci);
						if(buff_nmbr == 1){
							item = cache_list_remove(&cache_hash_list[i],item);
							aggregated = item->aggregateExpiredFlow;
							cache_list_add(&cache_remove_list,item);
							item = (struct cache_item *)cache_hash_list[i].first;
							
							if(aggregated){
								aggregated = 0;
								return item;
							}
						}
						else if(buff_nmbr == 2){
							item = cache_list_remove(&aggreg_cache_hash_list_first[i],item);
							cache_list_add(&cache_remove_list,item);
							item = (struct cache_item *)aggreg_cache_hash_list_first[i].first;
						}
						else if(buff_nmbr == 3){
							item = cache_list_remove(&aggreg_cache_hash_list_second[i],item);
							cache_list_add(&cache_remove_list,item);
							item = (struct cache_item *)aggreg_cache_hash_list_second[i].first;
						}
						else if(buff_nmbr == 4){
							item = cache_list_remove(&aggreg_cache_hash_list_third[i],item);
							cache_list_add(&cache_remove_list,item);
							item = (struct cache_item *)aggreg_cache_hash_list_third[i].first;
						}
						match = 1;
						break;
					}
				ci = ci->next;	
				}
				if(!item)
					break;
				if(!match){				
					if(buff_nmbr == 1){
						item = cache_list_remove(&cache_hash_list[i],item);
						aggregated = item->aggregateExpiredFlow;
						cache_list_add(&aggreg_cache_hash_list_first[hash],item);
						item = (struct cache_item *)cache_hash_list[i].first;

						if(aggregated){
							aggregated = 0;
							return item;
						}
					}
					else if(buff_nmbr == 2){
						item = cache_list_remove(&aggreg_cache_hash_list_first[i],item);
						cache_list_add(&aggreg_cache_hash_list_second[hash],item);
						item = (struct cache_item *)aggreg_cache_hash_list_first[i].first;
					}
					else if(buff_nmbr == 3){
						item = cache_list_remove(&aggreg_cache_hash_list_second[i],item);
						cache_list_add(&aggreg_cache_hash_list_third[hash],item);
						item = (struct cache_item *)aggreg_cache_hash_list_second[i].first;
					}
					else if(buff_nmbr == 4){
						item = cache_list_remove(&aggreg_cache_hash_list_third[i],item);
						cache_list_add(&aggreg_cache_hash_list_fourth[hash],item);
						item = (struct cache_item *)aggreg_cache_hash_list_third[i].first;
					}
					break;
				}
			}
		}
		else if((item->octet_total_count > AGGREGATION_CONDITION) && (item->aggregateExpiredFlow)){
			item->aggregateExpiredFlow = 0;
			return item;
		}
	item = item->next;
	}	
}

uint64_t hashes(unsigned char *str)
{
    uint64_t hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}


uint64_t fwd_packet_flow_identificator(packet_info_t *packet){

	char string_for_hash[100];

	if(packet->ip_version == 4){

		sprintf(string_for_hash,"%d%lu%lu%d%d",
			packet->ip_protocol,
			packet->ip_src_addr.s_addr,
			packet->ip_dst_addr.s_addr,
			packet->srcport,
			packet->dstport);
	}

	else if(packet->ip_version == 6){

		sprintf(string_for_hash,"%d%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x%d%d",
			packet->ip_protocol,
			packet->ip6_src_addr.s6_addr[0],packet->ip6_src_addr.s6_addr[1],
			packet->ip6_src_addr.s6_addr[2],packet->ip6_src_addr.s6_addr[3],
			packet->ip6_src_addr.s6_addr[4],packet->ip6_src_addr.s6_addr[5],
			packet->ip6_src_addr.s6_addr[6],packet->ip6_src_addr.s6_addr[7],
			packet->ip6_src_addr.s6_addr[8],packet->ip6_src_addr.s6_addr[9],
			packet->ip6_src_addr.s6_addr[10],packet->ip6_src_addr.s6_addr[11],
			packet->ip6_src_addr.s6_addr[12],packet->ip6_src_addr.s6_addr[13],
			packet->ip6_src_addr.s6_addr[14],packet->ip6_src_addr.s6_addr[15],
			packet->ip6_dst_addr.s6_addr[0],packet->ip6_dst_addr.s6_addr[1],
			packet->ip6_dst_addr.s6_addr[2],packet->ip6_dst_addr.s6_addr[3],
			packet->ip6_dst_addr.s6_addr[4],packet->ip6_dst_addr.s6_addr[5],
			packet->ip6_dst_addr.s6_addr[6],packet->ip6_dst_addr.s6_addr[7],
			packet->ip6_dst_addr.s6_addr[8],packet->ip6_dst_addr.s6_addr[9],
			packet->ip6_dst_addr.s6_addr[10],packet->ip6_dst_addr.s6_addr[11],
			packet->ip6_dst_addr.s6_addr[12],packet->ip6_dst_addr.s6_addr[13],
			packet->ip6_dst_addr.s6_addr[14],packet->ip6_dst_addr.s6_addr[15],
			packet->srcport,
			packet->dstport);
	}
	return (hashes(string_for_hash));
}

uint64_t bckwd_packet_flow_identificator(packet_info_t *packet){

	char string_for_hash[100];

	if(packet->ip_version == 4){

		sprintf(string_for_hash,"%d%lu%lu%d%d",
			packet->ip_protocol,
			packet->ip_dst_addr.s_addr,
			packet->ip_src_addr.s_addr,
			packet->dstport,
			packet->srcport);
	}

	else if(packet->ip_version == 6){

		sprintf(string_for_hash,"%d%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x%d%d",
			packet->ip_protocol,
			packet->ip6_dst_addr.s6_addr[0],packet->ip6_dst_addr.s6_addr[1],
			packet->ip6_dst_addr.s6_addr[2],packet->ip6_dst_addr.s6_addr[3],
			packet->ip6_dst_addr.s6_addr[4],packet->ip6_dst_addr.s6_addr[5],
			packet->ip6_dst_addr.s6_addr[6],packet->ip6_dst_addr.s6_addr[7],
			packet->ip6_dst_addr.s6_addr[8],packet->ip6_dst_addr.s6_addr[9],
			packet->ip6_dst_addr.s6_addr[10],packet->ip6_dst_addr.s6_addr[11],
			packet->ip6_dst_addr.s6_addr[12],packet->ip6_dst_addr.s6_addr[13],
			packet->ip6_dst_addr.s6_addr[14],packet->ip6_dst_addr.s6_addr[15],
			packet->ip6_src_addr.s6_addr[0],packet->ip6_src_addr.s6_addr[1],
			packet->ip6_src_addr.s6_addr[2],packet->ip6_src_addr.s6_addr[3],
			packet->ip6_src_addr.s6_addr[4],packet->ip6_src_addr.s6_addr[5],
			packet->ip6_src_addr.s6_addr[6],packet->ip6_src_addr.s6_addr[7],
			packet->ip6_src_addr.s6_addr[8],packet->ip6_src_addr.s6_addr[9],
			packet->ip6_src_addr.s6_addr[10],packet->ip6_src_addr.s6_addr[11],
			packet->ip6_src_addr.s6_addr[12],packet->ip6_src_addr.s6_addr[13],
			packet->ip6_src_addr.s6_addr[14],packet->ip6_src_addr.s6_addr[15],
			packet->dstport,
			packet->srcport);
	}
	return (hashes(string_for_hash));
}

void flow_keys_reduction(struct cache_item *item, int buff_nmbr){
	int i,j,value = 0;
		
	for(i=0;i<buff_nmbr;i++){
		switch(i){
			case 0: value = first_aggreg_value;break;
			case 1: value = second_aggreg_value;break;
			case 2: value = third_aggreg_value;break;
			case 3: value = fourth_aggreg_value;break;
		}
		switch(value){
			case 4: item->flow_key.ip_protocol = 0;break;
			case 7: item->flow_key.src_port = 0;break;
			case 8: 
				item->flow_key.ip_src_addr = 0;
				item->distCntOfSrcIPAddr = 1;
				item->distCntOfSrcIPv4Addr = 1;
			break;
			case 11: item->flow_key.dst_port = 0;break;
			case 12: 
				item->flow_key.ip_dst_addr = 0;
				item->distCntOfDstIPAddr = 1;
				item->distCntOfDstIPv4Addr = 1;
			break;
			case 27:
				item->distCntOfSrcIPAddr = 1;
				item->distCntOfSrcIPv6Addr = 1; 
				for(j=0;j<16;j++)
						item->flow_key.ip6_src_addr.s6_addr[j] = 0;
				break;
			case 28:
				item->distCntOfDstIPAddr = 1;
				item->distCntOfDstIPv6Addr = 1;
				for(j=0;j<16;j++)
						item->flow_key.ip6_dst_addr.s6_addr[j] = 0;
				break;
			case 827: 
				if(item->flow_key.ip_src_addr){
					item->distCntOfSrcIPAddr = 1;
					item->distCntOfSrcIPv4Addr = 1;
					item->flow_key.ip_src_addr = 0;
				}
				else{
					item->distCntOfSrcIPAddr = 1;
					item->distCntOfSrcIPv6Addr = 1;
					for(j=0;j<16;j++)
						item->flow_key.ip6_src_addr.s6_addr[j] = 0;
				}
				break;
			case 1228:
				if(item->flow_key.ip_dst_addr){
					item->distCntOfDstIPAddr = 1; 
					item->distCntOfDstIPv4Addr = 1;
					item->flow_key.ip_dst_addr = 0;
				}
				else{
					item->distCntOfDstIPAddr = 1;
					item->distCntOfDstIPv6Addr = 1;
					for(j=0;j<16;j++)
						item->flow_key.ip6_dst_addr.s6_addr[j] = 0;
				}
				break;
			default: break;
		}
	}
}