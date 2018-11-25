/*! \file aggregation.h
*  \brief Hlavickovy subor modulu pre agregaciu tokov
* 
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
#include "ipfix_infelems.h"
#include "list.h"
#include "queue.h"
#include "beem.h"
#include "cache.h"

//#define AGGREGATION_PARAMETER (uint64_t)100000000

extern struct list		cache_hash_list[HASH_SIZE];
extern struct list		cache_free_list;
extern struct list 		cache_remove_list;

extern int 				AGGREGATION_CONDITION;
extern volatile uint8_t doAggregation;
extern struct list		aggreg_cache_hash_list_first[HASH_SIZE];
extern struct list		aggreg_cache_hash_list_second[HASH_SIZE];
extern struct list		aggreg_cache_hash_list_third[HASH_SIZE];
extern struct list		aggreg_cache_hash_list_fourth[HASH_SIZE];


extern int first_aggreg_value;
extern int second_aggreg_value;
extern int third_aggreg_value;
extern int fourth_aggreg_value;

uint64_t fwd_packet_flow_identificator(packet_info_t *packet);
uint64_t bckwd_packet_flow_identificator(packet_info_t *packet);
uint64_t hashes(unsigned char *str);
void flow_keys_reduction(struct cache_item *item, int buff_nmbr);
void merge_flows(struct cache_item *from, struct cache_item *to);
void flow_cache_rework(void);
struct cache_item *move_flows_to_next_buff(struct cache_item *item, int i, int buff_nmbr);
struct cache_item *packet_to_flow(packet_info_t *packet);