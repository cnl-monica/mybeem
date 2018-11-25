/*! \file capture.c
*  \brief Modul pre funkcie odchyt�vania a dissekcie paketu
*
*  Modul obsahuje funkcie na spustenie odchyt�vanie paketov zo zvolen�ho interface, alebo dump s�boru. Nap��a �trukt�ru s inform�ciami o pakete.
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

#include <pthread.h>
#include "capture.h"
#include "debug.h"
#include "sampling.h"
#include "cache.h"
#include "config.h"
#include "sync.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h> 
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/ether.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
//#include <bits/string3.h>

/*! 
* �tandardn� ve�kost ethernetovej hlavi�ky
*/
#define SIZE_ETHERNET 14

/*! 
* �tandardn� ve�kost ipv6 hlavi�ky
*/
#define SIZE_IPV6 40

/*!
* Priznak ukoncenia odchytavania
*/
int capture_interrupted = 0;

//Priznak hlbkovej analyzy paketov
int doDPI = 0;
//Smernik na subor s protokolmi
char *protofile = NULL;

/*!
* Externy smernik na konfiguraciu
*/
extern xmlDocPtr configData; 

/*
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
};
*/
struct packet_capturing_thread	*pcts;
int				pct_count;

/*!
* Datab�za �abl�n
*/
//template_t tmpl_db[MAXTEMPLATES]; 

/*!
* Mutex pre management/zapis pamate tokov
*/
pthread_mutex_t flow_cache_mutex;

pthread_mutex_t pcache_input_mutex;
pthread_cond_t	pcache_input_wait;

pthread_mutex_t dpi_cache_mutex;

pthread_t	packet_processing_thread;
/*!
* Vl�kno pre �asov� expir�ciu tokov
*/
pthread_t time_expire_thread;

/*!
* Vl�kno pre export tokov
*/
pthread_t export_thread;

/*!
* Flow aggregation thread
*/
pthread_t aggregation_thread;

pthread_t sync_thread;

/*!
* Premenna pre ulozenie casu poslednej inicializacie
*/
uint64_t init_time;

/*!
* Funkcia vl�kna �asovej expir�cie tokov.
*/

/*!
* Test SVN pripojenia
*/
int p=0;

void* threadTimeExpire(void *arg){
        char message[LOG_MESSAGE_SIZE];
	strcpy(message,"[Flow Expiration] Thread started");
	log_message(message,6);
	sprintf(message,"[Flow Expiration] PID %i", syscall(SYS_gettid));
	log_message(message,6);
	flowCacheTimeExpireInit();
	strcpy(message,"[Flow Expiration] Thread finished");
	log_message(message,6);
	return 0;
}

/*!
* Funkcia vl�kna exportu tokov
*/
void* threadExport(void *arg){
        char message[LOG_MESSAGE_SIZE];
	strcpy(message,"[Flow Exporting] Thread started");
	log_message(message,6);
	sprintf(message,"[Flow Exporting] PID %i", syscall(SYS_gettid));
	log_message(message,6);	
	flowCacheExport();
	strcpy(message,"[Flow Exporting] Thread finished");
	log_message(message,6);
	return 0;
}

void* threadPacketProcessing(void *arg){
        char message[LOG_MESSAGE_SIZE];
	strcpy(message,"[Packet Processing] Thread started");
	log_message(message,6);
	sprintf(message,"[Packet Processing] PID %i", syscall(SYS_gettid));
	log_message(message,6);	
	flowCachePacketProcessing();
	strcpy(message,"[Packet Processing] Thread finished");
	log_message(message,6);
	return 0;
}

void* threadFlowAggregation(void *arg){
        char message[LOG_MESSAGE_SIZE];
	strcpy(message,"[Flow Aggregation] Thread started");
	log_message(message,6);
	sprintf(message,"[Flow Aggregation] PID %i", syscall(SYS_gettid));
	log_message(message,6);	
	flowAggregationProcess();
	strcpy(message,"[Flow Aggregation] Thread finished");
	log_message(message,6);
	return 0;
}

void *setsignal (int sig, void (*func)(int)){
	struct sigaction old, new;

	memset(&new, 0, sizeof(new));
	new.sa_handler = func;
	if (sigaction(sig, &new, &old) < 0)
		return (SIG_ERR);
	return (old.sa_handler);

} 

void *malloc_wrapper(unsigned long size) {
    void *result = malloc(size);
    memset(result, 0, size);
    return result;
}

void free_wrapper(void *freeable) {
    free(freeable);
}

struct ndpi_detection_module_struct *setup_ndpi() {
    if (!doDPI) {
        return NULL;
    }
    
    char message[LOG_MESSAGE_SIZE];
    struct ndpi_detection_module_struct *ndpi_struct;
    NDPI_PROTOCOL_BITMASK all;
    
    ndpi_struct = ndpi_init_detection_module(1000, malloc_wrapper, free_wrapper, NULL); //1st parameter: time values in millisecond
    if (ndpi_struct == NULL) {
        strcpy(message, "[DPI] Global structure initialization failed");
        log_message(message, 3);
        exit(0);
    }
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);
    if (protofile) {
        ndpi_load_protocols_file(ndpi_struct, protofile);
    }
    
//    printf("%d | %d\n", ndpi_struct->ndpi_num_supported_protocols, ndpi_struct->ndpi_num_custom_protocols);
    
    return ndpi_struct;
}

void terminate_ndpi(struct ndpi_detection_module_struct *ndpi_struct) {
    if (ndpi_struct)
        ndpi_exit_detection_module(ndpi_struct, free_wrapper);
}

void* threadPacketCapturing(void *arg){
        char message[LOG_MESSAGE_SIZE];
	struct packet_capturing_thread	*t = &pcts[(int)arg];
	char *net;
	char *mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct in_addr addr;
	struct bpf_program fp;

	if(!t->interface){
		strcpy(message,"[interface unknown] Interface name is not defined, thread finished");
		log_message(message,3);
		return 0;
	}
	t->packet_count = 0;

	sprintf(message,"[interface %s] Packet Capturing thread started", t->interface);
	log_message(message,6);
	sprintf(message,"[interface %s] PID: %i", t->interface, syscall(SYS_gettid));
	log_message(message,6);

	if(t->dump_file){
		t->descr = pcap_open_offline(t->dump_file, errbuf);
	}else{
		if(!pcap_lookupnet(t->interface, &netp, &maskp, errbuf)){
			addr.s_addr = netp;
			net = inet_ntoa(addr);
			if(net != NULL)
			{
				sprintf(message,"[interface %s] Subnet address for selected interface is %s", t->interface, net);
				log_message(message,6);
			}			
			addr.s_addr = maskp;
			mask = inet_ntoa(addr);
			if(mask != NULL)
			{	
				sprintf(message,"[interface %s] Subnet mask for selected interface is %s", t->interface, mask);
				log_message(message,6);
			}
		}
		t->descr = pcap_open_live(t->interface,SNAP_LEN, 1, 1000, errbuf);
	}
	if(t->descr == NULL){
		sprintf(message,"[interface %s] error: %s", t->interface, errbuf);
		log_message(message,3);
		return 0;
	}

	if(!t->pcap_filter){
		sprintf(message,"[interface %s] Filter is not set. Filter deactivated", t->interface);
		log_message(message,3);
	}else if(pcap_compile(t->descr, &fp, t->pcap_filter, 0, netp) == -1){
		sprintf(message,"[interface %s] Filter compilation error. Filter deactivated", t->interface);
		log_message(message,3);
	}else if(pcap_setfilter(t->descr, &fp) == -1){
		sprintf(message,"[interface %s] Filter pcap application error. Filter deactivated", t->interface);
		log_message(message,3);
	}
	pcap_freecode(&fp);

	sprintf(message,"[interface %s] Starting packet capturing", t->interface);
	log_message(message,6);
	//printf("\n<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>");

        t->ndpi_struct = setup_ndpi();
        
	pcap_loop(t->descr, -1, doCallback, (u_char *)t);
        
	pcap_close(t->descr);
        terminate_ndpi(t->ndpi_struct);

	sprintf(message,"[interface %s] Packet Capturing thread finished", t->interface);
	log_message(message,6);
	sprintf(message,"[interface %s] Number of captured packets: %llu", t->interface, t->packet_count);
	log_message(message,6);

	return 0;
}
/*!
* Funkcia identifikuje tok pre konkr�tny paket a odo�le ho na spracovanie do pam�te tokov
* \param packet_info Inform�cie o pakete
*/
void addPacket(packet_info_t *packet_info){
	pthread_mutex_lock(&pcache_input_mutex);
	pqueue_put(&pcache_input_queue, packet_info);
	pthread_cond_signal(&pcache_input_wait);	//pthread_cond_broadcast(&pcache_input_wait);
	pthread_mutex_unlock(&pcache_input_mutex);
}

/*!
* Funkcia zabezpe�uj�ca vlastn� spracovanie paketu a odoslanie d�t na klasifik�ciu
* \param packet Bin�rne d�ta paketu
*/
void processPacket(struct packet_capturing_thread *t, const u_char *packet, const struct pcap_pkthdr *pkthdr){
        char message[LOG_MESSAGE_SIZE];
	// ethernet hlavicka
	header_ethernet_t *header_ethernet;  
	// IPv4 hlavicka
	header_ip_t *header_ip;  
	// IPv6 hlavicka
	header_ip6_t *header_ip6;            
	// TCP hlavicka
	header_tcp_t *header_tcp;           
	// UDP hlavicka
	header_udp_t *header_udp;           
	// ICMP hlavicka
	header_icmp_t *header_icmp; 
	// ICMPv6 hlavicka
	header_icmp6_t *header_icmp6;        
	// IGMP hlavicka
	header_igmp_t *header_igmp;
	// DNS hlavicka
	struct DNS_HEADER *header_dns;
	// data v pakete
//        u_char *payload;     
        //nDPI struktury
        struct ndpi_flow_struct *ndpi_flow = NULL;
        struct ndpi_id_struct *src = NULL, *dst = NULL;
        struct dpi_item *dpi_item = NULL;
        int hash;
        struct flow_key fk;
        uint64_t key;
        
	// velkosti jednotlivych hlaviciek a dat
	int size_ip;
	int size_tcp;
	int size_udp;
	unsigned int    size_header;
    	unsigned short  end_of_headers, fragmented;
    	uint8_t    next;
    	const uint8_t  *where_am_i;
    	const struct ip6_ext *eh;
    	const struct ip6_frag *frag;
//        int size_payload;

	// struktura pre informacie o pakete
	packet_info_t *packet_info;

	pthread_mutex_lock(&flow_cache_mutex);
	packet_info = pcache_list_get(&pcache_free_list);
	pthread_mutex_unlock(&flow_cache_mutex);

	if(packet_info == 0){
		strcpy(message,"Pcache full");		
		log_message(message,3);
		return;
	}

	if (!is_sampled(t->sampling_type, t->sampling_param1, t->sampling_param2))
	{
		pthread_mutex_lock(&flow_cache_mutex);
		pcache_list_add(&pcache_free_list, packet_info);
		pthread_mutex_unlock(&flow_cache_mutex);
		//packet_info->is_sampled = 1;
		return;
	}

	// explicitna cast ethernetovej hlavicky
	header_ethernet = (header_ethernet_t*)(packet);

	
// explicitna cast IP hlavicky
	if (ntohs(header_ethernet->ether_type) == ETHERTYPE_IP)
{
	header_ip = ( header_ip_t*)(packet + SIZE_ETHERNET);
	size_ip = header_ip->ip_hl*4;
	if (size_ip < 20) {
		sprintf(message,"Bad IP header length (%i bytes)",size_ip);
		log_message(message,7);
		pthread_mutex_lock(&flow_cache_mutex);
		pcache_list_add(&pcache_free_list, packet_info);
		pthread_mutex_unlock(&flow_cache_mutex);
		return;
	}

	memset(packet_info, 0, sizeof(packet_info_t));
	packet_info->timestamp = getCurrentTime(3);
//        memcpy(&(packet_info->ipheader4), header_ip, sizeof(header_ip_t));
	// polozky zavisle na skumanom protokole
	switch(header_ip->ip_p) {
		case IPPROTO_TCP:

			// explicitna cast tcp hlavicky
			header_tcp = (header_tcp_t*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = header_tcp->doff*4;
			if (size_tcp < 20) {
				sprintf(message,"Bad TCP header length (%i bytes)",size_tcp);
				log_message(message,7);
				pthread_mutex_lock(&flow_cache_mutex);
				pcache_list_add(&pcache_free_list, packet_info);
				pthread_mutex_unlock(&flow_cache_mutex);
				return;
			}
			packet_info->srcport = ntohs(header_tcp->source);
			packet_info->dstport = ntohs(header_tcp->dest);
			packet_info->tcp_seqnumber = ntohl(header_tcp->seq);
			packet_info->tcp_acknumber = ntohl(header_tcp->ack_seq);
			packet_info->tcp_flags = (header_tcp->urg << 5) | (header_tcp->ack << 4) |
				(header_tcp->psh << 3) | (header_tcp->rst << 2) |
				(header_tcp->syn << 1) | header_tcp->fin;
			packet_info->tcp_window = ntohs(header_tcp->window);
			packet_info->tcp_urgent_ptr = ntohs(header_tcp->urg_ptr);
			packet_info->tcp_hlength = size_tcp;

			packet_info->layer_4_hlength = header_tcp->doff << 2;
                        
//                        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
//                        size_payload = header_ip->ip_len - size_ip - size_tcp;
			break;
		case IPPROTO_UDP:

			// explicitna cast udp hlavicky
			header_udp = (header_udp_t*)(packet + SIZE_ETHERNET + size_ip);
			size_udp = header_udp->len;
			if (size_udp < 8) {
				sprintf(message,"Bad UDP header length (%i bytes)",size_udp);
				log_message(message,7);
				pthread_mutex_lock(&flow_cache_mutex);
				pcache_list_add(&pcache_free_list, packet_info);
				pthread_mutex_unlock(&flow_cache_mutex);
				return;
			}
			packet_info->srcport = ntohs(header_udp->source);
			packet_info->dstport = ntohs(header_udp->dest);
			packet_info->udp_hlength = ntohs(size_udp);			

			if(packet_info->srcport == 53 || packet_info->dstport == 53){
				header_dns = (void *)header_udp + sizeof(header_udp_t);
				packet_info->dns_id = ntohs(header_dns->id);
				packet_info->dns_opcode = header_dns->opcode;
				packet_info->dns_rd = header_dns->rd;
				packet_info->dns_qr = header_dns->qr;
			}
                        
                        // UDP header length is 8 bytes
//                        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
//                        size_payload = header_ip->ip_len - size_ip - 8;
			break;
		case IPPROTO_ICMP:

			// explicitna cast icmp hlavicky
			header_icmp = (header_icmp_t*)(packet + SIZE_ETHERNET + size_ip);
			packet_info->srcport = packet_info->dstport = header_icmp->un.echo.id;
			packet_info->icmp_code = header_icmp->code;
			packet_info->icmp_type = header_icmp->type;
			packet_info->tcp_seqnumber = header_icmp->un.echo.sequence;
                        
                        // ICMP header length is 8 bytes
//                        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
//                        size_payload = header_ip->ip_len - size_ip - 8;
			break;
		case IPPROTO_IGMP:

			// explicitna cast icmp hlavicky
			header_igmp = (header_igmp_t*)(packet + SIZE_ETHERNET + size_ip);
			packet_info->icmp_code = header_igmp->igmp_code;
			packet_info->icmp_type = header_igmp->igmp_type;
                        
                        // IGMP packets have no payload
//                        payload = NULL;
//                        size_payload = 0;
			break;
		default:
			pthread_mutex_lock(&flow_cache_mutex);
			pcache_list_add(&pcache_free_list, packet_info);
			pthread_mutex_unlock(&flow_cache_mutex);
			return;
			break;
	}
	// ziskanie zdroj. a cielovej MAC adresy
	memcpy(packet_info->ether_dmac,header_ethernet->ether_dhost,sizeof(header_ethernet->ether_dhost));
	memcpy(packet_info->ether_smac,header_ethernet->ether_shost,sizeof(header_ethernet->ether_shost));

	packet_info->ip_version = header_ip->ip_v;
	packet_info->ip_src_addr = header_ip->ip_src;
	packet_info->ip_dst_addr = header_ip->ip_dst;
	packet_info->ip_ttl = header_ip->ip_ttl;
	packet_info->ip_protocol = header_ip->ip_p;
	packet_info->ip_tos = header_ip->ip_tos;
	packet_info->ip_dcp = header_ip->ip_tos;
	packet_info->ip_id = header_ip->ip_id;
	packet_info->ip_offset = header_ip->ip_off;
	packet_info->ip_hlength = header_ip->ip_hl * 4;
	packet_info->ip_length = ntohs(header_ip->ip_len);
	packet_info->ip_plength = packet_info->ip_length - packet_info->ip_hlength;

	packet_info->layer_3_hlength = header_ip->ip_hl << 2;
	packet_info->layer_3_length = ntohs(header_ip->ip_len);
		
	copy_char_array(packet + SIZE_ETHERNET,packet_info->packet_ident,ntohs(header_ip->ip_len)<512?ntohs(header_ip->ip_len):512);
        
        if(doDPI) {
            memset(&fk, 0, sizeof(struct flow_key));
            fk.ip_ver = 4;
            fk.ip_protocol = packet_info->ip_protocol;
            fk.ip_src_addr = packet_info->ip_src_addr.s_addr;
            fk.ip_dst_addr = packet_info->ip_dst_addr.s_addr;
            fk.src_port = packet_info->srcport;
            fk.dst_port = packet_info->dstport;
            key = flow_identificator(&fk);
//            printf("DPI key: %llu\n", key);
            pthread_mutex_lock(&dpi_cache_mutex);
            dpi_item = dpi_get_item(packet_info, key);
            if (!dpi_item) {
                dpi_item = cache_list_get(&dpicache_free_list);
                if(dpi_item) {
                    dpi_item->flowid = key;
                    hash = hash_func(packet_info->srcport + packet_info->dstport);
                    cache_list_add(&dpicache_hash_list[hash], dpi_item);
                    
                    ndpi_flow = &(dpi_item->ndpi_flow);
                    src = &(dpi_item->src);
                    dst = &(dpi_item->dst);

                    packet_info->dpi_protocol = ndpi_detection_process_packet(t->ndpi_struct, ndpi_flow, (uint8_t *) header_ip, pkthdr->len - SIZE_ETHERNET, pkthdr->ts.tv_sec / 1000, src, dst);
//                    packet_info->dpi_protocol = 0;
                } else {
                    packet_info->dpi_protocol = 0;
                    strcpy(message, "DPI Cache Full");			
                    log_message(message, 3);
		}
            } else {
                dpi_item->flowid = key;
                
                ndpi_flow = &(dpi_item->ndpi_flow);
                src = &(dpi_item->src);
                dst = &(dpi_item->dst);

                packet_info->dpi_protocol = ndpi_detection_process_packet(t->ndpi_struct, ndpi_flow, (uint8_t *) header_ip, pkthdr->len - SIZE_ETHERNET, pkthdr->ts.tv_sec / 1000, src, dst);
//                packet_info->dpi_protocol = 0;
            }
            pthread_mutex_unlock(&dpi_cache_mutex);
        } else {
            packet_info->dpi_protocol = 0;
        }
        
	// debug vypis
	//	printf("S: %s",inet_ntoa(packet_info.ip_src_addr));printf("|D: %s |L: %i |SP: %u |DP: %u\n", inet_ntoa(packet_info.ip_dst_addr), packet_info.ip_length, packet_info.srcport, packet_info.dstport);
	// tu musi ist mutex
	addPacket(packet_info);
	//	debugFlowCache(flow_cache);	
	}
	else if (ntohs(header_ethernet->ether_type) == ETHERTYPE_IPV6)
  	{			
			header_ip6 = ( header_ip6_t*)(packet + SIZE_ETHERNET);
//                        memcpy(&(packet_info->ipheader6), header_ip6, sizeof(header_ip6_t));

			memcpy(packet_info->ether_dmac,header_ethernet->ether_dhost,sizeof(header_ethernet->ether_dhost));
			memcpy(packet_info->ether_smac,header_ethernet->ether_shost,sizeof(header_ethernet->ether_shost));
	
			packet_info->ip6_fl = header_ip6->ip6_flow;
			packet_info->ip_version = header_ip6->ip6_vfc >> 4;
			packet_info->ip6_src_addr = header_ip6->ip6_src;
			packet_info->ip6_dst_addr = header_ip6->ip6_dst;
			packet_info->ip_ttl = header_ip6->ip6_hlim;
			packet_info->ip_tos = (header_ip6->ip6_vfc << 4);
			packet_info->ip_hlength = 40;
			packet_info->ip_plength = header_ip6->ip6_plen;
			packet_info->ip_length = (packet_info->ip_hlength + packet_info->ip_plength)/256;
			packet_info->ip6_nh = header_ip6->ip6_nxt;
			
			packet_info->layer_3_hlength = 40;
			packet_info->layer_3_length = ntohs(packet_info->ip_length);
			
			where_am_i = packet + SIZE_ETHERNET;

			next = header_ip6->ip6_nxt;
		    size_header = SIZE_IPV6;

            end_of_headers = 0;
            fragmented = 0;
            
            while (!end_of_headers) {
                
                if (next == 0 || next == 43 || next == 50 || next == 51 || next == 60 || next == 140) {
                    eh = (struct ip6_ext*) (where_am_i);
                    next = eh->ip6e_nxt;
                    size_header = eh->ip6e_len;
                }
                else if (next == 44) {
                    fragmented = 1;
                    frag = (struct ip6_frag*) (where_am_i);
                    next = frag->ip6f_nxt;
                    size_header = 8;
                } else {
                    end_of_headers = 1;
                }
                where_am_i = where_am_i + size_header;
            }
            
            if (!fragmented || frag->ip6f_offlg == 0) {
                if (next == IPPROTO_UDP)
                {
                    header_udp = (header_udp_t*)(where_am_i);
                    size_udp = header_udp->len;
                    if (size_udp < 8) {
                            sprintf(message,"Bad UDP header length (%i bytes)",size_udp);
                            log_message(message,7);
                            pthread_mutex_lock(&flow_cache_mutex);
                            pcache_list_add(&pcache_free_list, packet_info);
                            pthread_mutex_unlock(&flow_cache_mutex);
                            return;
                            }
                    packet_info->ip_protocol = 17;
                    packet_info->srcport = ntohs(header_udp->source);
                    packet_info->dstport = ntohs(header_udp->dest);
                    packet_info->udp_hlength = ntohs(size_udp);

                    if(packet_info->srcport == 53 || packet_info->dstport == 53){
                            header_dns = (void *)header_udp + sizeof(header_udp_t);
                            packet_info->dns_id = ntohs(header_dns->id);
                            packet_info->dns_opcode = header_dns->opcode;
                            packet_info->dns_rd = header_dns->rd;
                            packet_info->dns_qr = header_dns->qr;
                    }

//                    payload = (u_char *)(packet + SIZE_ETHERNET + size_header + 8);
//                    size_payload = header_ip->ip_len - size_header - 8;
                }
               else if (next == IPPROTO_TCP)
                {
                    packet_info->ip_protocol = 6;
                    header_tcp = (header_tcp_t*)(where_am_i);
                    size_tcp = header_tcp->doff*4;
                    if (size_tcp < 20) {
                            sprintf(message,"Bad TCP header length (%i bytes)",size_tcp);
                            log_message(message,7);
                            pthread_mutex_lock(&flow_cache_mutex);
                            pcache_list_add(&pcache_free_list, packet_info);
                            pthread_mutex_unlock(&flow_cache_mutex);
                            return;
                    }
                    packet_info->srcport = ntohs(header_tcp->source);
                    packet_info->dstport = ntohs(header_tcp->dest);
                    packet_info->tcp_seqnumber = ntohl(header_tcp->seq);
                    packet_info->tcp_acknumber = ntohl(header_tcp->ack_seq);
                    packet_info->tcp_flags = (header_tcp->urg << 5) | (header_tcp->ack << 4) |
                            (header_tcp->psh << 3) | (header_tcp->rst << 2) |
                            (header_tcp->syn << 1) | header_tcp->fin;
                    packet_info->tcp_window = ntohs(header_tcp->window);
                    packet_info->tcp_urgent_ptr = ntohs(header_tcp->urg_ptr);
                    packet_info->tcp_hlength = size_tcp;

                    packet_info->layer_4_hlength = header_tcp->doff << 2;
                    //printf("Options %d\n",size_tcp - 20);
                    if(size_tcp > 20) {
                    // printf("options najdene pri packete so seq: %d\n", packet_info->tcp_seqnumber);	
                    //TODO processOptions zo starej verzie pridat					
                    //processOptions(packet, packet_info, size_tcp, (int)where_am_i);
                    }

//                    payload = (u_char *)(packet + SIZE_ETHERNET + size_header + size_tcp);
//                    size_payload = header_ip->ip_len - size_header - size_tcp;
                }
                else if (next == IPPROTO_ICMPV6)
                {
                    header_icmp6 = (header_icmp6_t*)(where_am_i);
                    packet_info->ip_protocol = 58;
                    packet_info->icmp6_type =header_icmp6->icmp6_type;
                    packet_info->icmp6_code = header_icmp6->icmp6_code;
                    packet_info->srcport = packet_info->dstport = header_icmp6->icmp6_id;
                    packet_info->tcp_seqnumber = header_icmp6->icmp6_seq;
                    
                    //ICMPv6 header is 4 bytes
//                    payload = (u_char *)(packet + SIZE_ETHERNET + size_header + 4);
//                    size_payload = header_ip->ip_len - size_header - 4;
                }
                else
                {
                    pthread_mutex_lock(&flow_cache_mutex);
                    pcache_list_add(&pcache_free_list, packet_info);
                    pthread_mutex_unlock(&flow_cache_mutex);
                    return;
                }			
            }
            copy_char_array(packet + SIZE_ETHERNET,packet_info->packet_ident,ntohs(header_ip6->ip6_plen)<512?ntohs(header_ip6->ip6_plen):512);
            
            if (doDPI) {
                memset(&fk, 0, sizeof(struct flow_key));
                fk.ip_ver = 6;
                fk.ip_protocol = packet_info->ip_protocol;
                fk.ip6_src_addr = packet_info->ip6_src_addr;
                fk.ip6_dst_addr = packet_info->ip6_dst_addr;
                fk.src_port = packet_info->srcport;
                fk.dst_port = packet_info->dstport;
                key = flow_identificator(&fk);
                pthread_mutex_lock(&dpi_cache_mutex);
                dpi_item = dpi_get_item(packet_info, key);
                if (!dpi_item) {
                    dpi_item = cache_list_get(&dpicache_free_list);
                    if(dpi_item) {
                        dpi_item->flowid = key;
                        hash = hash_func(packet_info->srcport + packet_info->dstport);
                        cache_list_add(&dpicache_hash_list[hash], dpi_item);

                        ndpi_flow = &(dpi_item->ndpi_flow);
                        src = &(dpi_item->src);
                        dst = &(dpi_item->dst);

                        packet_info->dpi_protocol = ndpi_detection_process_packet(t->ndpi_struct, ndpi_flow, (uint8_t *) header_ip6, pkthdr->len - SIZE_ETHERNET, pkthdr->ts.tv_sec / 1000, src, dst);
//                        packet_info->dpi_protocol = 0;
                    } else {
                        packet_info->dpi_protocol = 0;
                        strcpy(message, "DPI Cache Full");			
                        log_message(message, 3);
                    }
                } else {
                    dpi_item->flowid = key;

                    ndpi_flow = &(dpi_item->ndpi_flow);
                    src = &(dpi_item->src);
                    dst = &(dpi_item->dst);

                    packet_info->dpi_protocol = ndpi_detection_process_packet(t->ndpi_struct, ndpi_flow, (uint8_t *) header_ip6, pkthdr->len - SIZE_ETHERNET, pkthdr->ts.tv_sec / 1000, src, dst);
//                    packet_info->dpi_protocol = 0;
                }
                pthread_mutex_unlock(&dpi_cache_mutex);
            } else {
                packet_info->dpi_protocol = 0;
            }
            
            addPacket(packet_info);
  }

}

/*!
* Funkcia na odchytenie druh�ho sign�lu SIGINT. Po tomto sign�le program definit�vne kon��.
*/
void catchInt2(int sig_num){	
        char message[LOG_MESSAGE_SIZE];
	// preregistrovanie signalu na novu obsluhu
	setsignal(SIGINT, SIG_DFL);
	strcpy(message,"Forcing program to stop");	
	log_message(message,3);
	capture_interrupted = 4;
	cache_status();
	// ukoncenie programu
	//cleanShutdown(2,configData);
}
void catchInt(int sig_num){
	int i;	
        char message[LOG_MESSAGE_SIZE];
	// preregistrovanie signalu na novu obsluhu
	setsignal(SIGINT, catchInt2);
	setsignal(SIGTERM, catchInt2);
	fflush(stdout);
	cache_status();
	strcpy(message,"Metering process stopped");
	log_message(message,1);
	strcpy(message,"In case you dont want to wait for exporting process to finish, press CTRL + C again");
	log_message(message,6);
	// ukoncenie cyklu odchytavania
	for(i = 0;i < pct_count;i++)
		if(pcts[i].descr)
			pcap_breakloop(pcts[i].descr);
	//sleep(1);
	capture_interrupted = 1;
	pthread_cond_signal(&pcache_input_wait);

	//debugFlowCache();
	//pthread_exit(NULL);
	//exit(0);
}

/*!
* Callback funkcia pcap kni�nice zabezpe�uj�ca odoslanie d�t v pakete na spracovanie
* \param arguments Argumenty, pred�van� do callback funckie posledn�m argumentom funkcie pcap_loop
* \param pkthdr Smern�k na hlavi�ku paketu obsahuj�cu timestamp, odchyten� d�ku paketu a re�lnu d�ku paketu
* \param packet Smern�k na vlastn� odchyten� d�ta paketu.
* \see pcap_pkthdr
*/
void doCallback(u_char *argument, const struct pcap_pkthdr *pkthdr, const u_char *packet){
	if (!capture_interrupted){
		processPacket((struct packet_capturing_thread *)argument, packet, pkthdr);
		((struct packet_capturing_thread *)argument)->packet_count++;
	}
}

/*!
* Funkcia, ktor� inicializuje odchyt�vanie paketov: nastavuje BPF filter pre pcap kni�nicu, a sp�a vlastn� cyklus odchyt�vania.
*/
void startCapture(){
        char message[LOG_MESSAGE_SIZE];
	// navratova hodnota vlakna 
	int tet_ret, tex_ret, ppt_ret, fat_ret;
        int st_ret, sync_support;
	int i;
	

	wait();
	strcpy(message,"[capture] Starting packet capturing");	
	log_message(message,6);
	// inicializacia random seedu pre vzorkovanie	
	srand(time(NULL));
	// zaregistrovanie signalu pre ukoncenie programu
	setsignal(SIGINT, catchInt);
	setsignal(SIGTERM, catchInt);

	// nacitanie databazy sablon z konfiguracneho suboru
//	getConfigTemplates(configData, tmpl_db);

	// inicializacia pamate tokov
	if(flowCacheInit()){
		exit(1);
	}
	if(readConfigInterfaces(configData, &pcts, &pct_count)){
		strcpy(message,"Error reading interfaces configuration from file");		
		log_message(message,3);
		exit(1);
	}
	// inicializacia mutexu pre pristup do pamate tokov
	pthread_mutex_init(&flow_cache_mutex,NULL);

	pthread_mutex_init(&pcache_input_mutex,NULL);
	pthread_cond_init(&pcache_input_wait,NULL);

        if(!strcmp("true", getConfigElement(configData, "/configuration/synchronization/doSync"))) {
		sync_support = 1;
		strcpy(message,"[capture] Synchronization support: true");
		log_message(message,6);
	} else {
		sync_support = 0;
		strcpy(message,"[capture] Synchronization support: false");
		log_message(message,6);
	}
        
        if(!strcmp("true", getConfigElement(configData, "/configuration/dpi/doDpi"))) {
            doDPI = 1;
            protofile = getConfigElement(configData, "/configuration/dpi/protofile");
            if (!strcmp("NULL", protofile)) {
                free(protofile);
                protofile = NULL;
            }
            strcpy(message,"[capture] Deep packet inspection support: true");
            log_message(message,6);
        } else {
            strcpy(message,"[capture] Deep packet inspection support: false");
            log_message(message,6);
        }
                
	// spustenie vlakna pre casovu expiraciu tokov
	tet_ret = pthread_create(&time_expire_thread, NULL, threadTimeExpire, NULL);

	// spustenie vlakna pre export tokov
	tex_ret = pthread_create(&export_thread, NULL, threadExport, NULL);

	ppt_ret = pthread_create(&packet_processing_thread, NULL, threadPacketProcessing, NULL);

	if(sync_support)	
            st_ret = pthread_create(&sync_thread, NULL, threadSync, NULL);
        
        // spustenie vlakna pre agregaciu tokov
        if((!strcmp("true",getConfigElement(configData,"/configuration/aggregation/doAggregation"))) ||
            (!strcmp("true",getConfigElement(configData,"/configuration/aggregation/automaticAggregation")))){
                fat_ret = pthread_create(&aggregation_thread, NULL, threadFlowAggregation, NULL);
    	}
	for(i=0;i<pct_count;i++){
		pthread_create(&pcts[i].thread, NULL, threadPacketCapturing, (void *)i);
	}

	//cas inicializacie	
	init_time = getCurrentTime(1);


	pthread_join(time_expire_thread,NULL);
	pthread_join(export_thread,NULL);
	pthread_join(packet_processing_thread,NULL);
	if(sync_support)
            pthread_join(sync_thread,NULL);
        
	if((!strcmp("true",getConfigElement(configData,"/configuration/aggregation/doAggregation"))) ||
            (!strcmp("true",getConfigElement(configData,"/configuration/aggregation/automaticAggregation")))){
                pthread_join(aggregation_thread,NULL);
	}
	
	for(i = 0;i < pct_count;i++)
		pthread_join(pcts[i].thread,NULL);
	
	// vypnutie syslog daemona, ak bolo zapnute logovanie na server
	if(syslog_serv_use != NULL)
	{
		int pid = getpid();	
		char beem_pid[10];	
		char shell_command[30] = "pkill -f ";

		sprintf(beem_pid,"%d",pid);
		strcat(shell_command,beem_pid);	
		
		strcpy(message, "[capture] Waiting for the syslog daemon to send all logs and terminate");
		log_message(message,6);			
		sleep(5);

		system(shell_command);
        }	
	
	strcpy(message,"Packet exporting finished\n");	
	log_message(message,6);
}

