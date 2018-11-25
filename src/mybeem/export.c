/*! \file export.c
*  \brief Modul pre export nameran�ch d�t cez protokol IPFIX
* 
*  Modul inicializuje, spravuje a odosiela spr�vy vo form�te IPFIX cez sie�ov� rozhranie do zhroma��ova�a.
*/

/*
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

#include "ipfix_def.h"
#include "ipfix.h"

#include "config.h"
#include "cache.h"
#include "debug.h"
#include "capture.h"


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/*!
* Extern� smern�k na konfigur�ciu
*/
extern xmlDocPtr configData;

//extern struct command_line_arg;

// globalne nastavenia exportera
static ipfix_t           *ipfixh  = NULL;
static ipfix_template_t  *ipfixt  = NULL;
static template_t tmpl[MAXTEMPLATES];
static uint32_t	obs_pointid;
static uint32_t	obs_domainid;	

/*!
* Inicializa�n� funkcia export�ra. Nastavuje v�etky n�le�itosti pre �spe�n� spojenie
*/
void initExport()
{
        char message[LOG_MESSAGE_SIZE];
	char chost[256];
	ipfix_proto_t  protocol = IPFIX_PROTO_UDP;
	int port= IPFIX_PORTNO;
	int version = IPFIX_VERSION;
	int i;
	ipfix_field_type_t ie;
	int refreshTmpl;
	int reconnFreq;
	int connTimeout;
	char template[10];
	char doMediation[8];


	// nastav nakonfigurovane parametre

	strcpy(doMediation,getConfigElement(configData,"/configuration/mediator/doMediation"));

	if(strcmp("true",doMediation) == 0)
	{
		if(strlen(config_option.host_IP) != 0)
			strcpy(chost,config_option.host_IP);
		else	
			strcpy(chost, getConfigElement(configData,"/configuration/mediator/host"));

		if(strlen(config_option.port_number) != 0)
			port = atoi(config_option.port_number);
		else	
			port = atoi(getConfigElement(configData,"/configuration/mediator/port"));

		version = atoi(getConfigElement(configData,"/configuration/mediator/version"));

		if(strlen(config_option.port_number) != 0)
		{	
			if(strcmp("UDP",config_option.protocol_type) == 0) protocol = IPFIX_PROTO_UDP;
			if(strcmp("TCP",config_option.protocol_type) == 0) protocol = IPFIX_PROTO_TCP;
			if(strcmp("SCTP",config_option.protocol_type) == 0) protocol = IPFIX_PROTO_SCTP;
		}
		else
		{	
			if (!strcmp("UDP", getConfigElement(configData,"/configuration/mediator/protocol"))) protocol = IPFIX_PROTO_UDP;
			if (!strcmp("TCP", getConfigElement(configData,"/configuration/mediator/protocol"))) protocol = IPFIX_PROTO_TCP;
			if (!strcmp("SCTP", getConfigElement(configData,"/configuration/mediator/protocol"))) protocol = IPFIX_PROTO_SCTP;
		}

		refreshTmpl = atoi(getConfigElement(configData,"/configuration/mediator/refreshTemplateTime"));
		reconnFreq = atoi(getConfigElement(configData,"/configuration/mediator/reconnectFrequency"));
		connTimeout = atoi(getConfigElement(configData,"/configuration/mediator/connectionTimeout"));
	}
	else
	{
		if(strlen(config_option.host_IP) != 0)
			strcpy(chost,config_option.host_IP);
		else	
			strcpy(chost, getConfigElement(configData,"/configuration/collector/host"));
		
		if(strlen(config_option.port_number) != 0)
			port = atoi(config_option.port_number);
		else	
			port = atoi(getConfigElement(configData,"/configuration/collector/port"));
		
		version = atoi(getConfigElement(configData,"/configuration/collector/version"));
	
		if(strlen(config_option.port_number) != 0)
		{	
			if(strcmp("UDP",config_option.protocol_type) == 0) protocol = IPFIX_PROTO_UDP;
			if(strcmp("TCP",config_option.protocol_type) == 0) protocol = IPFIX_PROTO_TCP;
			if(strcmp("SCTP",config_option.protocol_type) == 0) protocol = IPFIX_PROTO_SCTP;
		}
		else
		{	
			if (!strcmp("UDP", getConfigElement(configData,"/configuration/collector/protocol"))) protocol = IPFIX_PROTO_UDP;
			if (!strcmp("TCP", getConfigElement(configData,"/configuration/collector/protocol"))) protocol = IPFIX_PROTO_TCP;
			if (!strcmp("SCTP", getConfigElement(configData,"/configuration/collector/protocol"))) protocol = IPFIX_PROTO_SCTP;
		}

		refreshTmpl = atoi(getConfigElement(configData,"/configuration/collector/refreshTemplateTime"));
		reconnFreq = atoi(getConfigElement(configData,"/configuration/collector/reconnectFrequency"));
		connTimeout = atoi(getConfigElement(configData,"/configuration/collector/connectionTimeout"));
	}

	if(config_option.obs_pointid == 0)
		 obs_pointid = atol(getConfigElement(configData,"/configuration/observationPointID"));
	else
		obs_pointid = config_option.obs_pointid;
	
	if(config_option.obs_domainid == 0)
		 obs_domainid = atol(getConfigElement(configData,"/configuration/observationDomainID"));
	else
		obs_domainid = config_option.obs_domainid;
	
	// inicializuj modul pre ipfix export
	if ( ipfix_init() <0) {
		sprintf(message,"Cannot init ipfix module: %s", strerror(errno) );
		log_message(message,3);
		cleanShutdown(2,configData);
	}

	// otvor ipfix export
	if ( ipfix_open( &ipfixh, obs_domainid, version ) <0 ) {
		sprintf(message,"Ipfix_open() failed: %s", strerror(errno) );
		log_message(message,3);
		cleanShutdown(2,configData);
	}

        // nastav nakonfiguraovny mediator
	if(strcmp("true",doMediation) == 0)
	{
		sprintf(message,"Adding mediator: %s:%d", chost, port);
		log_message(message,6);
	}
	else
	{
		// nastav nakonfiguraovny zhromazdovac
		sprintf(message,"Adding collector: %s:%d", chost, port);
		log_message(message,6);
	}

	if ( ipfix_add_collector( ipfixh, chost, port, protocol, refreshTmpl, reconnFreq, connTimeout ) <0 ) {
		sprintf(message,"Ipfix_new_template() failed: %s", strerror(errno) );
		log_message(message,3);
		cleanShutdown(2,configData);
	}

	getConfigTemplates(configData, tmpl, version);
        if (version == IPFIX_VERSION_NF5) {
            sprintf(message,"[Flow exporting] NetFlow v5 is in use, last 3 header fields are set to value 1");
            log_message(message,4);
            updateIeLenghts();
        } else if (version == IPFIX_VERSION_NF9) {
			sprintf(message,"[Flow exporting] NetFlow v9 is in use, enterprise information elements are not exported");
            log_message(message,4);
		}
	// TODO: implementovat podporu viacerych sablon naraz
        
	// nastav nakonfigurovanu sablonu
	if ( ipfix_new_data_template( ipfixh, &ipfixt, tmpl[0].field_count, tmpl[0].template_number ) < 0 )
	{
		sprintf(message,"Ipfix_new_template() failed: %s", strerror(errno) );
		log_message(message,3);
		cleanShutdown(2,configData);
	}
	strcpy(message,"Adding template fields:");
	for (i=0 ; i < tmpl[0].field_count; i++ )  
	{
		ie = findIEField(tmpl[0].fields[i].ie_number);
		//DMSG("Adding template field #%d (eno:%d, length:%d)",tmpl[0].fields[i].ie_number,tmpl[0].fields[i].enterprise,ie.length);
		sprintf(template," %i", tmpl[0].fields[i].ie_number);
		strcat(message,template);		
		if(tmpl[0].fields[i].enterprise != 0)
		{
			sprintf(template,"[%i]", tmpl[0].fields[i].enterprise);
			strcat(message,template);
		}
		// TODO: pridat pre enterprise cisla = 1 aj zistovanie dlzky z configu
		if ( ipfix_add_field( ipfixh, ipfixt, tmpl[0].fields[i].enterprise, tmpl[0].fields[i].ie_number, ie.length ) < 0 ) 
		{
			sprintf(message,"Ipfix_add_field() failed: %s", strerror(errno) );
			log_message(message,3);
			cleanShutdown(2,configData);
		}
	}
	log_message(message,6);
	//printf("\n");
}	

/*!
* Deinicializa�n� funkcia export�ra. Nastavuje v�etky n�le�itosti pre �spe�n� ukon�enie spojenia
*/
void closeExport() 
{
	// uprac	
	ipfix_delete_template( ipfixh, ipfixt );
	ipfix_close( ipfixh );
	ipfix_cleanup();
}	

/*!
* Eportn� funkcia. Napln� IPFIX spr�vu konkr�tnymi �dajmi a odo�le ju po sie�ovom transporte zhroma��ova�u
* \param flow Tok, ktor� sa bude exportova�
*/
int exportFlow (struct cache_item *flow)
{
        char message[LOG_MESSAGE_SIZE];
        uint64_t ef_s = getCurrentTime(3);
    
	char buf[IPFIX_DEFAULT_BUFLEN];
	int offset = 0;
	ipfix_field_type_t ie;
	int i, tmp;
	memset(buf,'\0',IPFIX_DEFAULT_BUFLEN);
	//premenna pre ulozenie casov v roznych mierach
	uint64_t seconds;
	//premenna pre ulozenie relativnych casov od poslednej (re)inicializacie IPFIX zariadenia
	uint32_t sys_init_seconds;
	uint16_t temp16;
	uint8_t temp8;
	unsigned char *ip, byte, appId_nbo[4];

	// naplnime buffer podla sablony
	for (i=0 ; i < tmpl[0].field_count; i++ )  
	{
		ie = findIEField(tmpl[0].fields[i].ie_number);
		switch (tmpl[0].fields[i].ie_number)
		{
#ifdef IPFIX_PACKETDELTACOUNT
		case IPFIX_FT_PACKETDELTACOUNT:
			if(flow->expiration_reason == 2) {
				flow->packet_delta_count = flow->packet_total_count - flow->packet_delta_count;
			} else {
				flow->packet_delta_count = 0;
			}
			memcpy(buf+offset , &flow->packet_delta_count , ie.length);
			break;
#endif
#ifdef IPFIX_OCTETDELTACOUNT
		case IPFIX_FT_OCTETDELTACOUNT:
			if(flow->expiration_reason == 2) {
				flow->octet_delta_count = flow->octet_total_count - flow->octet_delta_count;
			} else {
				flow->packet_delta_count = 0;
			}
			memcpy(buf+offset , &flow->octet_delta_count , ie.length);
			break;
#endif
#ifdef IPFIX_PACKETTOTALCOUNT                    
		case IPFIX_FT_PACKETTOTALCOUNT:
			memcpy(buf+offset , &flow->packet_total_count , ie.length);
			break;
#endif
#ifdef IPFIX_OCTETTOTALCOUNT
		case IPFIX_FT_OCTETTOTALCOUNT:
			memcpy(buf+offset , &flow->octet_total_count , ie.length);
			break;
#endif                        
#ifdef IPFIX_OCTETTOTALSUMOFSQUARES
		case IPFIX_FT_OCTETTOTALSUMOFSQUARES:
			memcpy(buf+offset , &flow->octet_total_sum_of_squares , ie.length);
			break;
#endif

//informacny model tento IE neobsahuje			
//			//IE popisujuci zaciatok toku v sekundach
//		case IPFIX_FT_FLOWSTARTSECONDS:
//			seconds = flow->flow_start_nano_seconds / 1000000000;
//			memcpy(buf+offset , &seconds, ie.length);
//			break;

//informacny model tento IE neobsahuje			
//			//IE popisujuci koniec toku v sekundach
//		case IPFIX_FT_FLOWENDSECONDS:
//			seconds = flow->flow_end_nano_seconds / 1000000000;
//			memcpy(buf+offset , &seconds, ie.length);  		               				
//			break;

#ifdef IPFIX_FLOWSTARTMILLISECONDS
			//IE popisujuci zaciatok toku v milisekundach
		case IPFIX_FT_FLOWSTARTMILLISECONDS:
			seconds = flow->flow_start_nano_seconds / 1000000;
			memcpy(buf+offset , &seconds, ie.length);  			       				
			break;
#endif
#ifdef IPFIX_FLOWENDMILLISECONDS
			//IE popisujuci koniec toku v milisekundach
		case IPFIX_FT_FLOWENDMILLISECONDS:
			seconds = flow->flow_end_nano_seconds / 1000000;
			memcpy(buf+offset , &seconds, ie.length);  			       				
			break;
#endif
#ifdef IPFIX_FLOWSTARTDELTAMICROSECONDS
		case IPFIX_FT_FLOWSTARTDELTAMICROSECONDS:
			sys_init_seconds = getCurrentTime(2) - (flow->flow_start_nano_seconds / 1000);	
			//printf("delta start %I32u\n", sys_init_seconds);
			memcpy(buf+offset, &sys_init_seconds, ie.length);
			break;
#endif
#ifdef IPFIX_FLOWSTARTMICROSECONDS
			//IE popisujuci zaciatok toku v microsekundach
		case IPFIX_FT_FLOWSTARTMICROSECONDS:
			seconds = flow->flow_start_nano_seconds / 1000;
			memcpy(buf+offset , &seconds, ie.length); 			
			break;
#endif
#ifdef IPFIX_FLOWSTARTDELTAMICROSECONDS                        
			//element rozdielu casu v hlavicke a casu prichody posledneho packetu
		case IPFIX_FT_FLOWENDDELTAMICROSECONDS:
			sys_init_seconds = getCurrentTime(2) - (flow->flow_end_nano_seconds / 1000);	
			//printf("delta end %I32u\n", sys_init_seconds);
			memcpy(buf+offset, &sys_init_seconds, ie.length);
			break;
#endif
#ifdef IPFIX_FLOWENDMICROSECONDS
			//IE popisujuci koniec toku v microsekundach
		case IPFIX_FT_FLOWENDMICROSECONDS:
			seconds = flow->flow_end_nano_seconds / 1000;
			memcpy(buf+offset , &seconds, ie.length);                          
			break;
#endif
#ifdef IPFIX_FLOWSTARTNANOSECONDS
		case IPFIX_FT_FLOWSTARTNANOSECONDS:
			memcpy(buf+offset , &flow->flow_start_nano_seconds , ie.length);
			break;
#endif
#ifdef IPFIX_FLOWENDNANOSECONDS
		case IPFIX_FT_FLOWENDNANOSECONDS:
			memcpy(buf+offset , &flow->flow_end_nano_seconds , ie.length);
			break;
#endif
#ifdef IPFIX_FLOWSTARTAFTEREXPORT
		case IPFIX_FT_FLOWSTARTAFTEREXPORT:
			memcpy(buf+offset , &flow->flow_start_after_export , ie.length);
			break;
#endif
#ifdef IPFIX_FLOWDURATIONMILLISECONDS
			//IE pre rozdielu casu prichodu posledneho a prveho packetu do toku
		case IPFIX_FT_FLOWDURATIONMILLISECONDS:
			seconds = (flow->flow_end_nano_seconds - flow->flow_start_nano_seconds) / 1000000;
			memcpy(buf+offset , &seconds, ie.length);                          
			break;
#endif
#ifdef IPFIX_FLOWDURATIONMICROSECONDS
			//IE pre rozdielu casu prichodu posledneho a prveho packetu do toku
		case IPFIX_FT_FLOWDURATIONMICROSECONDS:
			seconds = (flow->flow_end_nano_seconds - flow->flow_start_nano_seconds) / 1000;			
			memcpy(buf+offset , &seconds, ie.length);                         
			break;
#endif
#ifdef IPFIX_SYSTEMINITTIMEMILLISECONDS
			//IE pre export casu poslednej (re)inicializacie zariadenia		
		case IPFIX_FT_SYSTEMINITTIMEMILLISECONDS:
			memcpy(buf+offset, &init_time, ie.length);
			break;
#endif
#ifdef IPFIX_FLOWENDSYSUPTIME
			//cas od (re)inicializacie ipfix zariadenia po ukoncenie toku		
		case IPFIX_FT_FLOWENDSYSUPTIME:			
			seconds = flow->flow_end_nano_seconds / 1000000;
			sys_init_seconds = (uint32_t) (seconds - init_time);			
			memcpy(buf+offset, &sys_init_seconds, ie.length);
			break;
#endif
#ifdef IPFIX_FLOWSTARTSYSUPTIME
			//cas od (re)inicializacie ipfix zariadenia po zacatie toku
		case IPFIX_FT_FLOWSTARTSYSUPTIME:
			seconds = flow->flow_start_nano_seconds / 1000000;
			sys_init_seconds = (uint32_t) (seconds - init_time);
			memcpy(buf+offset, &sys_init_seconds, ie.length);
			break;
#endif
#ifdef IPFIX_FLOWACTIVETIMEOUT
		case IPFIX_FT_FLOWACTIVETIMEOUT:
			memcpy(buf+offset, &active_timeout, ie.length);
			break;
#endif
#ifdef IPFIX_FLOWIDLETIMEOUT
		case IPFIX_FT_FLOWINACTIVETIMEOUT:
			//printf("protocol is: %X and ip version is: %X, igm is %X\n", flow->flow_key.ip_protocol, flow->flow_key.ip_ver, IPPROTO_IGMP);
			memcpy(buf+offset, &passive_timeout, ie.length);
			break;
#endif
#ifdef IPFIX_FLOWENDREASON
		case IPFIX_FT_FLOWENDREASON:
			//TODO implementacia dovodu ukoncenia toku, nieco tu uz je, ale asi to nie je vsetko
			memcpy(buf+offset, &flow->expiration_reason, ie.length);
			break;
#endif
#ifdef IPFIX_ICMPTYPECODEIPV4
			//icmptypecodeipv4		
		case IPFIX_FT_ICMPTYPECODEIPV4:
			//printf("icmptypecodeipv4: %I16u\n", flow->icmpTypeIPv4 * 256 + flow->icmpCodeIPv4);			
			temp16 = (flow->icmpTypeIPv4 << 8) | flow->icmpCodeIPv4;		
			memcpy(buf+offset, &temp16, ie.length);
			break;
#endif
#ifdef IPFIX_IGMPTYPE
			//typ igmp messageu
		case IPFIX_FT_IGMPTYPE:
			memcpy(buf+offset, &flow->icmpTypeIPv4, ie.length);
			break;
#endif

			//velkost tcp hlavicky
//v informacnom modeli nie je definovany
//		case IPFIX_FT_TCPHEADERLENGTH:
//			//printf("velkost tcp hlavicky: %I8u\n", flow->layer_4_hlength_tcp);
//			memcpy(buf+offset, &flow->layer_4_hlength_tcp, ie.length);
//			break;

			//velkost udp hlavicky
//v informacnom modeli nie je definovany
//		case IPFIX_FT_UDPMESSAGELENGTH:
//			//printf("velkost udp hlavicky: %I16u\n", flow->layer_4_hlength_udp);
//			memcpy(buf+offset, &flow->layer_4_hlength_udp, ie.length);
//			break;

#ifdef IPFIX_TCPURGENTPOINTER                        
			//hodnota urgent pointera v tcp messagei
		case IPFIX_FT_TCPURGENTPOINTER:			
			//printf("urgent pointer: %I16u\n",flow->tcpUrgentPtr);
			memcpy(buf+offset, &flow->tcpUrgentPtr, ie.length);
			break;
#endif

//Nedefinovany IE                        
//			//zdrojovy udp port
//		case IPFIX_FT_UDPSOURCEPORT:			
//			if(flow->flow_key.ip_protocol == IPPROTO_UDP)			
//				memcpy(buf+offset , &flow->flow_key.src_port , ie.length);
//			else
//				memset(buf+offset , 0 , ie.length);
//			break;

//Nedefinovany IE                        
//			//cielovy udp port
//		case IPFIX_FT_UDPDESTINATIONPORT:
//			if(flow->flow_key.ip_protocol == IPPROTO_UDP)			
//				memcpy(buf+offset , &flow->flow_key.dst_port , ie.length);
//			else
//				memset(buf+offset , 0 , ie.length);			
//			break;

//Nedefinovany IE                                                
//			//zdrojovy tcp port
//		case IPFIX_FT_TCPSOURCEPORT:
//			if(flow->flow_key.ip_protocol == IPPROTO_TCP)			
//				memcpy(buf+offset , &flow->flow_key.src_port , ie.length);
//			else
//				memset(buf+offset , 0 , ie.length);
//			break;

//Nedefinovany IE                                                
//			//cielovy tcp port
//		case IPFIX_FT_TCPDESTINATIONPORT:
//			if(flow->flow_key.ip_protocol == IPPROTO_TCP)			
//				memcpy(buf+offset , &flow->flow_key.dst_port , ie.length);
//			else
//				memset(buf+offset , 0 , ie.length);
//			break;

#ifdef IPFIX_TCPSEQUENCENUMBER
			//tcp sequence number prveho packetu
		case IPFIX_FT_TCPSEQUENCENUMBER:
			//printf("sequence: %I32u\n", flow->tcpSeqNumber);
			memcpy(buf+offset , &flow->tcpSeqNumber , ie.length);
			break;	
#endif
#ifdef IPFIX_TCPACKNOWLEDGEMENTNUMBER
			//tcp acknowledgement number prveho packetu
		case IPFIX_FT_TCPACKNOWLEDGEMENTNUMBER:
			//printf("acknowledgement: %I32u\n", flow->tcpAckNumber);
			memcpy(buf+offset , &flow->tcpAckNumber , ie.length);
			break;	
#endif
#ifdef IPFIX_TCPWINDOWSIZE
			//tcp window size
		case IPFIX_FT_TCPWINDOWSIZE:
			//printf("windowSize: %I16u\n", flow->tcpWindowSize);
			memcpy(buf+offset , &flow->tcpWindowSize , ie.length);
			break;					
#endif
#ifdef IPFIX_SOURCEIPV4ADDRESS
		case IPFIX_FT_SOURCEIPV4ADDRESS:
			memcpy(buf+offset , &flow->flow_key.ip_src_addr , ie.length);
			break;
#endif
#ifdef IPFIX_IPTOTALLENGTH
			//total length of ip packet (ipv4 only) TODO IPV6
		case IPFIX_FT_IPTOTALLENGTH:
			memcpy(buf+offset, &flow->layer_3_length_fst, ie.length);
			break;
#endif
#ifdef IPFIX_TOTALLENGTHIPV4
			// total length ipv4
		case IPFIX_FT_TOTALLENGTHIPV4:
			//printf("total length of ipv4 packet: %lld\n", flow->layer_3_length_fst);
			memcpy(buf+offset, &flow->layer_3_length_fst, ie.length);
			break;
#endif
#ifdef IPFIX_IPV4IHL
			// internet header length in units of 4 bytes		
		case IPFIX_FT_INTERNETHEADERLENGTHIPV4:
			//printf("internet header length: %I8u\n", flow->ihl);
			memcpy(buf+offset, &flow->ihl, ie.length);
			break;
#endif
#ifdef IPFIX_IPHEADERLENGTH
			// header length in bytes
		case IPFIX_FT_IPHEADERLENGTH:
			temp8 = flow->ihl << 2;
			//			seconds = flow->ihl << 2;		
			//printf("ip header length: %I8u\n", temp8);
			memcpy(buf+offset, &temp8, ie.length); 
			//			printf("vypis originalneho buffera: \n");
			//			vypisbuf(buf, IPFIX_DEFAULT_BUFLEN, offset);
			break;
#endif
#ifdef IPFIX_ISMULTICAST
			//is multicast TODO IPV6
		case IPFIX_FT_ISMULTICAST:
			ip = (unsigned char *) &flow->flow_key.ip_dst_addr;
			//printf("prvy oktet ipcky: %d\n", ip[0]);
			if(ip[0] >= 224 && ip[0] <= 239) {
				//printf("je to multicast\n");			
				temp8 = 0x80;
				memcpy(buf+offset, &temp8, ie.length);
			}
			else {
				//printf("neni to multicast\n");
				memset(buf+offset, 0, ie.length);
			}			
			break;
#endif
#ifdef IPFIX_FRAGMENTIDENTIFICATION
			// fragment identification
		case IPFIX_FT_IDENTIFICATIONIPV4:
			//printf("fragment id: %I32u\n", flow->fragmentID);
			memcpy(buf+offset , &flow->fragmentID , ie.length);
			break;
#endif
#ifdef IPFIX_FRAGMENTFLAGS
			// fragment flags
		case IPFIX_FT_FRAGMENTFLAGSIPV4:					
			temp8 = flow->fragmentOff >> 8;
			//printf("fragment flags: %d\n", temp8);
			memcpy(buf+offset, &temp8, ie.length);
			break;	
#endif
#ifdef IPFIX_FRAGMENTOFFSET
			// fragment offset
		case IPFIX_FT_FRAGMENTOFFSETIPV4:
			//printf("fragment offset: %I16u\n", flow->fragmentOff);
			memcpy(buf+offset, &flow->fragmentOff, ie.length);
			break;
#endif
#ifdef IPFIX_IPTTL
			// ip ttl
		case IPFIX_FT_IPTIMETOLIVE:
			//printf("time to live: %I8u\n", flow->ttl);
			memcpy(buf+offset, &flow->ttl, ie.length);
			break;
#endif
#ifdef IPFIX_IPDIFFSERVCODEPOINT
			// differentiated services code point (DSCP)
		case IPFIX_FT_IPDIFFSERVCODEPOINT:
			temp8 = flow->ToS >> 2;
			//printf("DSCP: %I8u\n", temp8);
			memcpy(buf+offset, &temp8, ie.length);
			break;
#endif
#ifdef IPFIX_IPPRECEDENCE
			// ip precedence
		case IPFIX_FT_IPPRECEDENCE:
			temp8 = flow->ToS >> 5;
			//printf("ip precedence: %I8u\n", temp8);
			memcpy(buf+offset, &temp8, ie.length);
			break;
#endif
#ifdef IPFIX_IPVERSION
			// ip version
		case IPFIX_FT_IPVERSION:
			//printf("ip version: %I8u\n", flow->flow_key.ip_ver);
			memcpy(buf+offset, &flow->flow_key.ip_ver, ie.length);
			break;
#endif
#ifdef IPFIX_DESTINATIONIPV4ADDRESS
		case IPFIX_FT_DESTINATIONIPV4ADDRESS:
			memcpy(buf+offset , &flow->flow_key.ip_dst_addr , ie.length);
			break;
#endif
#ifdef IPFIX_SOURCETRANSPORTPORT
		case IPFIX_FT_SOURCETRANSPORTPORT:
			memcpy(buf+offset , &flow->flow_key.src_port , ie.length);
			break;
#endif
#ifdef IPFIX_DESTINATIONTRANSPORTPORT
		case IPFIX_FT_DESTINATIONTRANSPORTPORT:
			memcpy(buf+offset , &flow->flow_key.dst_port , ie.length);
			break;
#endif
#ifdef IPFIX_ROUNDTRIPTIMENANOSECONDS
		case IPFIX_FT_ROUNDTRIPTIMENANOSECONDS:		//ien=240
			flow->rtt_avg = flow->rtt_avg_fwd + flow->rtt_avg_bwd;
			memcpy(buf+offset , &flow->rtt_avg, ie.length);
			break;
#endif
#ifdef IPFIX_PACKETPAIRSTOTALCOUNT
		case IPFIX_FT_RTTPAIRSTOTALCOUNT:	//ien=241
			flow->rtt_cnt = flow->rtt_cnt_fwd + flow->rtt_cnt_bwd;
			memcpy(buf+offset , &flow->rtt_cnt, ie.length);
			break;
#endif
#ifdef IPFIX_OBSERVATIONPOINTID
		case IPFIX_FT_OBSERVATIONPOINTID:
			memcpy(buf+offset, &obs_pointid, ie.length);			
			break;
#endif
#ifdef IPFIX_OBSERVATIONDOMAINID
		case IPFIX_FT_OBSERVATIONDOMAINID:
			memcpy(buf+offset, &obs_domainid, ie.length);		
			break;
#endif
#ifdef IPFIX_PROTOCOLIDENTIFIER
		case IPFIX_FT_PROTOCOLIDENTIFIER:
			memcpy(buf+offset, &flow->flow_key.ip_protocol, ie.length);
			break;
#endif
#ifdef IPFIX_ICMPTYPEIPV4
		case IPFIX_FT_ICMPTYPEIPV4:
			memcpy(buf+offset, &flow->icmpTypeIPv4, ie.length);
			break;
#endif
#ifdef IPFIX_ICMPCODEIPV4
		case IPFIX_FT_ICMPCODEIPV4:
			memcpy(buf+offset, &flow->icmpCodeIPv4, ie.length);
			break;
#endif
#ifdef IPFIX_TCPSYNTOTALCOUNT
		case IPFIX_FT_TCPSYNTOTALCOUNT:
			memcpy(buf+offset, &flow->tcpSynTotalCount, ie.length);
			break;
#endif
#ifdef IPFIX_TCPFINTOTALCOUNT
		case IPFIX_FT_TCPFINTOTALCOUNT:
			memcpy(buf+offset, &flow->tcpFinTotalCount, ie.length);
			break;
#endif
#ifdef IPFIX_TCPRSTTOTALCOUNT                        
		case IPFIX_FT_TCPRSTTOTALCOUNT:
			memcpy(buf+offset, &flow->tcpRstTotalCount, ie.length);
			break;
#endif
#ifdef IPFIX_TCPPSHTOTALCOUNT                        
		case IPFIX_FT_TCPPSHTOTALCOUNT:
			memcpy(buf+offset, &flow->tcpPshTotalCount, ie.length);
			break;
#endif
#ifdef IPFIX_TCPACKTOTALCOUNT                        
		case IPFIX_FT_TCPACKTOTALCOUNT:
			memcpy(buf+offset, &flow->tcpAckTotalCount, ie.length);
			break;
#endif
#ifdef IPFIX_TCPURGTOTALCOUNT                        
		case IPFIX_FT_TCPURGTOTALCOUNT:
			memcpy(buf+offset, &flow->tcpUrgTotalCount, ie.length);
			break;
#endif
#ifdef IPFIX_POSTIPCLASSOFSERVICE                        
		case IPFIX_FT_POSTCLASSOFSERVICEIPV4:
#endif
#ifdef IPFIX_IPCLASSOFSERVICE                    
		case IPFIX_FT_CLASSOFSERVICEIPV4:			
			memcpy(buf+offset, &flow->ToS, ie.length);
			break;
#endif
#ifdef IPFIX_FIRSTPACKETID                        
		case IPFIX_FT_FIRSTPACKETID:
			memcpy(buf+offset, flow->firstPacketID, ie.length);
			break;
#endif
#ifdef IPFIX_LASTPACKETID                        
		case IPFIX_FT_LASTPACKETID:
			memcpy(buf+offset, flow->lastPacketID, ie.length);
			break;
#endif
#ifdef IPFIX_FLOWID                        
		case IPFIX_FT_FLOWID:
			memcpy(buf+offset, &flow->flow_id, ie.length);
			// printf("==================================================================\n");	
			// sprintf(message,"Flow_ID value: %llu",flow->flow_id);
			// log_message(message,6);
			break;
#endif
#ifdef IPFIX_SOURCEIPV6ADDRESS                        
		case IPFIX_FT_SOURCEIPV6ADDRESS:
			  memcpy(buf+offset , &flow->flow_key.ip6_src_addr , ie.length);
			  break;
#endif
#ifdef IPFIX_DESTINATIONIPV6ADDRESS                          
		case IPFIX_FT_DESTINATIONIPV6ADDRESS:
			  memcpy(buf+offset, &flow->flow_key.ip6_dst_addr, ie.length);
			  break;
#endif
#ifdef IPFIX_ICMPTYPEIPV6                          
		case IPFIX_FT_ICMPTYPEIPV6:
			  memcpy(buf+offset, &flow->icmpTypeIPv6, ie.length);
			  break;
#endif
#ifdef IPFIX_ICMPCODEIPV6                          
		case IPFIX_FT_ICMPCODEIPV6:
			  memcpy(buf+offset, &flow->icmpCodeIPv6, ie.length);
			  break;
#endif
#ifdef IPFIX_ICMPTYPECODEIPV6                          
	    	case IPFIX_FT_ICMPTYPECODEIPV6:
			   temp16 = (flow->icmpTypeIPv6 << 8) | flow->icmpCodeIPv6;
		       memcpy(buf+offset, &temp16, ie.length);
		       break;
#endif
#ifdef IPFIX_NEXTHEADERIPV6                       
		case IPFIX_FT_NEXTHEADERIPV6:
		       memcpy(buf+offset, &flow->ipv6NextHeader, ie.length);
		       break;
#endif
#ifdef IPFIX_FLOWLABELIPV6                       
		case IPFIX_FT_FLOWLABELIPV6:
			memcpy(buf+offset, &flow->ip6_fl, ie.length);
			break;
#endif
#ifdef IPFIX_EXPORTERIPV4ADDRESS                        
		case IPFIX_FT_EXPORTERIPV4ADDRESS:
			memcpy(buf+offset, &flow->exporter_ipv4, ie.length);
			break;
#endif
#ifdef IPFIX_EXPORTERIPV6ADDRESS                        
		case IPFIX_FT_EXPORTERIPV6ADDRESS:
			memcpy(buf+offset, &flow->exporter_ipv6, ie.length);
			break;
#endif
#ifdef IPFIX_FLOWKEYINDICATOR                        
		case IPFIX_FT_FLOWKEYINDICATOR:
			memcpy(buf+offset, &flow->flowKey_in, ie.length);
			break;
#endif
#ifdef IPFIX_IPPAYLOADLENGTH                        
		case IPFIX_FT_IPPAYLOADLENGTH:
			memcpy(buf+offset, &flow->ip_pl, ie.length);
			break;
#endif
#ifdef IPFIX_COLLECTORIPV4ADDRESS                        
		case IPFIX_FT_COLLECTORIPV4ADDRESS:
			memcpy(buf+offset, &flow->collector_ipv4, ie.length);
			break;
#endif
#ifdef IPFIX_COLLECTORIPV6ADDRESS                        
		case IPFIX_FT_COLLECTORIPV6ADDRESS:
			memcpy(buf+offset, &flow->collector_ipv6, ie.length);
			break;
#endif
#ifdef IPFIX_EXPORTINTERFACE                        
		case IPFIX_FT_EXPORTINTERFACE:
			memcpy(buf+offset, &flow->export_i, ie.length);
			break;
#endif
#ifdef IPFIX_EXPORTPROTOCOLVERSION                        
		case IPFIX_FT_EXPORTPROTOCOLVERSION:
			memcpy(buf+offset, &flow->export_protVer, ie.length);
			break;
#endif
#ifdef IPFIX_EXPORTTRANSPORTPROTOCOL                        
		case IPFIX_FT_EXPORTTRANSPORTPROTOCOL:
			memcpy(buf+offset, &flow->export_protocol, ie.length);
			break;
#endif
#ifdef IPFIX_COLLECTORTRANSPORTPORT                        
		case IPFIX_FT_COLLECTORTRANSPORTPORT:
			memcpy(buf+offset, &flow->collector_port, ie.length);
			break;
#endif
#ifdef IPFIX_EXPORTERTRANSPORTPORT                        
		case IPFIX_FT_EXPORTERTRANSPORTPORT:
			memcpy(buf+offset, &flow->exporter_port, ie.length);
			break;
#endif
#ifdef IPFIX_DROPPEDPACKETDELTACOUNT                        
		case IPFIX_FT_DROPPEDPACKETDELTACOUNT:
			memcpy(buf+offset, &flow->dropped_packet_delta, ie.length);
			break;
#endif
#ifdef IPFIX_DROPPEDOCTETDELTACOUNT                        
		case IPFIX_FT_DROPPEDOCTETDELTACOUNT:
			memcpy(buf+offset, &flow->dropped_octet_delta, ie.length);
			break;
#endif
#ifdef IPFIX_ORIGINALFLOWSPRESENT                        
		case IPFIX_FT_ORIGINALFLOWSPRESENT:
			memcpy(buf+offset, &flow->originalFlowsPresent, ie.length);
			break;
#endif
#ifdef IPFIX_ORIGINALFLOWSINITIATED                        
		case IPFIX_FT_ORIGINALFLOWSINITIATED:
			memcpy(buf+offset, &flow->originalFlowsInitiated, ie.length);
			break;
#endif 
#ifdef IPFIX_ORIGINALFLOWSCOMPLETED                        
		case IPFIX_FT_ORIGINALFLOWSCOMPLETED:
			memcpy(buf+offset, &flow->originalFlowsCompleted, ie.length);
			break;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFSOURCEIPADDRESS                        
		case IPFIX_FT_DISTINCTCOUNTOFSOURCEIPADDRESS:
			memcpy(buf+offset, &flow->distCntOfSrcIPAddr, ie.length);
			break;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFDESTINATIONIPADDRESS                        
		case IPFIX_FT_DISTINCTCOUNTOFDESTINATIONIPADDRESS:
			memcpy(buf+offset, &flow->distCntOfDstIPAddr, ie.length);
			break;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFSOURCEIPV4ADDRESS                        
		case IPFIX_FT_DISTINCTCOUNTOFSOURCEIPV4ADDRESS:
			memcpy(buf+offset, &flow->distCntOfSrcIPv4Addr, ie.length);
			break;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFDESTINATIONIPV4ADDRESS                        
		case IPFIX_FT_DISTINCTCOUNTOFDESTINATIONIPV4ADDRESS:
			memcpy(buf+offset, &flow->distCntOfDstIPv4Addr, ie.length);
			break;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFSOURCEIPV6ADDRESS                        
		case IPFIX_FT_DISTINCTCOUNTOFSOURCEIPV6ADDRESS:
			memcpy(buf+offset, &flow->distCntOfSrcIPv6Addr, ie.length);
			break;
#endif
#ifdef IPFIX_DISTINCTCOUNTOFDESTINATIONIPV6ADDRESS                        
		case IPFIX_FT_DISTINCTCOUNTOFDESTINATIONIPV6ADDRESS:
			memcpy(buf+offset, &flow->distCntOfDstIPv6Addr, ie.length);
			break;
#endif
#ifdef IPFIX_SOURCEMACADDRESS
		case IPFIX_FT_SOURCEMACADDRESS:
			memcpy(buf+offset, &flow->source_mac, ie.length);
			break;
#endif
#ifdef IPFIX_DESTINATIONMACADDRESS
		case IPFIX_FT_DESTINATIONMACADDRESS:
			memcpy(buf+offset, &flow->destination_mac, ie.length);
			break;
#endif 
#ifdef IPFIX_APPLICATIONID
                case IPFIX_FT_APPLICATIONID:
                	//converting 3 bytes to network byte order
                	memcpy(appId_nbo, flow->appId, 4);
                	byte = appId_nbo[3]; 
                	appId_nbo[3] = appId_nbo[1];
                	appId_nbo[1] = byte;
                    memcpy(buf+offset, appId_nbo, ie.length);
                    break;
#endif    
#ifdef IPFIX_APPLICATIONNAME
                case IPFIX_FT_APPLICATIONNAME:
                    memcpy(buf+offset, flow->appName, ie.length);
                    break;
#endif                     
                    case NF5_FT_NEXTHOP:
                        tmp = 0;
                        memcpy(buf + offset, &tmp, ie.length);
                        break;
                    case NF5_FT_INPUTINTERFACE:
                        tmp = 0;
                        memcpy(buf + offset, &tmp, ie.length);
                        break;
                    case NF5_FT_OUTPUTINTERFACE:
                        tmp = 0;
                        memcpy(buf + offset, &tmp, ie.length);
                        break;
                    case NF5_FT_TCPFLAGS:
                        tmp = 0;
                        memcpy(buf + offset, &tmp, ie.length);
                        break;
                    case NF5_FT_SOURCEAS:
                        tmp = 0;
                        memcpy(buf + offset, &tmp, ie.length);
                        break;
                    case NF5_FT_DESTINATIONAS:
                        tmp = 0;
                        memcpy(buf + offset, &tmp, ie.length);
                        break;
                    case NF5_FT_SOURCEMASK:
                        tmp = 0;
                        memcpy(buf + offset, &tmp, ie.length);
                        break;
                    case NF5_FT_DESTINATIONMASK:
                        tmp = 0;
                        memcpy(buf + offset, &tmp, ie.length);
                        break;
                    case NF5_FT_PADDING1:
                        tmp = 0;
                        memcpy(buf + offset, &tmp, ie.length);
                        break;
                    case NF5_FT_PADDING2:
                        tmp = 0;
                        memcpy(buf + offset, &tmp, ie.length);
                        break;
		}
		offset+=ie.length;
	}	

	//    IMSG("Exporting data to collector");
	if ( ipfix_export( ipfixh, ipfixt, buf ) <0 ) {
		sprintf(message,"Ipfix_export() failed: %s", strerror(errno) );
		log_message(message,3);
		cleanShutdown(2,configData);
	}
		
	if ( ipfix_export_flush( ipfixh ) <0 ) {		
		sprintf(message,"Ipfix_export_flush() failed: %s", strerror(errno) );
		log_message(message,3);
		cleanShutdown(2,configData);
	}	

//        sprintf(message,"[exportFlow] %llu nsec (flow ID: %llu)", getCurrentTime(3)-ef_s, flow->flow_id);
//        log_message(message,6);
        
	return 0;
}
