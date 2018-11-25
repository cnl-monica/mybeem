/*! \file config.h
*  \brief Hlavi�kov� s�bor s konfigura�n�mi premenn�mi a funkciami
* 
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

#ifndef _CONFIG__H_
#define _CONFIG__H_

/*! 
* maxim�lny po�et pol� v �abl�ne
*/
#define MAXFIELDS 100
/*! 
* Maxim�lny po�et definovan�ch �abl�n
*/
#define MAXTEMPLATES 10

#include <libxml2/libxml/xpath.h>
#include <libxml2/libxml/tree.h>
#include "capture.h"


extern FILE *out_fp;
extern char *syslog_serv_use;

/*! 
* Defin�cia XML re�azca
*/
typedef unsigned char xmlChar;

/*! 
* Typ pre informa�n� element
*/
typedef struct _ie_t {
	/*! 
	* ��slo informa�n�ho elementu
	*/
	int ie_number;
	/*! 
	* Enterprise ��slo informa�n�ho elementu
	*/
	int enterprise;
} ie_t;

/*! 
* Typ pre �abl�nu
*/
typedef struct _template_t {
	/*! 
	* ��slo �abl�ny
	*/
	int template_number;
	/*! 
	* Po�et pol� v �abl�ne
	*/
	int field_count;
	/*! 
	* Vlastn� polia �abl�ny
	*/
	ie_t fields[MAXFIELDS];
} template_t;

/* 
* Definicia struktury pre parametre prikazoveho riadku
*/
typedef struct command_line_arg {
	/* 
	* Meno log suboru
	*/
	char log_file_name[256];
	/* 
	* Typ protokolu
	*/	
	char protocol_type[10];
	/* 
	* Interface, na ktorom budeme chytat data
	*/
	char interface_type[10];
	/* 
	* Nazov xml config suboru
	*/
	char config_file_name[256];
	/* 
	* Pcap filter
	*/
	char pcap_filter[20];
	/* 
	* Port
	*/
	char port_number[10];
	/* 
	* Host IP address
	*/
	char host_IP[20];
	/*
	* Level logovania BEEMu
	*/
	char log_level[3];
	/*
	* Observation point ID
	*/
	uint32_t obs_pointid;
	/*
	* Observation domain ID
	*/
	uint32_t obs_domainid;
	/*
	* Log server port
	*/
	char log_serv_protocol[10];	
	/*
	* Log server IP adresa
	*/
	char log_serv_IP[40];
	/*
	* Log server port
	*/
	char log_serv_port[10];
	/*
	* Log server port
	*/
	char aggregation[6];

}command_line_arg;

extern struct command_line_arg config_option;



/*!
* Extern� smern�k na konfigur�ciu
*/
extern xmlDocPtr configData;

void printConfig(xmlDocPtr doc);
xmlXPathObjectPtr getNodeSet(xmlDocPtr doc, xmlChar *xpath);
xmlDocPtr readConfigFile (const char *docname);
char* getConfigElement(xmlDocPtr doc, const char* xpath);
void getConfigTemplates(xmlDocPtr doc, template_t templates[], int version);
void cleanShutdown(int exitc, xmlDocPtr configuration);
int readConfigInterfaces(xmlDocPtr doc, struct packet_capturing_thread**pcts, int * pct_count);
void syslog_server_config_file();
#endif //_CONFIG__H_
