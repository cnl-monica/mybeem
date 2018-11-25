/*! \file config.c
*  \brief Modul pre mene�ovanie konfigur�cie
* 
*  Na��tanie a mene�ovanie konfigura�n�ch parametrov ulo�en�ch v konfigura�nom XML s�bore. Pre tento ��el bola pou�it� kni�nica libxml (http://xmlsoft.org/index.html)
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

#include "config.h"
#include "debug.h"
#include "ipfix.h"
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/xpath.h>
#include <libxml2/libxml/tree.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

struct command_line_arg config_option;

/*!
* Funkcia vyp�e na debugovac� v�stup moment�lnu konfigur�ciu
* \param doc	Ukazovate� na XML konfigur�ciu ktor� sa m� vyp�sa�
*/
void printConfig(xmlDocPtr doc)
{	
        char message[LOG_MESSAGE_SIZE];
	sprintf(message,"Configured interface for capture is: %s",getConfigElement(doc, "/configuration/interface"));
	log_message(message,6);	
	sprintf(message,"Configured read from file flag is: %s",getConfigElement(doc, "/configuration/readFile"));
	log_message(message,6);
	sprintf(message,"Configured dumpfile filename is: %s",getConfigElement(doc, "/configuration/dumpFile"));
	log_message(message,6);
	sprintf(message,"Configured LibPcap BPF filter is: %s",getConfigElement(doc, "/configuration/pcapFilter"));
	log_message(message,6);
	sprintf(message,"Configured sampling type is: %s",getConfigElement(doc, "/configuration/sampling/type"));
	log_message(message,6);
	sprintf(message,"Configured 1st sampling parameter is: %s",getConfigElement(doc, "/configuration/sampling/parameter1"));
	log_message(message,6);
	sprintf(message,"Configured 2nd sampling parameter is: %s",getConfigElement(doc, "/configuration/sampling/parameter2"));
	log_message(message,6);
}

/*!
* Funkcia pod�a XPath v�razu vyh�ad� prv� vyhovuj�ci uzol v konfigura�nom XML s�bore
* \param doc	Ukazovate� na XML konfigur�ciu ktor� sa bude preh�ad�va�
* \param xpath Ukazovate� na XPath v�raz
*/
xmlXPathObjectPtr getNodeSet(xmlDocPtr doc, xmlChar *xpath)
{
        char message[LOG_MESSAGE_SIZE];
	xmlXPathContextPtr context;
	xmlXPathObjectPtr result;

	context = xmlXPathNewContext(doc);
	if (context == NULL)
	{
		strcpy(message,"Error in xmlXPathNewContext");
		log_message(message,3);
		cleanShutdown(1,doc);
	}
	result = xmlXPathEvalExpression(xpath, context);
	xmlXPathFreeContext(context);
	if (result == NULL)
	{
		strcpy(message,"Error in xmlXPathEvalExpression");
		log_message(message,3);
		cleanShutdown(1,doc);
	}
	if(xmlXPathNodeSetIsEmpty(result->nodesetval))
	{
		xmlXPathFreeObject(result);
		return NULL;
	}
	return result;
}
int readConfigInterfaces(xmlDocPtr doc, struct packet_capturing_thread **pcts, int *pct_count){
        char message[LOG_MESSAGE_SIZE];
	xmlXPathObjectPtr xpathobj = getNodeSet(doc, (xmlChar*)"/configuration/interfaces");
	xmlNodeSetPtr nodeset;
	//xmlNodePtr node;
	xmlNodePtr nodeConfiguration, nodeInterfaces, nodeInterface;
	int i;
	char *name;

	if(xpathobj->type != XPATH_NODESET){
		strcpy(message,"Bad configuration file");		
		log_message(message,3);
		return -1;
	}
	nodeset = xpathobj->nodesetval;
	if(nodeset->nodeNr < 1){
		strcpy(message,"Bad configuration file");
		log_message(message,3);
		return -1;
	}
	//node = 
	nodeConfiguration = nodeset->nodeTab[0];
	//printf("X: name %s line %i type %i\n", node->name, node->line, node->type);
	//for(nodeConfiguration = node->children;nodeConfiguration;nodeConfiguration = nodeConfiguration->next){
	//	if(nodeConfiguration->type != 1)
	//		continue;
	//	printf(" X: name %s line %i type %i\n", nodeConfiguration->name, nodeConfiguration->line, nodeConfiguration->type);
	//	if(!strcmp((char *)nodeConfiguration->name, "interfaces"))
	*pct_count = 0;
	if(strlen(config_option.interface_type) != 0)
		*pct_count = 1;
	else
	{	
		for(nodeInterfaces = nodeConfiguration->children;nodeInterfaces;nodeInterfaces = nodeInterfaces->next){
			if(nodeInterfaces->type != 1)
				continue;
			if(!strcmp((char *)nodeInterfaces->name, "interface"))
				(*pct_count)++;
		}
	}
	*pcts = (struct packet_capturing_thread *)malloc(sizeof(struct packet_capturing_thread) * (*pct_count));
	memset(*pcts, 0, sizeof(struct packet_capturing_thread) * (*pct_count));
	i = 0;
	for(nodeInterfaces = nodeConfiguration->children;nodeInterfaces;nodeInterfaces = nodeInterfaces->next){
		if(nodeInterfaces->type != 1)
			continue;
		//	printf("  X: name %s line %i type %i\n", nodeInterfaces->name, nodeInterfaces->line, nodeInterfaces->type);
		if(!strcmp((char *)nodeInterfaces->name, "interface")){
			for(nodeInterface = nodeInterfaces->children;nodeInterface;nodeInterface = nodeInterface->next){
				if(nodeInterface->type != 1)
					continue;
				//			printf("   X: name %s line %i type %i\n", nodeInterface->name, nodeInterface->line, nodeInterface->type);
				name = (char *)nodeInterface->name;
				if(!strcmp(name, "name"))
				{
					if(strlen(config_option.interface_type) != 0)
						(*pcts)[i].interface = config_option.interface_type;	
					else
						(*pcts)[i].interface = strdup((char *)xmlNodeGetContent(nodeInterface));
				}
				else if(!strcmp(name, "pcapFilter"))
				{
					if(strlen(config_option.pcap_filter) != 0)
					(*pcts)[i].pcap_filter = config_option.pcap_filter;
					else						
					(*pcts)[i].pcap_filter = strdup((char *)xmlNodeGetContent(nodeInterface));
				}
				else if(!strcmp(name, "dumpFile")){
					(*pcts)[i].dump_file = strdup((char *)xmlNodeGetContent(nodeInterface));
				}else if(!strcmp(name, "samplingType")){
					(*pcts)[i].sampling_type = atoi((char *)xmlNodeGetContent(nodeInterface));
				}else if(!strcmp(name, "samplingParam1")){
					(*pcts)[i].sampling_param1 = atoi((char *)xmlNodeGetContent(nodeInterface));
				}else if(!strcmp(name, "samplingParam2")){
					(*pcts)[i].sampling_param2 = atoi((char *)xmlNodeGetContent(nodeInterface));
				}
			}
		if(strlen(config_option.interface_type) != 0)
			break;
		else			
			i++;
		}
	}
	//}

	return 0;
}
/*!
* Funkcia do pam�te na��ta zadan� konfigura�n� s�bor
* \param docname Meno konfigura�n�ho s�boru
*/
xmlDocPtr readConfigFile (const char *docname)
{
        char message[LOG_MESSAGE_SIZE];
	xmlDocPtr doc;
	doc = xmlParseFile(docname);

	if (doc == NULL ) {
		strcpy(message,"Configuration not parsed successfully");
		log_message(message,3);
	}
	return doc;
}

/*!
* Funkcia z�ska z XPath v�razu prisl�chaj�ci obsah elementu, ktor� je cie�om tohoto v�razu.
* \param doc	Ukazovate� na XML konfigur�ciu ktor� sa bude preh�ad�va�
* \param xpath	Ukazovate� na xpath v�raz
*/
char* getConfigElement(xmlDocPtr doc, const char* xpath)
{
	xmlNodeSetPtr nodeset;
	xmlXPathObjectPtr result;
	xmlChar *keyword = NULL;

	result = getNodeSet(doc, (unsigned char*) xpath);
	if (result) {
		nodeset = result->nodesetval;
		keyword = xmlNodeListGetString(doc, nodeset->nodeTab[0]->xmlChildrenNode, 1);
		xmlXPathFreeObject (result);
	}
	return (char*)keyword;
}

/*!
* Funkcia z�ska pole nakonfigurovan�ch �abl�n
* \param doc	Ukazovate� na XML konfigur�ciu ktor� sa bude preh�ad�va�
* \param templates	Pole �abl�n, ktor� bude naplnen�
*/
void getConfigTemplates(xmlDocPtr doc, template_t templates[], int version)
{
    
    if (version == IPFIX_VERSION_NF5) {
        
        templates[0].template_number = 1;       
        templates[0].field_count = 20;
        templates[0].fields[0].ie_number = NF5_FT_SOURCEADDRESS;  // 8 in IPFIX
        templates[0].fields[1].ie_number = NF5_FT_DESTINATIONADDRESS;  // 12
        templates[0].fields[2].ie_number = NF5_FT_NEXTHOP;  // 15
        templates[0].fields[3].ie_number = NF5_FT_INPUTINTERFACE;  // 10 -- 4--> 2 bytes
        templates[0].fields[4].ie_number = NF5_FT_OUTPUTINTERFACE;  // 14 -- 4--> 2 bytes
        templates[0].fields[5].ie_number = NF5_FT_PACKETCOUNT;  // 2 -- 8--> 4 bytes
        templates[0].fields[6].ie_number = NF5_FT_OCTETCOUNT;  // 1 -- 8--> 4 bytes
        templates[0].fields[7].ie_number = NF5_FT_STARTSYSTEMUPTIME;  // 22
        templates[0].fields[8].ie_number = NF5_FT_ENDSYSTEMUPTIME;  // 21
        templates[0].fields[9].ie_number = NF5_FT_SOURCEPORT;  // 7
        templates[0].fields[10].ie_number = NF5_FT_DESTINATIONPORT;  // 11
        templates[0].fields[11].ie_number = NF5_FT_PADDING1; // 8 bit padding
        templates[0].fields[12].ie_number = NF5_FT_TCPFLAGS;  // 6?
        templates[0].fields[13].ie_number = NF5_FT_PROTOCOLTYPE;  // 215
        templates[0].fields[14].ie_number = NF5_FT_TYPEOFSERVICE;  // 4?
        templates[0].fields[15].ie_number = NF5_FT_SOURCEAS;  // 16
        templates[0].fields[16].ie_number = NF5_FT_DESTINATIONAS;  // 17
        templates[0].fields[17].ie_number = NF5_FT_SOURCEMASK;  // 9
        templates[0].fields[18].ie_number = NF5_FT_DESTINATIONMASK;  // 13
        templates[0].fields[19].ie_number = NF5_FT_PADDING2; // 16 bit padding
        
        return;
    }
    
	xmlNodeSetPtr nodeset;
	xmlXPathObjectPtr result;
	xmlChar *value;
	xmlChar *enterprise;
	xmlNode *field;

	int cnt,i;
        
	result = getNodeSet (doc, (xmlChar*) "/configuration/templates/*");
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
			templates[i].template_number=atoi((const char*)xmlGetProp(nodeset->nodeTab[i], (xmlChar*)"id"));
			field = nodeset->nodeTab[i]->children;
			cnt = 0;
			do
			{
				value = xmlNodeListGetString(doc, field->xmlChildrenNode, 1);
				enterprise = xmlGetProp(field, (xmlChar*)"enterprise");
				if (value != NULL)
				{
                                    if (version == IPFIX_VERSION) {
                                        templates[i].fields[cnt].ie_number=atoi((const char*)value);
                                        if (enterprise != NULL)	templates[i].fields[cnt].enterprise = atoi((const char*)enterprise);
                                        else templates[i].fields[cnt].enterprise = 0;
                                        cnt++;   
                                    } else if ((version == IPFIX_VERSION_NF9) && (enterprise == NULL)) {
                                        templates[i].fields[cnt].ie_number=atoi((const char*)value);
                                        templates[i].fields[cnt].enterprise = 0;
                                        cnt++;
                                    }
				}
				field=field->next;

			} while ( field != NULL);
			templates[i].field_count=cnt;
			xmlFree(value);
			xmlFree(enterprise);
		}
		xmlXPathFreeObject (result);
	}
}




/*!
* Funkcia pre vytvorenie konfiguracneho suboru pre syslog-ng klienta, ak chce pouzivatel pouzit logovanie na
* syslog server.
*/
void syslog_server_config_file()
{ 	
	FILE *syslog_serv_conf = fopen("/etc/syslog-ng/beem_syslog-ng.conf", "w");
	

	//char *const envp[] = {NULL};
		
	char route[50] ="/var/log/mybeem/beem_pid";
	char str_pid[10];
	pid_t pid2;	

	if(strlen(config_option.log_file_name) == 0)
	{
		pid2 = getpid();
		sprintf(str_pid,"%d",pid2);		
		strcat(route,str_pid); 	
		out_fp = fopen(route,"w");
	}

	char *const parmList[] = {str_pid,"-f","/etc/syslog-ng/beem_syslog-ng.conf",NULL};

	if(syslog_serv_conf != NULL)
	{
		fputs("options {\nchain_hostnames(0);\ntime_reopen(10);\ntime_reap(360);\nlog_fifo_size(2048);\ncreate_dirs(yes);\n group(adm);\nperm(0640);\ndir_perm(0755);\nuse_dns(no);\nstats_freq(0);\nbad_hostname(\"^gconfd$\");\n};\n\n",syslog_serv_conf);
		
		if(strlen(config_option.log_file_name) > 0)
		{
			char str1[200] = "source s_file{file(\"";
			char str2[50] = "\" follow-freq(1));};\n";
			strcat(str1,config_option.log_file_name);
			strcat(str1,str2);
			fputs(str1,syslog_serv_conf);			
		}
		else
		{
			char str1[200] = "source s_file{file(\"";
			strcat(str1,route);
			strcat(str1,"\" follow-freq(1));};\n");
			fputs(str1,syslog_serv_conf);
		}
			

			char str3[200] = "destination d_connect{";
		if(strlen(config_option.log_serv_protocol) > 0)
			strcat(str3,config_option.log_serv_protocol);
		else
			strcat(str3,getConfigElement(configData,"/configuration/logging/sendingProtocol"));
			
			strcat(str3,"(\"");	
	
		if(strlen(config_option.log_serv_IP) > 0)
			strcat(str3,config_option.log_serv_IP);
		else
			strcat(str3,getConfigElement(configData,"/configuration/logging/syslogServIP"));	
	
			strcat(str3,"\" port(");
	
		if(strlen(config_option.log_serv_port) > 0)
			strcat(str3,config_option.log_serv_port);			
		else	
			strcat(str3,getConfigElement(configData,"/configuration/logging/syslogServPort"));

			strcat(str3,"));};\n\n");

		//fputs("destination d_connect{tcp( ip(\"147.232.241.139\") port(4739));};\n\n",syslog_serv_conf);
		
		fputs(str3,syslog_serv_conf);
				
		fputs("log{\nsource(s_file);\ndestination (d_connect);\n};",syslog_serv_conf);

		
	}	

	fclose(syslog_serv_conf);
	
	pid_t syslog_ng_pid = fork();

	if(syslog_ng_pid == 0)
		execv("/usr/sbin/syslog-ng",parmList);

}	

/*!
* Funkcia korektne ukon�� �innos� programu s pr�slu�n�m statusom. Uzatvor� XML parser a dealokuje pam� s nim asociovan�.
* \param exitc Status programu pri skon�en�
* \param configuration	Ukazovate� na XML konfigur�ciu ktor� sa m� uvo�ni�
*/
void cleanShutdown(int exitc, xmlDocPtr configuration)
{
        char message[LOG_MESSAGE_SIZE];
	strcpy(message,"Cleaning memory");	
	log_message(message,7);
	xmlFreeDoc(configuration);
	xmlCleanupParser();
	strcpy(message,"Exiting\n");
	log_message(message,7);
	exit(exitc);
}	
