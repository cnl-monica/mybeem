/*! \file beem.c
*  \brief Hlavn� programov� modul
* 
*  Hlavn� programov� modul beem-u. Obsahuje inicializ�ciu konfigur�cie a spustenie odchyt�vania klasifikovania a exportu.
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

#include "beem.h"
#include "capture.h"
#include "config.h"
#include "debug.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*! 
*  * Smern�k na konfigura�n� parametre
*   */
xmlDocPtr configData;

/*! 
* Vystupny logovaci subor
*/
FILE *out_fp = NULL;

/*! 
* Kontrolna premenna, ci sa ma pouzit syslog server
*/
char *syslog_serv_use = NULL;	

/*! 
* Main funkcia
*/
int main(int argc, char **argv) {
	int i = 0;
        
		/* 
		* Naplnanie struktury config_option konfiguracnymi hodnotami z parametrov poveloveho riadku
		*/

		while(i != argc - 1)
		{

			i++;
			if(!strcmp(argv[i], "-h"))
			{
				printf("\nUsage: mybeem <CONFIG_FILE>\n\n");
				printf("Type as argument in command line : \n\n");				
				printf("	-v  show version\n\n");			
				printf("	-h  show information\n\n");
				printf("	-p  <PROTOCOL TYPE> to set protocol type\n\n");
				printf("	-i  <INTERFACE> to set interface, where to capture\n\n");
				printf("	-c  <CONFIG FILE> to set exact xml config file\n\n");
				printf("	-l  <LOGFILE> to set logfile for program output\n\n");
				printf("	-pc <PCAP FILTER> to set pcap filter\n\n");
				printf("	-po <PORT NUMBER> to set port number\n\n");
				printf("	-ho <HOST IP> to set collector/mediator IP address\n\n");
				printf("		-aggreg turns on aggregation proccess\n\n");
				printf("    	-llvl <LOG LEVEL> to set level of logging\n\n");
				printf("    	-opid <OBSERVATION POINT ID> to set observationPointId\n\n");
				printf("    	-odid <OBSERVATION DOMAIN ID> to set observationDomainId\n\n");
				printf("    	-logserv [NO PARAM] to TURN ON logging on syslog server using configuration from beem's config.xml (by default)\n\n");
				printf("    	-logprot <PROTOCOL TYPE> to set protocol for syslog message transfer to syslog server otherwise value from config.xml used\n\n");
				printf("    	-logaddr <IP ADDRESS> to set IP address of syslog server otherwise value from config.xml used\n\n");
				printf("    	-logport <PORT NUMBER> to set communication port for syslog server otherwise value from config.xml used\n\n");
				return 0;
			}
			else if(!strcmp(argv[i], "-v"))
			{
				printf("MyBeem v1.1-9\n");
				
				return 0;
			}
			else if(strcmp(argv[i], "-p") == 0)
			{
				i++;
				strcpy(config_option.protocol_type,argv[i]);
			}
			else if(strcmp(argv[i], "-i") == 0)	
			{		
				i++;
				strcpy(config_option.interface_type,argv[i]);
			}
			else if(strcmp(argv[i], "-c") == 0)
			{
				i++;
				strcpy(config_option.config_file_name,argv[i]);				
				configData = readConfigFile(argv[i]);
			}
			else if(strcmp(argv[i], "-l") == 0)
			{
				i++;								
				strcat(config_option.log_file_name,argv[i]);			
				out_fp = freopen(config_option.log_file_name,"w",stdout);			
			}
			else if(strcmp(argv[i], "-pc") == 0)
			{
				i++;
				strcpy(config_option.pcap_filter,argv[i]);
			}
			else if(strcmp(argv[i], "-po") == 0)
			{
				i++;
				strcpy(config_option.port_number,argv[i]);					
			}
			else if(strcmp(argv[i], "-ho") == 0)
			{
				i++;
				strcpy(config_option.host_IP,argv[i]);					
			}
			else if(strcmp(argv[i], "-llvl") == 0)
			{
				i++;
				strcpy(config_option.log_level,argv[i]);
			}
			else if(strcmp(argv[i], "-opid") == 0)
			{
				i++;
				config_option.obs_pointid = atol(argv[i]);
			}
			else if(strcmp(argv[i], "-odid") == 0)
			{
				i++;
				config_option.obs_domainid = atol(argv[i]);
			}			
			else if(strcmp(argv[i], "-logserv") == 0)
			{	
				syslog_serv_use = "-serv";
			}
			else if(strcmp(argv[i], "-logprot") == 0)
			{
				i++;
				strcpy(config_option.log_serv_protocol,argv[i]);
			}
			else if(strcmp(argv[i], "-logaddr") == 0)
			{
				i++;
				strcpy(config_option.log_serv_IP,argv[i]);
			}
			else if(strcmp(argv[i], "-logport") == 0)
			{
				i++;
				strcpy(config_option.log_serv_port,argv[i]);
			}
			else if(strcmp(argv[i], "-aggreg") == 0)
			{
				strcpy(config_option.aggregation,"true");
			}
		}			

		if(configData == NULL)		
			configData = readConfigFile("/etc/mybeem/config.xml");	

		if(syslog_serv_use != NULL)
			syslog_server_config_file();		

		if(strlen(config_option.log_level) == 0)
			logLevel = atoi(getConfigElement(configData,"/configuration/logging/messageLogLevel"));
		else
			logLevel = atoi(config_option.log_level);				

		if(configData != NULL)
				startCapture();
		
		if(out_fp != NULL)
	        	fclose(out_fp);
	
	return 0;
}

