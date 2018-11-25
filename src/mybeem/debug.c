#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "cache.h"
#include "debug.h"
#include "capture.h"
#include "config.h"

//char message[LOG_MESSAGE_SIZE];
int logLevel;

/*!
* funkcia pre vypis logov pocas behu programu
*/


void log_message(char message[],int code){

	char 	message_type[20];
	char	username[20];
	int 	day,month,year;
	int	    sec,min,hour;
	char    program_name[10] = "Beem";
	
	struct 	tm *Sys_T = NULL;	

	if(code <= logLevel)
	{
	
		if	(code == 0)
			strcpy(message_type,"EMERGENCY  ");
		else if	(code == 1)
			strcpy(message_type,"ALERT      ");	
		else if (code == 2)
			strcpy(message_type,"CRITICAL   ");
		else if	(code == 3)
			strcpy(message_type,"ERROR      ");	
		else if	(code == 4)
			strcpy(message_type,"WARNING    ");
		else if	(code == 5)
			strcpy(message_type,"NOTICE     ");	
		else if	(code == 6)
			strcpy(message_type,"INFORMATION");
		else if	(code == 7)
			strcpy(message_type,"DEBUG      ");
		else
			strcpy(message_type,"UnknownMessageCode");

	

		strcpy(username,getenv("USER"));
		if(username == NULL)
		{
			strcpy(username,"NoUsernameObtained");
		} 
	

	
		time_t Tval = 0;
		Tval = time(NULL);
		Sys_T = localtime(&Tval);

		day = Sys_T->tm_mday;
		month = Sys_T->tm_mon+1;
		year = 1900 + Sys_T->tm_year;

		sec = Sys_T->tm_sec;
		min = Sys_T->tm_min;	
		hour = Sys_T->tm_hour;

		printf("%d.%d.%d  %d:%d:%d  %s  %s  %s  %s\n",day,month,year,hour,min,sec,username,program_name,message_type,message);

                // nie je potrebne, lebo logovaci subor obsahoval duplicitne vypisy 
//		if(strlen(config_option.log_file_name) != 0)		
//			fprintf(out_fp,"%d.%d.%d  %d:%d:%d  %s  %s  %s  %s\n",day,month,year,hour,min,sec,username,program_name,message_type,message);
		
	}

} 
