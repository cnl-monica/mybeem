#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <pthread.h>

#include "capture.h"
#include "config.h"
#include "queue.h"
#include "debug.h"

pthread_mutex_t		time_cache_mutex;
pthread_t		sender_thread;

struct queue data_queue;
struct item {
	struct item *next;
	int64_t time;
	int64_t c;
};

int64_t mns_dx = 0;
int64_t mns_dy = 0;
double sum_xx = 0;
double sum_xy = 0;
double sum_x = 0;
double sum_y = 0;
double N = 0;
double slope = 0;
double yntercept = 0;
FILE *messages;

void mns_init(){
	sum_xy = sum_x = sum_y = sum_xx = N = 0;
	mns_dx = mns_dy = 0;
}

void mns_insert(double x, double y){
	sum_xx += (x * x);
	sum_xy += (x * y);
	sum_x += x;
	sum_y += y;
	N++;
}

void mns_remove(double x, double y){
	if(N > 0){
		sum_xx -= (x * x);
		sum_xy -= (x * y);
		sum_x -= x;
		sum_y -= y;
		N--;
	}
}

void mns_calc(void){
	slope = ((N * sum_xy) - (sum_x * sum_y))/((N * sum_xx) - (sum_x * sum_x));
	yntercept = (sum_y - (slope * sum_x))/N;
}

void mns_data(int64_t x, int64_t y){
	struct item *data;

	if(N <= 0){
		mns_dx = x;
		mns_dy = y;
	//todo: vymazat data_queue;
	}
	data = (struct item *)malloc(sizeof(struct item));
	data->time = x - mns_dx;
	data->c = y - mns_dy;
	queue_add_last(&data_queue, (struct list_item *)data);
	mns_insert((double)data->time, (double)data->c);
	if(data_queue.size > 60){
		data = (struct item *)queue_remove_first(&data_queue);
		mns_remove((double)data->time, (double)data->c);
		free((char *)data);
	}
}

uint64_t getLocalTime(int precision){
	struct timespec now;
	unsigned long long int current_time_sec;
	unsigned long long int current_time_nsec;
	clock_gettime(CLOCK_REALTIME,&now);
	current_time_sec = now.tv_sec;
	current_time_nsec = now.tv_nsec;

	switch (precision){
		 case 0:
			return current_time_sec;
			break;
		case 1:
			return (current_time_sec*1000)+current_time_nsec / 1000000;
			break;
		case 2:
			return (current_time_sec*1000000)+current_time_nsec / 1000;
			break;
		case 3:
			return (current_time_sec*1000000000)+current_time_nsec;
			break;
	}
	return 0;
}

void *senderThread(void *arg){
        char message[LOG_MESSAGE_SIZE];
	int sock = (int)arg;
	char chost[256];
	int n;
	struct hostent *host;
	struct sockaddr_in peer_addr;
	char buff[3 * sizeof(uint64_t)];
	uint64_t *sequence;
	uint64_t *t1;

	sequence = (uint64_t *)&buff[0];
	t1 = (uint64_t *)&buff[sizeof(uint64_t)];

	strcpy(chost, getConfigElement(configData,"/configuration/synchronization/serverAddress"));

	if(!(host = gethostbyname(chost))){
		strcpy(message,"gethostbyname failed");
		log_message(message,3);
		return (void *)-1;
	}
	memset((char *)&peer_addr, 0, sizeof(struct sockaddr_in));
	peer_addr.sin_family = host->h_addrtype;
	memcpy((char *)&peer_addr.sin_addr.s_addr, host->h_addr_list[0], host->h_length);
	peer_addr.sin_port = (uint16_t) htons(atoi(getConfigElement(configData,"/configuration/synchronization/serverPort"))); 		
	sprintf(message,"[synchronization] Server port number : %d", ntohs(peer_addr.sin_port));
	log_message(message,6);

	while(!capture_interrupted){
		sleep(1);
		(*sequence)++;
		*t1 = getLocalTime(3);		
		n = sendto(sock, buff, 3 * sizeof(uint64_t), 0, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr));
	}
	return (void *)0;
}

void *threadSync(void *arg){
        char message[LOG_MESSAGE_SIZE];
	int sock, n, set_ret;
	socklen_t len;
	char buff[1000];
	struct sockaddr_in serv_addr, cli_addr;
	struct item *diff;
	uint64_t t1, t2, t3;
	int64_t t1s, t2s, t3s, delay2, drift;
	uint64_t sequence;

	FILE *f;	
	f = fopen("/var/log/mybeem/synchronization", "w");	
	if(!f) {
		strcpy(message,"[synchronization] Nepodarilo sa otvorit subor pre synchronizacne vypisy");
		log_message(message,3);
	}
	data_queue.last = 0;
	data_queue.size = 0;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0){
		strcpy(message,"[synchronization] socket()");
		log_message(message,3);
		return (void *)-1;
	}

	//lokalna adresa, adresa udp servra
	memset((char *)&serv_addr, 0, sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = (uint16_t) htons(atoi(getConfigElement(configData,"/configuration/synchronization/port")));

	if(bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1){
		strcpy(message,"[synchronization] bind failed");
		log_message(message,3);
		return (void *)-1;
	}

	set_ret = pthread_create(&sender_thread, NULL, senderThread, (void *)sock);

	while(capture_interrupted < 4){
		len = sizeof(cli_addr);
		fd_set socks;
		struct timeval t;
		FD_ZERO(&socks);
		FD_SET(sock, &socks);
		t.tv_sec = 3;
		//volanie select pred rcvfrom pre odstranenie nekonecneho cakania na data
		if (select(sock + 1, &socks, NULL, NULL, &t)) {
			n = recvfrom(sock, buff, 1000, 0, (struct sockaddr *)&cli_addr, &len);
		} else	{
			continue;
		}				
		t3 = getLocalTime(3);
		memcpy(&sequence, &buff[0], sizeof(uint64_t));
		memcpy(&t1, &buff[sizeof(uint64_t)], sizeof(uint64_t));

		memcpy(&t2, &buff[2 * sizeof(uint64_t)], sizeof(uint64_t));
		t1s = (int64_t)t1;
		t2s = (int64_t)t2;
		t3s = (int64_t)t3;		
		delay2 = (t3s - t1s) / 2;
		drift = t3s - t2s - delay2;
				
		mns_data(t3s, drift);		
		mns_calc();
		
		sprintf(message,"t[%lli] o1[%lli] o[%lli] ", t3s, t3s - t2s, t3s - t2s - delay2);
		log_message(message,7);
		fprintf(f, "t3[%lli], t3-t2[%lli], owd[%lli], t3-t2-owd[%lli]\n", t3s, t3s - t2s, t3s - t2s - delay2, delay2);

		drift = ((int64_t)(slope * ((double)(t3 - mns_dx)))) + (mns_dy + (int64_t)yntercept);
		sprintf(message,"slope[%lli] yntcpt[%lli ] drift[%lli]", slope, yntercept, drift);
		log_message(message,7);
		fprintf(f, "slope[%f], yntercept[%f], drift[%lli]\n", slope, yntercept, drift);
	}
	fclose(f);

	return (void *)0;
}
