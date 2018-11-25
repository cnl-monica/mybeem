/********************************************************************************
Autor:	Gorazd Baldovsky
Datum: 	26.3.2006

Pre linkovanie je potrebne pouzit options  -lssl (linkovanie s openssl kniznicou)
*********************************************************************************/

#include <netinet/in.h> 
#include <stdlib.h>
#include <openssl/md5.h>
#define HEADER_IDENTIFICATION_LENGTH 13 //in Bytes!!! number of Bytes from ip header used for identification
#define UNTIL_DST_ADD  20 //number of bytes in ip paket header until the end of destination IP address

struct identificator_s{
    unsigned char *identificator;//identificator of ip packet
    int length;
}identificator_t;



/*
    Funkcia pre vytvaranie identifikatora paketu zadanej dlzky.

    predpoklady:
	- vstupom je IP paket(podla RFC 791)
	- length_of_identificator je vacsie-rovne ako HEADER_IDENTIFICATION_LENGTH
	- paket je cely, alebo aspon dzky length_of_identificator + (LENGTH_IDENTIFICATOR - HEADER_IDENTIFICATION_LENGTH) 
	- neposkodeny	

    vstup:
	- length_of_identificator in Bytes from interval <HEADER_IDENTIFICATION_LENGTH,255>
	- recommended length depend on amount of packet where it should by unique:
		for example for 100 000 packets 40 Bytes is enough       
		
    vystup:
	- je identifikator paketu ktory je tym silnejsi cim je dlhsi
	- pokial nie je v pakete dostatok dat, dlzka identifikatora bude mensia ako pozadovana (teda dlzka bude min(length_of_identificator, najdlhsia mozna dlzka)  )
*/
struct identificator_s* ip_packet_identificator(const unsigned char* packet,const unsigned char length_of_identificator);


/*
    Funkcia pre vytvaranie zasifrovaneho identifikatora paketu pouzitim MD5. 

    vstup:
	- IP paket(podla RFC 791)	
	- paket je cely, alebo aspon dlzky 56 + (LENGTH_IDENTIFICATOR - HEADER_IDENTIFICATION_LENGTH) 	
	
    vystup:	
	- sifrovany identifikator paketu dlzky 16 Byte-ov
*/

void ip_packet_identificator_MD5(uint8_t *m_digest, const unsigned char* packet);



/**********************************************************************************************************************/
/****************************************** implementation ************************************************************/
/**********************************************************************************************************************/

void copy_char_array(const unsigned char *from,unsigned char *where,int length){
    int i;
        for(i=0;i<length;i++){
	        where[i] = from[i];
        }
}
		    	
struct identificator_s* ip_packet_identificator(const unsigned char* packet,const unsigned char length_of_identificator){
    
    struct identificator_s* ident;
    int tot_ip_len = ntohs(*((unsigned short int *)(packet+2))); //total length of ip packet
    int IHL = ((*packet) & 0x0f)*4;//internet header length IN BYTES!!!
    int payload_length = 0;

    ident = (struct identificator_s*)malloc(sizeof(struct identificator_s));
    ident->identificator = (unsigned char*)malloc(sizeof(unsigned char)*length_of_identificator);//moznoze bude kratsi

    //z hlavicky zoberieme vybrane polozky 
    copy_char_array(packet+2,ident->identificator,2); //tot length
    copy_char_array(packet+4,ident->identificator+2,2);//identification
    copy_char_array(packet+9,ident->identificator+4,1);//protocol
    copy_char_array(packet+12,ident->identificator+5,4);//src IP
    copy_char_array(packet+16,ident->identificator+9,4);//dst IP
		       
    //idealne je zobrat payload dlzky (length_of_identificator - HEADER_IDENTIFICATION_LENGTH) z dat paketu (bez options)
    if(tot_ip_len - IHL  >= length_of_identificator - HEADER_IDENTIFICATION_LENGTH){//ak plati nic nam nebrani takto urobit
	
	copy_char_array(packet+IHL,ident->identificator+HEADER_IDENTIFICATION_LENGTH,length_of_identificator - HEADER_IDENTIFICATION_LENGTH);
	payload_length = length_of_identificator - HEADER_IDENTIFICATION_LENGTH;
	//printf("+vetva1 payload %d+",payload_length);
    
    }else{//data paketu su kratsie, posluzia nam aj options
	
	if(tot_ip_len - UNTIL_DST_ADD >= length_of_identificator - HEADER_IDENTIFICATION_LENGTH){
		    //data + options je ich dost na naplnenie celeho identifikatora takeho dlheho ako chceme
		    //zober od zadu pozadovany pocet Byteov nech je tam cim menej byteov z options
		    copy_char_array(packet+(tot_ip_len - (length_of_identificator - HEADER_IDENTIFICATION_LENGTH)), ident->identificator + HEADER_IDENTIFICATION_LENGTH, length_of_identificator - HEADER_IDENTIFICATION_LENGTH);
		    payload_length = length_of_identificator - HEADER_IDENTIFICATION_LENGTH;
		    //printf("+vetva2 payload %d+",payload_length);		    
	}else{
		    //ani data+options nie je dost na naplnenie pozadovanej dlzky
		    //zoberieme ich cele, a identifikator bude kratsiu
		    copy_char_array(packet+UNTIL_DST_ADD,ident->identificator+HEADER_IDENTIFICATION_LENGTH,tot_ip_len - UNTIL_DST_ADD);
		    payload_length = tot_ip_len - UNTIL_DST_ADD;
		    //printf("+vetva3 payload %d+",payload_length);		    
	}
    
    }
    
    ident->length = HEADER_IDENTIFICATION_LENGTH + payload_length;


    return ident;
}




void ip_packet_identificator_MD5(uint8_t *m_digest, const unsigned char* packet){

    struct identificator_s *ident;

    ident = ip_packet_identificator(packet,56);
    
#if MD5_DIGEST_LENGTH > 16
#error MD5_DIGEST_LENGTH is greater than expected 16 Bytes!!!
#endif

	MD5(ident -> identificator, ident -> length, m_digest);
    
    free(ident->identificator);
    free(ident);			 
}

