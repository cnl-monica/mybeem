/*! \file ipfix.c
*  \brief Hlavný modul pre export dát pomocou protokolu IPFIX
*
*  Tento modul obsahuje funkcie, ktoré zabezpeèujú vytvorenie, naplnenie, správne enkódovanie a transport IPFIX správ z exportovacieho procesu do zhromaŸïovaèa
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "ipfix.h"
#include "ipfix_fields.h"
#include "debug.h"
#include "cache.h"
#include "config.h"


#ifndef NTOHLL
/*! 
* Definícia makier na prevod bitov
*/
#define HTONLL(val)  ((uint64_t)(htonl((uint32_t)((val)>>32))) | \
	(((uint64_t)htonl((uint32_t)((val)&0xFFFFFFFF)))<<32))
/*! 
* Definícia makier na prevod bitov
*/
#define NTOHLL(val)  ((uint64_t)(ntohl((uint32_t)((val)>>32))) | \
	(((uint64_t)ntohl((uint32_t)((val)&0xFFFFFFFF)))<<32))
#endif

/*! 
* Definicia makier na prevod a vlozenie bitov
*/
#define INSERTU16(b,l,val) \
		{ uint16_t _t=htons((val)); memcpy((b),&_t,2); (l)+=2; }
/*! 
* Definícia makier na prevod a vloŸenie bitov
*/
#define INSERTU32(b,l,val) \
		{ uint32_t _t=htonl((val)); memcpy((b),&_t,4); (l)+=4; }

/*!
*  buffer pre I/O operácie
*/
typedef struct ipfixiobuf
{
	/*! 
	* Vnútorný smerník
	*/
	struct ipfixiobuf  *next;
	/*! 
	* Veµko» buffra
	*/
	size_t             buflen;
	/*! 
	* Vlastný buffer
	*/
	char               buffer[IPFIX_DEFAULT_BUFLEN+IPFIX_HDR_BYTES_NF9]; /*!!*/
} iobuf_t;

/*!
*  ipfix uzol (zariadenie)
*/
typedef struct ipfix_node
{
	/*! 
	* Vnútorný smerník
	*/
	struct ipfix_node   *next;
	/*! 
	* ©truktúra s informáciami o uzle
	*/
	ipfix_t             *ifh;

} ipfix_node_t;

/*!
*  ipfix zhromaŸïovaè
*/
typedef struct collector_node
{
	/*! 
	* Vnútorný smerník
	*/
	struct collector_node *next;
	/*! 
	* Poèet pouŸití
	*/
	int                   usecount;

	/*! 
	* Adresa
	*/
	char            *chost;       
	/*! 
	* Port
	*/
	int             cport;        
	/*! 
	* Protokol
	*/
	ipfix_proto_t   protocol;     
	/*! 
	* Deskriptor soketu
	*/
	int             fd;           
	/*! 
	* Adresa soketu
	*/
	struct sockaddr *to;
	struct sockaddr_in6 *to6;      
	/*! 
	* DåŸka soketu
	*/
	socklen_t       tolen;        
	/*! 
	* Èas posledného pouŸitia
	*/
	time_t          lastaccess;
	/*! 
	* Frekvencia opakovania pripojenia
	*/		
	int creconnectFreq;
	/*! 
	* Timeout spojenia
	*/
	int cconnTimeout;   

} ipfix_collector_t;

/*! 
* Globálna premenná - èas
*/
static time_t             g_tstart = 0;
/*! 
* Globálna premenná - I/O buffer
*/
static iobuf_t            g_iobuf, *g_buflist =NULL;
/*! 
* Globálna premenná - zhromaŸïovaèe
*/
static ipfix_collector_t  *g_collectors =NULL;
/*! 
* Globálna premenná - IPFIX zariadenia
*/
static ipfix_node_t       *g_ipfixlist =NULL;
/*! 
* Globálna premenná - posledný pouŸitý uzol
*/
static uint16_t           g_lasttid;                  
/*! 
* Globálna premenná - dátový záznam
*/
static ipfix_datarecord_t g_data = { NULL, NULL, 0 };

/*! 
* Globálna premenná - polia záznamov
*/
static ipfix_field_t      *g_ipfix_fields;

static int rfTmplTime;

static int discTime;

extern int capture_interrupted;

void _ipfix_drop_collector( ipfix_collector_t **col );
int  _ipfix_write_template( ipfix_t *ifh, ipfix_template_t *templ );
int  ipfix_reconnect(ipfix_t *ifh);
int  ipfix_add_template(ipfix_t *ifh, iobuf_t *buf);

/*
 * Nastavit dlzky IE aby boli v sulade s NetFlow v5 definiciou
 */
void updateIeLenghts() {
    int ieindex = 0;
    
    ieindex = findIe(NF5_FT_INPUTINTERFACE);
    ipfix_field_types[ieindex].length = 2;
    ieindex = findIe(NF5_FT_OUTPUTINTERFACE);
    ipfix_field_types[ieindex].length = 2;
    ieindex = findIe(NF5_FT_PACKETCOUNT);
    ipfix_field_types[ieindex].length = 4;
    ieindex = findIe(NF5_FT_OCTETCOUNT);
    ipfix_field_types[ieindex].length = 4;
}

/*
 * Najde index IE v poli ipfix_field_types definovanom v ipfix_fields.h
 */
int findIe(int ie) {
    unsigned int i, max;
        
    max = sizeof(ipfix_field_types)/sizeof(ipfix_field_type_t);

    for (i = 0; i < max; i++) {
        if (ie == ipfix_field_types[i].ftype) 
            return i;
    }
    
    return -1;
}

/*!
* V generovanom poli v hlavièkovom súbore ipfix_fields.h nájde záznam konkrétneho informaèného elementu
* \param ie identifikátor informaèného elementu
* \returns ©truktúru obsahujúcu informácie o nájdenom informaènom elemente
*/
ipfix_field_type_t findIEField(int ie)
{
	unsigned int i, max;
        
        max = sizeof(ipfix_field_types)/sizeof(ipfix_field_type_t);
        
	for (i = 0; i < max; i++) {
            if (ie == ipfix_field_types[i].ftype) 
                return ipfix_field_types[i];
	}
        
	return ipfix_field_types[sizeof(ipfix_field_types)/sizeof(ipfix_field_type_t) - 1];
}

/*!
* Funkcia, ktorá zapí¹e do súboru 'n' bajtov. Pokiaµ je výstupný súbor stream socket , funguje ako write
* \param fd Deskriptor súboru
* \param ptr Buffer, ktorý sa do súboru zapí¹e
* \param nbytes  Poèet bajtov ktorý sa má do súboru zapísa»
* \returns Poèet zapísaných bajtov
*/
static int do_writen( int fd, char *ptr, int nbytes)
{
	int     nleft, nwritten;

	nleft = nbytes;
	while (nleft > 0)
	{
		nwritten = write(fd, ptr, nleft);
		if (nwritten <= 0)
			// stala sa chyba ... 
			return(nwritten);               

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(nbytes - nleft);
}

/*!
* Funkcia pre non-blocking pripojenie na socket
* \param sockfd Deskriptor socketu
* \param saptr Smerník na adresu soketu
* \param salen DåŸka socketu
* \param sec Timeout pre spojenie
*/
static int _connect_nonb( int sockfd, struct sockaddr *saptr, 
						 socklen_t salen, int sec)
{
        char message[LOG_MESSAGE_SIZE];
	int                     n, error;
	socklen_t               len;
	fd_set                  rset, wset;
	struct timeval          tval;

	//flags = fcntl(sockfd, F_GETFL, 0);
	//if ( (flags==-1) || (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) <0) )
	//	return -1;
        
        //char str[INET6_ADDRSTRLEN];
        //inet_ntop(AF_INET6, &((struct sockaddr_in6 *)saptr)->sin6_addr, str, INET6_ADDRSTRLEN);
        //printf("\n%s\n\n", str);
        
	error = 0;
	if ( (n = connect(sockfd, (struct sockaddr *) saptr, salen)) < 0)
		if (errno != EINPROGRESS) {
			// printf("Chyba 1, errno: %d\n", errno);
			return(-1);
		}

	// spojenie bez timeoutu
	//TODO odkomentovat cely if minimalne pre TCP
	if (n != 0)
	{      

		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);
		wset = rset;
		tval.tv_sec = sec;
		tval.tv_usec = 0;

		if ( (n = select(sockfd+1, &rset, &wset, NULL,
			sec ? &tval : NULL)) == 0) 
		{
			errno = ETIMEDOUT;
			// printf("Chyba 2\n");
			return(-1);
		}

		if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
			len = sizeof(error);
			if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
				// printf("Chyba 3\n");
				return(-1);                     
			}
		} else {
			strcpy(message,"Select error: sockfd not set");
			log_message(message,3);
		}

	}
	// obnovime flagy
	//if ( fcntl(sockfd, F_SETFL, flags) <0 )  
	//	EMSG("Fcntl failed <%s>\n", strerror(errno));

	if (error) {
		errno = error;
		// printf("Chyba 4\n");
		return(-1);
	}
	return(0);
}
/*! 
* Funkcia na získanie ïal¹ieho bufferu
* \returns Ïal¹í buffer
*/
iobuf_t *_ipfix_getbuf ( void )
{
	iobuf_t *b = g_buflist;

	if ( b ) {
		g_buflist = b->next;
		b->next = NULL;
	}

	return b;
}
/*! 
* Funkcia na uvoµnenie bufferu
* \param b Buffer
*/
void _ipfix_freebuf( iobuf_t *b )
{
	if ( b ) {
		b->next = g_buflist;
		g_buflist = b;
	}
}

/*!
* Funkcia uprace v pamäti tabuµku typov polí
* \param flist Smerník na tabuµku typov polí
*/
void _free_field_types( ipfix_field_t **flist )
{
	ipfix_field_t *tmp, *n = *flist;

	while( n ) {
		tmp = n->next;
		free( n );
		n = tmp;
	}

	*flist = NULL;
}

/*!
* Funkcia na kódovanie a dekódovanie informaèných elementov
*/
int ipfix_encode_int( void *in, void *out, size_t len )
{
	unsigned char *i = (unsigned char*) in;
	unsigned char *o = (unsigned char*) out;
	uint16_t      tmp16;
	uint32_t      tmp32;
	uint64_t      tmp64;

	switch ( len )
	{
	case 1:
		o[0] = i[0];
		break;
	case 2:
		memcpy( &tmp16, i, len );
		tmp16 = htons( tmp16 ); 
		memcpy( out, &tmp16, len );
		break;
	case 4:
		memcpy( &tmp32, i, len );
		tmp32 = htonl( tmp32 ); 
		memcpy( out, &tmp32, len );
		break;
	case 8:
		memcpy( &tmp64, i, len );
		tmp64 = HTONLL( tmp64 ); 
		memcpy( out, &tmp64, len );
		break;
	default:
		memset( out, 0xff, len );
		return -1;
	}
	return 0;
}

/*!
* Funkcia na kódovanie a dekódovanie informaèných elementov
*/
int ipfix_decode_int( void *in, void *out, size_t len )
{
	unsigned char *i = (unsigned char*) in;
	unsigned char *o = (unsigned char*) out;
	uint16_t      tmp16;
	uint32_t      tmp32;
	uint64_t      tmp64;

	switch ( len )
	{
	case 1:
		o[0] = i[0];
		break;
	case 2:
		memcpy( &tmp16, i, len );
		tmp16 = ntohs( tmp16 ); 
		memcpy( out, &tmp16, len );
		break;
	case 4:
		memcpy( &tmp32, i, len );
		tmp32 = ntohl( tmp32 ); 
		memcpy( out, &tmp32, len );
		break;
	case 8:
		memcpy( &tmp64, i, len );
		tmp64 = NTOHLL( tmp64 ); 
		memcpy( out, &tmp64, len );
		break;
	default:
		memset( out, 0xff, len );
		return -1;
	}
	return 0;
}

/*!
* Funkcia na kódovanie a dekódovanie informaèných elementov
*/
int ipfix_snprint_int( char *str, size_t size, void *data, size_t len )
{
	int8_t       tmp8;
	int16_t      tmp16;
	int32_t      tmp32;
	int64_t      tmp64;

	switch ( len ) {
	  case 1:
		  memcpy( &tmp8, data, len );
		  return snprintf( str, size, "%d", tmp8 );
	  case 2:
		  memcpy( &tmp16, data, len );
		  tmp16 = ntohs( tmp16 ); 
		  return snprintf( str, size, "%d", tmp16 );
	  case 4:
		  memcpy( &tmp32, data, len );
		  tmp32 = ntohl( tmp32 ); 
		  return snprintf( str, size, "%d", tmp32 );
	  case 8:
		  memcpy( &tmp64, data, len );
		  tmp64 = NTOHLL( tmp64 ); 
		  return snprintf( str, size, "%lld", tmp64 );
	  default:
		  break;
	}
	return snprintf( str, size, "err" );
}

/*!
* Funkcia na kódovanie a dekódovanie informaèných elementov
*/
int ipfix_snprint_uint( char *str, size_t size, void *data, size_t len )
{
	uint8_t       tmp8;
	uint16_t      tmp16;
	uint32_t      tmp32;
	uint64_t      tmp64;

	switch ( len ) {
	  case 1:
		  memcpy( &tmp8, data, len );
		  return snprintf( str, size, "%u", tmp8 );
	  case 2:
		  memcpy( &tmp16, data, len );
		  tmp16 = htons( tmp16 ); 
		  return snprintf( str, size, "%u", tmp16 );
	  case 4:
		  memcpy( &tmp32, data, len );
		  tmp32 = htonl( tmp32 ); 
		  return snprintf( str, size, "%u", (unsigned int)tmp32 );
	  case 8:
		  memcpy( &tmp64, data, len );
		  tmp64 = HTONLL( tmp64 ); 
		  return snprintf( str, size, "%llu", tmp64 );
	  default:
		  break;
	}
	return snprintf( str, size, "err" );
}

/*!
* Funkcia na kódovanie a dekódovanie informaèných elementov
*/
int ipfix_encode_bytes( void *in, void *out, size_t len )
{
	if ( in != out )
		memcpy( out, in, len );
	return 0;
}

/*!
* Funkcia na kódovanie a dekódovanie informaèných elementov
*/
int ipfix_decode_bytes( void *in, void *out, size_t len )
{
	if ( in != out )
		memcpy( out, in, len );
	return 0;
}

/*!
* Funkcia na kódovanie a dekódovanie informaèných elementov
*/
int ipfix_snprint_bytes( char *str, size_t size, void *data, size_t len )
{
	size_t  i, n = 0;
	uint8_t *in = (uint8_t*) data;

	if ( size < 4 )
		return snprintf( str, size, "err" );

	while ( ((len*2) + 2) > size )
		len--;

	sprintf( str, "0x" );
	n = 2;
	for( i=0; i<len; i++ ) {
		sprintf( str+n, "%02x", *in );
		n += 2;
		in++;
	}
	return n;
}

/*!
* Funkcia na kódovanie a dekódovanie informaèných elementov
*/
int ipfix_snprint_string( char *str, size_t size, void *data, size_t len )
{
	ssize_t  i;
	uint8_t *in = (uint8_t*) data;

	for( i=len-1; i>=0; i-- ) {
		if ( in[i] == '\0' ) {
			return snprintf( str, size, "%s", in );
		}
	}

	if ( len < size ) {
		memcpy( str, in, len );
		str[len] = '\0';
		return len;
	}

	return snprintf( str, size, "err" );
}

/*!
* Funkcia na kódovanie a dekódovanie informaèných elementov
*/
int ipfix_snprint_ipaddr( char *str, size_t size, void *data, size_t len )
{
	uint8_t *in = (uint8_t*)data;
	char    tmpbuf[100];

	switch ( len ) {
	  case 4:
		  return snprintf( str, size, "%u.%u.%u.%u", 
			  in[0], in[1], in[2], in[3] );
	  case 16:
		  {
			  uint16_t  i, tmp16;

			  for( i=0, *tmpbuf=0; i<16; i+=2 ) {
				  memcpy( &tmp16, (char*)data+i, 2 );
				  tmp16 = htons( tmp16 ); 
				  sprintf( tmpbuf+strlen(tmpbuf), "%s%x", i?":":"", tmp16 );
			  }
			  return snprintf( str, size, "%s", tmpbuf );
		  }

	  default:
		  return ipfix_snprint_bytes( str, size, data, len );
	}
}

/*! 
* Funkcia na upratanie neznámych poloŸiek tabuµky polí
* \param f Tabuµka polí
*/
void ipfix_free_unknown_ftinfo( ipfix_field_t *f )
{
	if ( f ) {
		if ( f->ft ) {
			if ( f->ft->name )
				free( f->ft->name );
			if ( f->ft->documentation )
				free( f->ft->documentation );
			free( f->ft );
		}
		free( f );
	}
}

/*! 
* Funkcia na vytvorenie neznámych poloŸiek tabuµky polí
* \param eno Enterprise èíslo
* \param type Typ poµa
* \returns ftinfo z globálneho zoznamu alebo NULL
*/
ipfix_field_t *ipfix_create_unknown_ftinfo( int eno, int type )
{
	ipfix_field_t      *f;
	ipfix_field_type_t *ft;
	char               tmpbuf[50];

	if ( (f=(ipfix_field_t*)calloc(1, sizeof(ipfix_field_t))) ==NULL ) {
		return NULL;
	}
	if ( (ft=(ipfix_field_type_t*)calloc(1, sizeof(ipfix_field_type_t))) ==NULL ) {
		free( f );
		return NULL;
	}

	sprintf( tmpbuf, "%u_%u", eno, type );
	ft->name = strdup( tmpbuf );
	ft->documentation = strdup( tmpbuf );
	ft->eno    = eno;
	ft->ftype  = type;
	ft->coding = IPFIX_CODING_BYTES;

	f->next    = NULL;
	f->ft      = ft;
	f->encode  = ipfix_encode_bytes;
	f->decode  = ipfix_decode_bytes;
	f->snprint = ipfix_snprint_bytes;

	return f;
}

/*!
* Funckia vracia konkrétnu poloŸku zo zoznamu neznámych poloŸiek
* \param eno Enterprise èíslo
* \param type Typ poµa
* \returns ftinfo z globálneho zoznamu alebo NULL
*/
ipfix_field_t *ipfix_get_ftinfo( int eno, int type )
{
	ipfix_field_t *elems = g_ipfix_fields; 
	while( elems ) {
		if( (elems->ft->ftype == type) && (elems->ft->eno==eno) )
		{
			return elems;
		}
		elems = elems->next;
	}

	return NULL;
}

/*!
* Funkcia zabezpeèujúca inicializáciu IPFIX exportéra
*/
int ipfix_init ( void )
{
	if ( g_tstart ) {
		ipfix_cleanup();
	}

	g_tstart = time(NULL);
	signal( SIGPIPE, SIG_IGN );
	//nastavene na 256, aby sa generovali id >256
	g_lasttid = 256;	
	g_iobuf.next = NULL;
	g_buflist = &g_iobuf;

	// inicializuj zoznam informacnych elementov
	if ( ipfix_add_vendor_information_elements( ipfix_field_types ) <0 ) {
		return -1;
	}

	return 0;
}

/*!
* Funkcia pridá informaèné elementy definované v ipfix_def.h súbore do globálneho zoznamu typov polí
* \param fields - Pole o veµkosti nfields+1. Posledný èlen má ftype = 0
*/
int ipfix_add_vendor_information_elements( ipfix_field_type_t *fields )
{
	ipfix_field_type_t *ft;
	ipfix_field_t      *n;

	if ( ! g_tstart ) {          
		if ( ipfix_init() < 0 )
			return -1;
	}

	// pridanie do zoznamu typov poli
	ft = fields;
	while ( ft->ftype !=0 )
	{

		// vytovorenie noveho uzla
		if ((n=(ipfix_field_t*)calloc( 1, sizeof(ipfix_field_t))) !=NULL )
		{
			n->ft = ft;
			if ( ft->coding == IPFIX_CODING_INT ) {
				n->encode = ipfix_encode_int;
				n->decode = ipfix_decode_int;
				n->snprint= ipfix_snprint_int;
			}
			else if ( ft->coding == IPFIX_CODING_UINT ) {
				n->encode = ipfix_encode_int;
				n->decode = ipfix_decode_int;
				n->snprint= ipfix_snprint_uint;
			}
			else if ( ft->coding == IPFIX_CODING_STRING ) {
				n->encode = ipfix_encode_bytes;
				n->decode = ipfix_decode_bytes;
				n->snprint= ipfix_snprint_string;
			}
			else {
				n->encode = ipfix_encode_bytes;
				n->decode = ipfix_decode_bytes;
				switch( ft->ftype ) {
				  case IPFIX_FT_SOURCEIPV4ADDRESS:
				  case IPFIX_FT_DESTINATIONIPV4ADDRESS:
				  case IPFIX_FT_SOURCEIPV6ADDRESS:
				  case IPFIX_FT_DESTINATIONIPV6ADDRESS:
				  case IPFIX_FT_IPNEXTHOPIPV4ADDRESS:
				  case IPFIX_FT_BGPNEXTHOPIPV4ADDRESS:
					  n->snprint= ipfix_snprint_ipaddr;
					  break;
				  default:
					  n->snprint= ipfix_snprint_bytes;
					  break;
				}
			}

			// vlozenie uzla
			if ( g_ipfix_fields ) {
				n->next = g_ipfix_fields;
				g_ipfix_fields = n;
			}
			else {
				n->next = NULL;
				g_ipfix_fields = n;
			}
			ft++;
			continue;
		}
		else
		{
			_free_field_types( &g_ipfix_fields );
			return -1;
		}
	}

	return 0;
}

/*!
* Funkcia uprace pamä»ové alokácie
*/
void ipfix_cleanup ( void )
{
	while ( g_ipfixlist ) {
		ipfix_close( g_ipfixlist->ifh );
	}
	_free_field_types( &g_ipfix_fields );
	g_tstart = 0;
	if ( g_data.lens ) free( g_data.lens );
	if ( g_data.addrs ) free( g_data.addrs );
	g_data.maxfields = 0;
	g_data.lens  = NULL;
	g_data.addrs = NULL;
}

/*! 
* Pomocná funkcia na pripojenie sa ku zhromaŸïovaèu
* \param col ZhromaŸïovaè
*/
int _ipfix_connect ( ipfix_collector_t *col )
{
        char message[LOG_MESSAGE_SIZE];
	char   *server = col->chost;
	int    port    = col->cport;
	int    socktype, sockproto;
	int    sock = -1;
	struct sockaddr_in serv_addr;
	struct sockaddr_in6 serv_addr6;
	struct hostent      *h;


	switch( col->protocol ) {
	  case IPFIX_PROTO_TCP:
		  socktype = SOCK_STREAM;
		  sockproto= 0;
		  break;
	  case IPFIX_PROTO_UDP:
		  socktype = SOCK_DGRAM;
		  sockproto= 0;
		  break;
	  case IPFIX_PROTO_SCTP:
		  socktype = SOCK_STREAM;		  
		  sockproto= IPPROTO_SCTP;
		  break;
	  default:
		  errno = ENOTSUP;
		  col->fd = -1;
		  return -1;
	}

	if ( col->fd >= 0 )
		return 0;

	// zisti adresu
	if ( ((h=gethostbyname(server)) == NULL) && ((h=gethostbyname2(server,AF_INET6)) == NULL)) {
		sprintf(message,"Cannot get address of host '%s': %s",
			server, hstrerror(h_errno) );
		log_message(message,3);
		errno = EINVAL;
		return -1;
	}
        
        if ( (col->to = (struct sockaddr *)calloc( 1, sizeof(serv_addr) )) == NULL) {
            close(sock);
            return -1; 
        }

	if (h->h_addrtype == AF_INET) {
		memset((char *)&serv_addr, 0, sizeof(serv_addr));
		memcpy(&(serv_addr.sin_addr), h->h_addr, sizeof(struct in_addr));
		//inet_pton(AF_INET, h->h_addr_list[0], &serv_addr.sin_addr);
            	//char str[INET_ADDRSTRLEN];
            	//printf("\n%s\n\n", inet_ntop(AF_INET, &(serv_addr.sin_addr), str, INET_ADDRSTRLEN));
		serv_addr.sin_family  = AF_INET;
		serv_addr.sin_port    = htons(port);

		// otvor socket
		if ( (sock = socket( AF_INET, socktype, sockproto)) < 0 ) {
			sprintf(message,"Socket() failed: %s", strerror(errno) );
			log_message(message,3);
			return -1;
		}
                
        memcpy( col->to, &serv_addr, sizeof(serv_addr) );
        col->tolen = sizeof(serv_addr);
        col->to6 = NULL;
	}
	else {
    	memset((char *)&serv_addr6, 0, sizeof(serv_addr6));
    	memcpy(&(serv_addr6.sin6_addr), h->h_addr, sizeof(struct in6_addr));
		//char str[INET6_ADDRSTRLEN];
		//inet_ntop(AF_INET6, h->h_addr, str, INET6_ADDRSTRLEN);
		//inet_pton(AF_INET6, str,  &serv_addr6.sin6_addr);
		serv_addr6.sin6_family  = AF_INET6;
		serv_addr6.sin6_port    = htons(port);

		// otvor socket
		if ( (sock = socket( AF_INET6, socktype, sockproto)) < 0 ) {
		    sprintf(message,"Socket() failed: %s", strerror(errno) );
		    log_message(message,3);
		    return -1;
		}
                
        if ((col->to6 = (struct sockaddr_in6 *)calloc(1, sizeof(serv_addr6))) == NULL) {
            close(sock);
            return -1; 
        }
        memcpy( col->to6, &serv_addr6, sizeof(serv_addr6) );
        col->tolen = sizeof(serv_addr6);
        col->to->sa_family = AF_INET6;
        col->to->sa_data[0] = '\0';
	}
        
#if defined(IPFIX_EXPORTERTRANSPORTPORT) || (IPFIX_EXPORTERIPV4ADDRESS) || (IPFIX_EXPORTERIPV6ADDRESS)                
                struct sockaddr_in sin = {};
                socklen_t slen = sizeof(sin);
                bind(sock, (struct sockaddr *)&sin, slen);
                getsockname(sock, (struct sockaddr *)&sin, &slen);
        #ifdef IPFIX_EXPORTERTRANSPORTPORT
                exp_port = ntohs(sin.sin_port);
        #endif
                if (sin.sin_family == AF_INET) {
        #ifdef IPFIX_EXPORTERIPV4ADDRESS                    
                    exp_ip = sin.sin_addr;
        #endif                     
        #ifdef IPFIX_EXPORTERIPV6ADDRESS                    
                    inet_pton(AF_INET6, "::", &exp_ip6);
        #endif                    
                }
                else if (sin.sin_family == AF_INET6) {
        #ifdef IPFIX_EXPORTERIPV4ADDRESS
                    inet_pton(AF_INET, "0.0.0.0", &exp_ip);
        #endif               
        #ifdef IPFIX_EXPORTERIPV6ADDRESS                    
                    inet_pton(AF_INET6, "::", &exp_ip6);
        #endif                    
                }
#endif

	if ( col->protocol==IPFIX_PROTO_TCP || col->protocol==IPFIX_PROTO_SCTP ) {
        if (h->h_addrtype == AF_INET) {
			if ( _connect_nonb( sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr), 2 /*s*/ ) < 0) {
					close( sock );
					sock = -1; 
			} else {
				sprintf(message,"Connected to collector %s:%d via %s",col->chost, col->cport, (col->protocol == IPFIX_PROTO_TCP)? "TCP":"SCTP");
				log_message(message,6);
			}
        } else {
            //char str[INET6_ADDRSTRLEN];
			//inet_ntop(AF_INET6, &serv_addr6.sin6_addr, str, INET6_ADDRSTRLEN);
            //printf("\n%s\n\n", str);
                
            if ( _connect_nonb( sock, (struct sockaddr *)&serv_addr6, sizeof(serv_addr6), 2 /*s*/ ) < 0) {
				close( sock );
				sock = -1; 
			} else {
				sprintf(message,"Connected to collector %s:%d via %s",col->chost, col->cport, (col->protocol == IPFIX_PROTO_TCP)? "TCP":"SCTP");
				log_message(message,6);
			}
        }
	}  

	if (sock < 0 ) {
		sprintf(message,"Cannot connect to %s: %s", server, strerror(errno) );
		log_message(message,3);
		return (-1); 
	}

	col->fd = sock;
	col->lastaccess = time(NULL);

	// skontroluj, ci je potrebne preposlat niektore sablony
	/*{		
		ipfix_node_t      *node;
		ipfix_collector_t *cnode;
		ipfix_template_t  *tnode;

		for( node=g_ipfixlist; node!=NULL; node=node->next ) {
			for( cnode=(ipfix_collector_t*)node->ifh->collectors; 
				cnode!=NULL; cnode=cnode->next ) {
					if ( col == cnode ) {
						for( tnode=node->ifh->templates; 
							tnode!=NULL; tnode=tnode->next ) {
								if (_ipfix_write_template( node->ifh, tnode ) <0 )
									return -1;
						}
						break;
					}
			}
		}
	}*/
	return 0;

}

/*!
* Funkcia odpája IPFIX exportér od zhromaŸïovaèa
* \param col Deskriptor zhrmomaŸïovaèa
*/
void _ipfix_disconnect( ipfix_collector_t *col )
{
	if ( (col->protocol==IPFIX_PROTO_UDP) && (col->to || col->to6) ) {
            if (col->to) {
                free(col->to);
                col->to = NULL;
            }
            if (col->to6) {
                free(col->to6);
                col->to6 = NULL;
            }
	}	
	close( col->fd );
	col->fd = -1;
}

/*!
* Funkcia odo¹le IPFIX správu podµa vstupných parametrov a buffera
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param buf Buffer obsahujúci dáta na odoslanie
*/
int _ipfix_send_msg( ipfix_t *ifh, iobuf_t *buf )
{
        char message[LOG_MESSAGE_SIZE];
	int i, retval =-1;
	ipfix_collector_t *col = (ipfix_collector_t*) ifh->collectors;	
	int ret = 0;			

	switch( col->protocol )
	{	
	case IPFIX_PROTO_SCTP:				
            for( i=0; i<2; i++ ) {	
                if(i>0) {
                        //vloz sablonu do povodneho zaznamu, ktory je znovu odosielany				
                        if(ipfix_add_template(ifh, buf) < 0)
                                continue;

                }

                if (col->to->sa_family == AF_INET) {
                    if((ret = sctp_sendmsg( col->fd, buf->buffer, buf->buflen, col->to, col->tolen, 0, 0, 0, 0, 0 )) != buf->buflen) 			
                    {			
                        if ( errno == ECONNRESET || errno == EPIPE )
                            if(ipfix_reconnect(ifh) < 0)
                                return -1;
                            else
                                continue;
                        else {											
                            return -1;
                        }
                    }
                }
                else {
                    if((ret = sctp_sendmsg( col->fd, buf->buffer, buf->buflen, col->to6, col->tolen, 0, 0, 0, 0, 0 )) != buf->buflen) 			
                    {			
                        if ( errno == ECONNRESET || errno == EPIPE )
                            if(ipfix_reconnect(ifh) < 0)
                                return -1;
                            else
                                continue;
                        else {											
                            return -1;
                        }
                    }
                }

                _ipfix_freebuf( buf );
                retval =0;
                break;
            }
            //sprava o chybe v pripade neuspechu pri odosielani
            if(i == 2 && ret != buf->buflen) {							
                            sprintf(message,"Ipfix message dropped. Size: %d, Sequence number: %d",buf->buflen,ifh->seqno);					
                            log_message(message,3);
            }
            break;
	case IPFIX_PROTO_TCP:
		for( i=0; i<2; i++ )
		{
			ret = 0;
			if(i>0) {
				//vloz sablonu do povodneho zaznamu, ktory je znovu odosielany
				if(ipfix_add_template(ifh, buf) < 0)
					continue;
				
			}
			// posli IPFIX hlavicku
			if ( do_writen( col->fd, buf->buffer, IPFIX_HDR_BYTES ) 
				!= IPFIX_HDR_BYTES) {	
					ret = -1;				
					// ak je problem s pripojenim, pokus o znovupripojenie					
					if ( errno == ECONNRESET || errno == EPIPE )
						if(ipfix_reconnect(ifh) < 0)
							return -1;
						else
							continue;
					else {						
						return -1;
					}
			}
			// posli telo IPFIX spravy
			if ( do_writen( col->fd, buf->buffer+IPFIX_HDR_BYTES, 
				buf->buflen-IPFIX_HDR_BYTES ) 
				!= (int)(buf->buflen-IPFIX_HDR_BYTES)) {
					ret = -1;
					// ak je problem s pripojenim, pokus o znovupripojenie
					if ( errno == ECONNRESET || errno == EPIPE )
						if(ipfix_reconnect(ifh) < 0)
							return -1;
						else
							continue;
					else {						
						return -1;
					}
			}
			_ipfix_freebuf( buf );
			retval =0;
			break;
		}
		//sprava o chybe v pripade neuspechu pri odosielani
		if(i == 2 && ret < 0) {			
				sprintf(message,"Ipfix message dropped. Size: %d, Sequence number: %d",buf->buflen,ifh->seqno);
				log_message(message,3);
		}
		break;

	case IPFIX_PROTO_UDP:
		{			
			ssize_t n, nleft= buf->buflen;
			uint8_t *p = (uint8_t*)(buf->buffer);

			while( nleft>0 ) {
                            	if (col->to->sa_family == AF_INET6) {
		                        //char str[INET6_ADDRSTRLEN];
		                        //inet_ntop(AF_INET6, &col->to6->sin6_addr, str, INET6_ADDRSTRLEN);
		                        //printf("\n%s\n\n", str);
		                        n = sendto(col->fd, p, nleft, 0, (struct sockaddr*)col->to6, col->tolen);
                            	}
                            	else {
					n=sendto( col->fd, p, nleft, 0, col->to, col->tolen );
			    	}
				if ( n<=0 )
					return -1;

				nleft -= n;
				p     += n;
			}
			_ipfix_freebuf( buf );
			retval =0;
			break;
		}

	default:
		return -1;
	}

	col->lastaccess = time(NULL);
	return retval;
}

/*!
* Funkcia sa pokusi o znovupripojenie k definovanemu zhromazdovacu
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_reconnect(ipfix_t *ifh) {
        char message[LOG_MESSAGE_SIZE];
	discTime = 0;
	while(discTime < ((ipfix_collector_t *) ifh->collectors)->cconnTimeout && !capture_interrupted) {
		printf("\n");
		strcpy(message,"Connection lost. reconnect");
		log_message(message,3);
		_ipfix_disconnect(ifh->collectors);
		if(_ipfix_connect(ifh->collectors) < 0) {
			discTime += ((ipfix_collector_t *) ifh->collectors)->creconnectFreq;
			sleep(((ipfix_collector_t *) ifh->collectors)->creconnectFreq);
		} else {
			return 0;
		}
		
	}
	strcpy(message,"Connection timed out");
	
	return -1;
}

/*!
* Funkcia zapíse na zaciatok bufferu sablonu
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param buf Buffer, ktorý bude hlavièku obsahova»
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_add_template(ipfix_t *ifh, iobuf_t *buf) {
	//struktura do ktorej sa docasne ulozi sablonovy zaznam		
	ipfix_t *temp_ifh;
	int tsize = 0, range = 2, i;
	//alokacia potrebnej pamete
	temp_ifh = (ipfix_t *) calloc( 1, sizeof(ipfix_t) );
	temp_ifh->buffer = (char *) calloc(1,IPFIX_DEFAULT_BUFLEN+IPFIX_HDR_BYTES_NF9);
	//nastavenie hodnot potrebnych pre ipfix_write_template
	temp_ifh->offset = 0;
	temp_ifh->nrecords = 0;
	temp_ifh->version = IPFIX_VERSION;						
	//zistenie velkosti sablony				
	for ( tsize=8,i=0; i<ifh->templates->nfields; i++ ) {
		tsize += 4;
		if (ifh->templates->fields[i].elem->ft->eno != IPFIX_FT_NOENO)
			tsize += 4;
	}
	//docasne vlozenie sablonoveho zaznamu do definovanej struktury
	if(_ipfix_write_template(temp_ifh,ifh->templates) < 0) {
		return -1;
	}
	//prepis velkosti novej IPFIX spravy
	INSERTU16( buf->buffer+range, range, tsize + buf->buflen );
	INSERTU32( buf->buffer+range, range, time(NULL) );
	//posun datoveho zaznamu IPFIX spravy o velkost sablony
	memmove( buf->buffer + tsize + IPFIX_HDR_BYTES, buf->buffer+IPFIX_HDR_BYTES, buf->buflen - IPFIX_HDR_BYTES );	
	//vlozenie sablony do buffera IPFIX spravy
	memcpy(buf->buffer+IPFIX_HDR_BYTES, temp_ifh->buffer,tsize);
	buf->buflen = tsize + buf->buflen;
	return 0;
}

/*!
* Funkcia zapí¹e do bufferu hlavièku IPFIX správy
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param buf Buffer, ktorý bude hlavièku obsahova»
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int _ipfix_write_hdr( ipfix_t *ifh, iobuf_t *buf )
{
	time_t      now = time(NULL);
	
        // NF5 hlavicka - 24 bajtov
        if (ifh->version == IPFIX_VERSION_NF5) {
            buf->buflen = 0;
            char tmp = 1;
            INSERTU16(buf->buffer + buf->buflen, buf->buflen, ifh->version);
            INSERTU16(buf->buffer + buf->buflen, buf->buflen, ifh->nrecords);               // record count, max 30
            INSERTU32(buf->buffer + buf->buflen, buf->buflen, ((now - g_tstart) * 1000));
            INSERTU32(buf->buffer + buf->buflen, buf->buflen, now);
            INSERTU32(buf->buffer + buf->buflen, buf->buflen, (now * 1000000000));
            INSERTU32(buf->buffer + buf->buflen, buf->buflen, ifh->seqno);
            memcpy(buf->buffer + buf->buflen, &tmp, 1);
            buf->buflen++;
            memcpy(buf->buffer + buf->buflen, &tmp, 1);
            buf->buflen++;
            INSERTU16(buf->buffer + buf->buflen, buf->buflen, 1);
        }
	// NF9 hlavicka - 20 bajtov
	else if ( ifh->version == IPFIX_VERSION_NF9 ) {
		buf->buflen = 0;
		INSERTU16( buf->buffer+buf->buflen, buf->buflen, ifh->version );
		INSERTU16( buf->buffer+buf->buflen, buf->buflen, ifh->nrecords );
		INSERTU32( buf->buffer+buf->buflen, buf->buflen, ((now-g_tstart)*1000));
		INSERTU32( buf->buffer+buf->buflen, buf->buflen, now );
		INSERTU32( buf->buffer+buf->buflen, buf->buflen, ifh->seqno );
		INSERTU32( buf->buffer+buf->buflen, buf->buflen, ifh->sourceid );
	}
	// IPFIX hlavicka - 16 bajtov
	else {
		buf->buflen = 0;
		INSERTU16( buf->buffer+buf->buflen, buf->buflen, ifh->version );
		INSERTU16( buf->buffer+buf->buflen, buf->buflen, ifh->offset + IPFIX_HDR_BYTES );
		INSERTU32( buf->buffer+buf->buflen, buf->buflen, now );
		INSERTU32( buf->buffer+buf->buflen, buf->buflen, ifh->seqno );
		INSERTU32( buf->buffer+buf->buflen, buf->buflen, ifh->sourceid );
	}
	ifh->seqno ++;
	return 0;
}


/*!
* Funkcia zapí¹e do bufferu ¹ablóny IPFIX správy
* \param ifh ©truktúra obsahujúca kompletné informácie o spojení
* \param templ ©ablóny, ktoré sa majú zapísa»
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int _ipfix_write_template( ipfix_t *ifh, ipfix_template_t *templ )
{
	size_t            buflen, tsize=0, ssize=0, osize=0;
	char              *buf;
	uint16_t          tmp16;
	int               i, n;

	// vypocitaj velkost sablony, zisti miesto
	if ( templ->type == OPTION_TEMPLATE ) {
		for ( i=0, ssize=0; i<templ->nscopefields; i++ ) {
			ssize += 4;
			if (templ->fields[i].elem->ft->eno != IPFIX_FT_NOENO)
				ssize += 4;
		}
		for ( osize=0; i<templ->nfields; i++ ) {
			osize += 4;
			if (templ->fields[i].elem->ft->eno != IPFIX_FT_NOENO)
				osize += 4;
		}
		tsize = 10 + osize + ssize;
	} else {
		for ( tsize=8,i=0; i<templ->nfields; i++ ) {
			tsize += 4;
			if (templ->fields[i].elem->ft->eno != IPFIX_FT_NOENO)
				tsize += 4;
		}
	}
	if ( tsize+ifh->offset > IPFIX_DEFAULT_BUFLEN ) {
		ipfix_export_flush( ifh );
		if ( tsize+ifh->offset > IPFIX_DEFAULT_BUFLEN )
			return -1;
	}

	// zapis sablony pred datami
	if ( ifh->offset > 0 ) {
		memmove( ifh->buffer + tsize, ifh->buffer, ifh->offset );
	}

	// vloz sablony do buffera
	buf    = ifh->buffer;
	buflen = 0;
	ifh->nrecords ++;
	if ( ifh->version == IPFIX_VERSION_NF9 ) {
		INSERTU16( buf+buflen, buflen, IPFIX_SETID_TEMPLATE_NF9);
		INSERTU16( buf+buflen, buflen, tsize );
		INSERTU16( buf+buflen, buflen, templ->tid );
		if ( templ->type == OPTION_TEMPLATE ) {
			INSERTU16( buf+buflen, buflen, ssize );
			INSERTU16( buf+buflen, buflen, osize );
		} else {
			INSERTU16( buf+buflen, buflen, templ->nfields );
		}
	} else {
		INSERTU16( buf+buflen, buflen, IPFIX_SETID_TEMPLATE);
		INSERTU16( buf+buflen, buflen, tsize );
		INSERTU16( buf+buflen, buflen, templ->tid );
		if ( templ->type == OPTION_TEMPLATE ) {
			INSERTU16( buf+buflen, buflen, templ->nfields );
			INSERTU16( buf+buflen, buflen, templ->nscopefields );
		} else {
			INSERTU16( buf+buflen, buflen, templ->nfields );
		}
	}

	if ( templ->type == OPTION_TEMPLATE ) {
		n = templ->nfields;
		for ( i=0; i<templ->nscopefields; i++ ) {
			if ( templ->fields[i].elem->ft->eno == IPFIX_FT_NOENO ) {
				INSERTU16( buf+buflen, buflen, templ->fields[i].elem->ft->ftype );
				INSERTU16( buf+buflen, buflen, templ->fields[i].flength );
			} else {
				tmp16 = templ->fields[i].elem->ft->ftype|IPFIX_EFT_VENDOR_BIT;
				INSERTU16( buf+buflen, buflen, tmp16 );
				INSERTU16( buf+buflen, buflen, templ->fields[i].flength );
				INSERTU32( buf+buflen, buflen, templ->fields[i].elem->ft->eno );
			}
		}
	} else {
		i = 0;
		n = templ->nfields;
	}

	for ( ; i<templ->nfields; i++ )
	{
		if ( templ->fields[i].elem->ft->eno == IPFIX_FT_NOENO ) {
			INSERTU16( buf+buflen, buflen, templ->fields[i].elem->ft->ftype );
			INSERTU16( buf+buflen, buflen, templ->fields[i].flength );
		} else {
			tmp16 = templ->fields[i].elem->ft->ftype|IPFIX_EFT_VENDOR_BIT;
			INSERTU16( buf+buflen, buflen, tmp16 );
			INSERTU16( buf+buflen, buflen, templ->fields[i].flength );
			INSERTU32( buf+buflen, buflen, templ->fields[i].elem->ft->eno );
		}
	}
	templ->tsend = time(0);

	ifh->offset += buflen;
	printf("\n ### TEMPLATE SENT ###\n");
	return 0;
}

/*!
* Funkcia otvorí ipfix export
* \param ipfixh ©truktúra obsahujúca kompltné informácie o spojení
* \param sourceid Identifikátor meracieho procesu
* \param ipfix_version Verzia IPFIX protokolu (0x09 - NetFlow, 0xa0 - IPFIX)
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_open( ipfix_t **ipfixh, int sourceid, int ipfix_version )
{
	ipfix_t       *i;
	ipfix_node_t  *node;

	if ( ! g_tstart )         
	{
		// inicializacia modulu
		if ( ipfix_init() < 0 )
			return -1;
	}

	switch( ipfix_version ) {
            case IPFIX_VERSION_NF5:
                break;
            case IPFIX_VERSION_NF9:
                break;
            case IPFIX_VERSION:
                break;
            default:
                errno = ENOTSUP;
                return -1;
	}

	if ( (i=(ipfix_t*)calloc( 1, sizeof(ipfix_t) )) ==NULL )
		return -1;

	if ( (i->buffer=(char*)calloc( 1, IPFIX_DEFAULT_BUFLEN )) ==NULL ) {
		free( i );
		return -1;
	}

	i->sourceid  = sourceid;
	i->offset    = 0;
	i->version   = ipfix_version;
	i->seqno     = 0;

	// ulozenie globalneho zoznamu
	if ( (node=(ipfix_node_t*)calloc( 1, sizeof(ipfix_node_t))) ==NULL) {
		free(i->buffer);
		free(i);
		return -1;
	}
	node->ifh   = i;
	node->next  = g_ipfixlist;
	g_ipfixlist = node;

	*ipfixh = i;
	return 0;
}

/*!
* Funkcia otvorí ipfix export
* \param h ©truktúra obsahujúca kompltné informácie o spojení
* \returns 0 pri úspechu, -1 pri neúspechu
*/
void ipfix_close( ipfix_t *h )
{
	if ( h )
	{
		ipfix_node_t *l, *n;

		ipfix_export_flush( h );

		_ipfix_disconnect( (ipfix_collector_t*) h->collectors );
		while( h->collectors )
			_ipfix_drop_collector( (ipfix_collector_t**)&h->collectors );

		/** remove handle from global list
		*/
		for( l=g_ipfixlist, n=l; n!=NULL; n=n->next ) {
			if ( g_ipfixlist->ifh == h ) {
				g_ipfixlist = g_ipfixlist->next;
				break;
			}
			if ( n->ifh == h ) {
				l->next = n->next;
				break;
			}
			l = n;
		}
		if ( n )
			free( n );
		//        else
		//            EMSG("INTERNAL ERROR: ipfix node not found!" );
		free(h->buffer);
		free(h);
	}
}


/*!
* Pomocná funkcia na odstránenie zhromaŸïovaèa zo zoznamu zhromaŸïovaèov
* \param list Zoznam zhromaŸïovaèov
* \param node ZhromaŸïovaè, ktorý má by» odstránený
*/
void _drop_collector( ipfix_collector_t **list,
					 ipfix_collector_t *node )
{
	if ( !list || !(*list) || !node )
		return;

	if ( *list == node ) {
		*list = (*list)->next;
	}
	else {
		ipfix_collector_t *last = *list;
		ipfix_collector_t *n = (*list)->next;

		while( n ) {
			if ( n == node ) {
				last->next = n->next;
				break;
			}
			last = n;
			n = n->next;
		}
	}
}

/*!
* Funkcia na odstránenie zhromaŸïovaèa zo zoznamu zhromaŸïovaèov
* \param col ZhromaŸïovaè, ktorý má by» odstránený
*/
void _ipfix_drop_collector( ipfix_collector_t **col )
{
	if ( *col==NULL )
		return;

	(*col)->usecount--;
	if ( (*col)->usecount==0 )
	{
		ipfix_collector_t *node = *col;

		_drop_collector( &g_collectors, *col );
		*col = NULL;  /* todo! */
		free( node->chost );
		free( node );
	}
	else
	{
		*col = NULL;  /* todo! */
	}
	return;
}


/*!
* Funkcia pridá zhromaŸïovaè do zoznamu zhromaŸïovaèov
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param host Adresa zhromaŸïovaèa
* \param port Port na ktorom tento zhromaŸïovaè oèakáva dáta
* \param prot Protokol prenosu
* \param refreshTmpl Čas obnovenia šablóny
* \param prot reconnectFreq frekvencia znovupripájania k zhromažďovaču
* \param prot connTimeout čas vypršania spojenia
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_add_collector( ipfix_t *ifh, char *host, int port,
						ipfix_proto_t prot, int refreshTmpl, int reconnectFreq, int connTimeout )
{
	ipfix_collector_t *col;
	rfTmplTime = refreshTmpl;
	if ( (ifh==NULL) || (host==NULL)  )
		return -1;

	// zatial podporujeme len jeden zhromazdovac :(
	if ( ifh->collectors ) {
		errno = EAGAIN;
		return -1;
	}


	// zisti ci sa uz zhromazdovac pouziva
	for( col=g_collectors; col; col=col->next )
	{
		if ( (strcmp( col->chost, host ) ==0) 
			&& (col->cport==port) && (col->protocol==prot) )
		{

			// zhromazdovac najdeny
			col->usecount++;
			ifh->collectors = (void*)col;
			return 0;
		}
	}

	if ( (col=(ipfix_collector_t*)calloc( 1, sizeof(ipfix_collector_t))) ==NULL)
		return -1;

	if ( (col->chost=strdup( host )) ==NULL ) {
		free( col );
		return -1;
	}

	col->creconnectFreq = reconnectFreq;
	col->cconnTimeout = connTimeout;
	col->cport = port;
	switch ( prot ) {
	  case IPFIX_PROTO_TCP:
	  case IPFIX_PROTO_SCTP:
	  case IPFIX_PROTO_UDP:
		  col->protocol  = prot;
		  break;
	  default:
		  free( col->chost );
		  free( col );
		  errno = EPROTONOSUPPORT;   /* !! ENOTSUP */
		  return -1;
	}

	col->fd         = -1;
	col->usecount   = 1;
	col->next       = g_collectors;

	g_collectors    = col;
	ifh->collectors = (void*)col;


	// pripoj
	return _ipfix_connect( col );
}

/*!
* Funkcia pridá ¹ablónu do zoznamu ¹ablón
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu ktorá sa má do zoznamu prida»
* \param nfields Poèet polí v pridávanej ¹ablóne
* \param id identifikátor šablóny
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_new_template( ipfix_t          *ifh, 
					   ipfix_template_t **templ, 
					   int              nfields, 
					   int                   id )
{
	ipfix_template_t  *t;

	if ( !ifh || !templ || (nfields<1) ) {
		errno = EINVAL;
		return -1;
	}

	// alokuj pamat
	if ( (t=(ipfix_template_t*)calloc( 1, sizeof(ipfix_template_t) )) ==NULL )
		return -1;

	if ( (t->fields=(ipfix_template_field_t*)calloc( nfields, sizeof(ipfix_template_field_t) )) ==NULL ) {
		free(t);
		return -1;
	}

	// vygeneruj id sablony - este neimplementovane
	//g_lasttid++;
	t->tid       = id;
	t->nfields   = 0;
	t->maxfields = nfields;
	*templ       = t;

	// pridaj sablonu do zoznamu sablon
	t->next = ifh->templates;
	ifh->templates = t;
	return 0;
}


/*!
* Funkcia pridá novú dátovú ¹ablónu do zoznamu ¹ablón
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu ktorá sa má do zoznamu prida»
* \param nfields Poèet polí v pridávanej ¹ablóne
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_new_data_template( ipfix_t          *ifh, 
							ipfix_template_t **templ, 
							int              nfields,
							int 		     id )
{
	if ( ipfix_new_template( ifh, templ, nfields, id ) <0 )
		return -1;

	(*templ)->type = DATA_TEMPLATE;
	return 0;
}

/*!
* Funkcia pridá novú ¹ablónu s nastavením do zoznamu ¹ablón
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu ktorá sa má do zoznamu prida»
* \param nfields Poèet polí v pridávanej ¹ablóne
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_new_option_template( ipfix_t          *ifh, 
							  ipfix_template_t **templ, 
							  int              nfields )
{
	//TODO doriesit id sablony	
	if ( ipfix_new_template( ifh, templ, nfields, 0 ) <0 )
		return -1;

	(*templ)->type = OPTION_TEMPLATE;
	return 0;
}


/*!
* Funkcia pridá nové pole do aktuálnej ¹ablóny
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu do ktorej sa pole pridá
* \param eno Enterprise èíslo poµa
* \param type Dátový typ poµa
* \param length DåŸka poµa
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_add_field( ipfix_t          *ifh, 
					ipfix_template_t *templ, 
					uint32_t         eno,
					uint16_t         type,
					uint16_t         length )
{
	int i;

	if ( (templ->nfields < templ->maxfields)
		&& (type < IPFIX_EFT_VENDOR_BIT) ) {
			// nastav pole sablony
			i = templ->nfields;
			templ->fields[i].flength = length;
//			printf(" vysledok fcie je %s\n",ipfix_get_ftinfo( eno, type));
			if ((templ->fields[i].elem = ipfix_get_ftinfo( eno, type)) == NULL) {
				errno = EINVAL;
				return -1;
			}

			templ->nfields ++;
			templ->ndatafields ++;
	}
	else {
		errno = EINVAL;
		return -1;
	}

	return 0;
}


/*!
* Funkcia pridá nové pole rozsahu do aktuálnej ¹ablóny
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu do ktorej sa pole rozsahu pridá
* \param eno Enterprise èíslo poµa rozsahu
* \param type Dátový typ poµa rozsahu
* \param length DåŸka poµa rozsahu
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_add_scope_field( ipfix_t          *ifh, 
						  ipfix_template_t *templ, 
						  uint32_t         eno,
						  uint16_t         type,
						  uint16_t         length )
{
	int i;

	if ( templ->type != OPTION_TEMPLATE ) {
		errno = EINVAL;
		return -1;
	}

	if ( templ->nfields < templ->maxfields ) {

		if ( templ->ndatafields ) {
			// vloz rozsah este pred nastavenie
			memmove( &(templ->fields[templ->nscopefields+1]),
				&(templ->fields[templ->nscopefields]),
				templ->ndatafields * sizeof(ipfix_template_field_t) );
		}

		// nastav pole sablony
		i = templ->nscopefields;
		templ->fields[i].elem->ft->ftype = type;
		templ->fields[i].flength = length;

		if ((templ->fields[i].elem 
			= ipfix_get_ftinfo( eno, templ->fields[i].elem->ft->ftype))==NULL){
				errno = EINVAL;
				return -1;
		}

		templ->nscopefields ++;
		templ->nfields ++;
	}

	return 0;
}

/*!
* Funkcia získa novú ¹ablónu
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu ktorá sa vytvorí
* \param nfields Poèet polí vo vytváranej ¹ablóne
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_get_template( ipfix_t          *ifh, 
					   ipfix_template_t **templ, 
					   int              nfields, ... )
{
	ipfix_template_t  *t;
	int               i, error;
	uint16_t          ftype, flength;
	va_list           args;

	// vytvor novy sablonu
	//TODO doriesit id sablony
	if ( ipfix_new_template( ifh, &t, nfields, 0 ) <0 )
		return -1;

	// napln polia sablony
	va_start(args, nfields);
	for ( error=0, i=0; i<nfields; i++ )
	{
		ftype   = va_arg( args, int );
		flength = va_arg( args, int );
		if ( ipfix_add_field( ifh, t, 0, ftype, flength ) <0 )
			error =1;
	}
	va_end(args);

	if (error) {
		ipfix_delete_template( ifh, t );
		return -1;
	}

	*templ = t;
	return 0;
}


/*!
* Funkcia získa novú ¹ablónu
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu ktorá sa vytvorí
* \param nfields Poèet polí vo vytváranej ¹ablóne
* \param types Type nových vytvaraných polí
* \param lengths DåŸky nových vytváraných polí
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_get_template_array( ipfix_t          *ifh, 
							 ipfix_template_t **templ, 
							 int              nfields,
							 int              *types,
							 int              *lengths )
{
	ipfix_template_t  *t;
	int               i, error, len=0;

	// alokuj pamat
	if ( (t=(ipfix_template_t*)calloc( 1, sizeof(ipfix_template_t) )) ==NULL )
		return -1;

	if ( (t->fields=(ipfix_template_field_t*)calloc( nfields, sizeof(ipfix_template_field_t) )) ==NULL )
	{
		free(t);
		return -1;
	}

	// napln polia sablony
	for ( error=0, i=0; i<nfields; i++ )
	{
		t->fields[i].elem->ft->ftype = types[i];
		t->fields[i].flength = lengths[i];

		len += t->fields[i].flength;
		if ((t->fields[i].elem
			= ipfix_get_ftinfo( 0, t->fields[i].elem->ft->ftype )) ==NULL) {
				error =1;
		}
	}

	if (error) {
		errno = EINVAL;
		free(t);
		return -1;
	}

	// vygeneruj identifikator sablony - este neimplementovane
	g_lasttid++;
	t->tid = g_lasttid;
	t->nfields = nfields;
	*templ     = t;

	// pridaj sablonu do zoznamu sablon
	t->next = ifh->templates;
	ifh->templates = t;
	return 0;
}


/*!
* Funkcia uvoµní pamä» vytvorenej ¹ablóny
* \param templ Ukazovateµ na ¹ablónu ktorá uvoµní pamä»
*/
void ipfix_free_template( ipfix_template_t *templ )
{
	if ( templ )
	{
		if ( templ->fields )
			free( templ->fields );
		free( templ );
	}
}


/*!
* Funkcia vymaŸe ¹ablónu
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu ktorá sa vymaŸe
*/
void ipfix_delete_template( ipfix_t *ifh, ipfix_template_t *templ )
{
	ipfix_template_t *l, *n;

	if ( ! templ )
		return;

	// odstran sablonu zo zoznamu
	for( l=ifh->templates, n=l; n!=NULL; n=n->next ) {
		if ( ifh->templates==templ ) {
			ifh->templates = templ->next;
			break;
		}
		if ( n==templ ) {
			l->next = n->next;
			break;
		}
		l=n;
	}

	// uvolnit id sablony - este neimplementovane
	ipfix_free_template( templ );
}


/*!
* Funkcia vymaŸe ¹ablónu
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu ktorá sa vymaŸe
*/
void ipfix_release_template( ipfix_t *ifh, ipfix_template_t *templ )
{
	ipfix_delete_template( ifh, templ );
}

/*!
* Funkcia na export dát pomocou protokolu IPFIX cez IPFIX správu podµa daných parametrov spojenia.
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu ktorá sa pouŸije pri exporte
* \param buffer Buffer obsahujúci binárne dáta na export
* \returns 0 pri úspechu, -1 pri neúspechu
*/
//int ipfix_export( ipfix_t *ifh, ipfix_template_t *templ, ... )
int ipfix_export( ipfix_t *ifh, ipfix_template_t *templ, void *buffer )
{
	int i;
	int offset = 0;

	if ( !templ )
		return -1;
	if ( templ->nfields > g_data.maxfields ) {
		if ( g_data.addrs ) free( g_data.addrs );
		if ( g_data.lens ) free( g_data.lens );
		if ( (g_data.lens=(uint16_t*)calloc( templ->nfields, sizeof(uint16_t))) ==NULL) {
			g_data.maxfields = 0;
			return -1;
		}
		if ( (g_data.addrs=(void**)calloc( templ->nfields, sizeof(void*))) ==NULL) {
			free( g_data.lens );
			g_data.lens = NULL;
			g_data.maxfields = 0;
			return -1;
		}      
		g_data.maxfields = templ->nfields;
	}

	// zozbieraj smerniky

	for ( i=0; i<templ->nfields; i++ )
	{
		g_data.addrs[i] = (char*)buffer+offset;
		g_data.lens[i] = templ->fields[i].flength;
		offset+=templ->fields[i].flength;
	}


	return ipfix_export_array( ifh, templ, templ->nfields, g_data.addrs, g_data.lens );
}


/*!
* Funkcia vykonáva vlastný export dát pomocou protokolu IPFIX cez IPFIX správu podµa daných parametrov spojenia.
* \param ifh ©truktúra obsahujúca kompltné informácie o spojení
* \param templ Ukazovateµ na ¹ablónu ktorá sa pouŸije pri exporte
* \param nfields Poèet exportovaných polí
* \param fields Smerníky na exportované polia
* \param lengths Pole dåŸok jednotlivých exportovaných polí
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int ipfix_export_array( ipfix_t          *ifh, 
					   ipfix_template_t *templ,
					   int              nfields, 
					   void             **fields,
					   uint16_t         *lengths )
{
	int               i;
	size_t            buflen, datasetlen;
	uint8_t           *p, *buf;
	static int	  sent = 0;

	// skontroluj parametre
	if ( (templ==NULL) || (nfields!=templ->nfields) ) {
		errno = EINVAL;
		return -1;
	}
        
        if (ifh->version != IPFIX_VERSION_NF5) {
            // vloz sablonovu sadu
            if((sent==0 && (((ipfix_collector_t *) ifh->collectors)->protocol == IPFIX_PROTO_SCTP || ((ipfix_collector_t *) ifh->collectors)->protocol == IPFIX_PROTO_TCP)) || ((ipfix_collector_t *) ifh->collectors)->protocol == IPFIX_PROTO_UDP) {
                    if ( ((time(0) - templ->tsend) >= rfTmplTime) && (_ipfix_write_template( ifh, templ )<0) ) {
                            return -1;
                    } else {
                            sent = 1;
                    }
            }
        }

        if (ifh->version == IPFIX_VERSION_NF5)
            datasetlen = 3;
        else
            datasetlen = 4;
        
	// zisti velkost dat a skontroluj pre nich miesto
	for ( i=0; i<nfields; i++ ) {
		if ( templ->fields[i].flength == IPFIX_FT_VARLEN ) {
			if ( lengths[i]>254 )
				datasetlen += 3;
			else
				datasetlen += 1;
		} else {
			if ( lengths[i] > templ->fields[i].flength ) {
				errno = EINVAL;
				return -1;
			}
		}
		datasetlen += lengths[i];
	}
	if ( ((ifh->offset + datasetlen) > IPFIX_DEFAULT_BUFLEN )
		&& (ipfix_export_flush( ifh ) <0) ) {
			return -1;
	}

	// napln buffer
	buf    = (uint8_t*)(ifh->buffer) + ifh->offset;
	buflen = 0;
    ifh->nrecords ++;

    if (ifh->version != IPFIX_VERSION_NF5) {
        // vloz data
        INSERTU16( buf+buflen, buflen, templ->tid );
        INSERTU16( buf+buflen, buflen, datasetlen );
    }

	// napln polozky sablony
	for ( i=0; i<nfields; i++ ) {
		if ( templ->fields[i].flength == IPFIX_FT_VARLEN ) {
			if ( lengths[i]>254 ) {
				*(buf+buflen) = 0xFF;
				buflen++;
				INSERTU16( buf+buflen, buflen, lengths[i] );
			}
			else {
				*(buf+buflen) = lengths[i];
				buflen++;
			}
		}
		p = (uint8_t*)fields[i];
		if ( templ->fields[i].relay_f ) {
			ipfix_encode_bytes( p, buf+buflen, lengths[i] );
		}
		else {
			templ->fields[i].elem->encode( p, buf+buflen, lengths[i] );
		}
		buflen += lengths[i];
	}

	ifh->offset += buflen;
	return 0;
}

/*!
* Funkcia vykonáva odoslanie správy a uzavretie exportu
* \param ifh ©truktúra obsahujúca kompletné informácie o spojení
* \returns 0 pri úspechu, -1 pri neúspechu
*/
int  ipfix_export_flush( ipfix_t *ifh )
{	
	iobuf_t *buf;

	if ( (ifh==NULL) || (ifh->offset==0) )
		return 0;
	
	if ( (buf=_ipfix_getbuf()) ==NULL )
		return -1;	

	//    DMSG("Records exported: %d", ifh->nrecords );	

	_ipfix_write_hdr( ifh, buf );
	memcpy( buf->buffer+buf->buflen, ifh->buffer, ifh->offset );
	buf->buflen += ifh->offset;

	ifh->offset = 0;
	ifh->nrecords = 0;	
	if ( _ipfix_send_msg( ifh, buf ) <0 )
	{
		_ipfix_freebuf( buf );
		return -1;
	}

	return 0;
}
