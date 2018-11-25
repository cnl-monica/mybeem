/*! \file ipfix.h
*  \brief Hlavi�kov� s�bor modulu pre ipfix export
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

#ifndef IMP_IPFIX_H
#define IMP_IPFIX_H

#include <inttypes.h>
#include "ipfix_def.h"


typedef struct {
	/*! 
	* Verzia z�znamu o toku
	*/
	uint16_t   version;  
	union {
		struct {
			/*! 
			* Celkov� po�et paketov v tejto spr�ve
			*/
			uint16_t   count;       
			/*! 
			* SysUpTime v milisekund�ch
			*/
			uint32_t   sysuptime;
			/*! 
			* Po�et sek�nd od epochy
			*/
			uint32_t   unixtime;
		} nf9;
		struct {
			/*! 
			* D�ka tejto IPFIX spr�vy
			*/
			uint16_t   length;     
			/*! 
			* �as exportu IPFIX spr�vy
			*/
			uint32_t   exporttime; 
		} ipfix;
	} u;
	/*! 
	* Sekven�n� inkrement�lne po��tadlo
	*/
	uint32_t   seqno;       
	/*! 
	* Identofik�tor exportovacej dom�ny
	*/
	uint32_t   sourceid;

} ipfix_hdr_t;

// Definicia hodnoty 5. verzie protokolu NetFlow
#define IPFIX_VERSION_NF5   0x05
/*! 
* Defin�cia verzie NetFlow v9
*/
#define IPFIX_VERSION_NF9           0x09
/*! 
* Defin�cia ve�kosti hlavi�ky NetFlow v9
*/
#define IPFIX_HDR_BYTES_NF9         20
/*! 
* Defin�cia identifik�tora �abl�ny pre NF9
*/
#define IPFIX_SETID_TEMPLATE_NF9    0
/*! 
* Defin�cia identifik�tora �abl�ny s nastaven�m pre NF9
*/
#define IPFIX_SETID_OPTTEMPLATE_NF9 1

/*! 
* Defin�cia verzie IPFIX
*/
#define IPFIX_VERSION               0x0A
/*! 
* Defin�cia ve�kosti hlavi�ky IPFIX
*/
#define IPFIX_HDR_BYTES             16
/*! 
* Defin�cia identifik�tora �abl�ny pre IPFIX
*/
#define IPFIX_SETID_TEMPLATE        2
/*! 
* Defin�cia identifik�tora �abl�ny s nastaven�m pre IPFIX
*/
#define IPFIX_SETID_OPTTEMPLATE     3
/*! 
* Defin�cia varabilnej d�ky
*/
#define IPFIX_FT_VARLEN             65535
/*! 
* Defin�cia kon�tanty pre nepr�tomn� enterprise ��slo
*/
#define IPFIX_FT_NOENO              0
#define IPFIX_EFT_VENDOR_BIT        0x8000

/*! 
* Defin�cia portu IPFIX
*/
#define IPFIX_PORTNO                4739

/*! 
* Defin�cia �tandardnej d�ku buffera
*/
#define IPFIX_DEFAULT_BUFLEN  1400

/*!
* Nosn� protokol
*/
typedef enum {
	/*! 
	* Protokol TCP
	*/
	IPFIX_PROTO_TCP  = 6,      /* IPPROTO_TCP  */     
	/*! 
	* Protokol UDP
	*/
	IPFIX_PROTO_UDP  = 17,     /* IPPROTO_UDP  */   
	/*! 
	* Protokol SCTP
	*/
	IPFIX_PROTO_SCTP  = 132    /* IPPROTO_SCTP  */     
} ipfix_proto_t;

/*! 
* Defin�cia typui po�a �abl�ny
*/
typedef struct
{
	/*! 
	* D�ka pol�
	*/
	uint16_t            flength;           /* less or eq. elem->flength  */
	/*! 
	* Pr�znak nezn�meho elementu
	*/
	int                 unknown_f;         /* set if unknown elem */
	/*! 
	* Pr�znak relayovania pol�
	*/
	int                 relay_f; 
	/*! 
	* Element
	*/
	ipfix_field_t       *elem;
} ipfix_template_field_t;

/*! 
* Defin�cia typu d�tov�ho z�znamu
*/
typedef struct ipfix_datarecord
{
	/*! 
	* Adresy hodn�t
	*/
	void              **addrs;
	/*! 
	* D�ky hodn��
	*/
	uint16_t          *lens;
	/*! 
	* Max. po�et pol�
	*/
	uint16_t          maxfields;         
} ipfix_datarecord_t;

/*! 
* Enumer�cia kon�t�nt identifikuj�cich �abl�ny
*/
typedef enum {
	DATA_TEMPLATE, OPTION_TEMPLATE
} ipfix_templ_type_t;

/*! 
* Typ pre IPFIX �abl�nu
*/
typedef struct ipfix_template
{

	/*! 
	* Vn�torn� smern�k
	*/
	struct ipfix_template   *next; 
	/*! 
	* Typ �abl�ny
	*/
	ipfix_templ_type_t      type;  
	/*! 
	* �as posledn�ho prenosu �abl�ny
	*/
	time_t                  tsend;
	/*! 
	* Identifik�tor �abl�ny
	*/
	uint16_t                tid;
	/*! 
	* Po�et d�tov�ch pol�
	*/
	int                     ndatafields;
	/*! 
	* Po�et pol� s rozsahom
	*/
	int                     nscopefields;
	/*! 
	* Celkov� po�et pol�
	*/
	int                     nfields;
	/*! 
	* Smern�k na polia
	*/
	ipfix_template_field_t  *fields;
	/*! 
	* Maxim�lny po�et pol�
	*/
	int                     maxfields;
} ipfix_template_t;


/*! 
* Typ pre IPFIX export
*/
typedef struct
{
	/*! 
	* Identifik�tor exportovacej dom�ny
	*/
	int              sourceid;    
	/*! 
	* Verzia exportu
	*/
	int              version;    
	/*! 
	* Zoznam zhroma��ova�ov
	*/
	void             *collectors;
	/*! 
	* Zoznam �abl�n
	*/
	ipfix_template_t *templates; 

	/*! 
	* V�stupn� buffer
	*/
	char        *buffer;      
	/*! 
	* Po�et z�znamov v buffri
	*/
	int         nrecords;         
	/*! 
	* Offset v buffri
	*/
	size_t      offset;           
	/*! 
	* Sekven�n� ��slo spr�vy
	*/
	uint32_t    seqno;            
} ipfix_t;


int  ipfix_open( ipfix_t **ifh, int sourceid, int ipfix_version ); 
int  ipfix_add_collector( ipfix_t *ifh, char *host, int port, ipfix_proto_t protocol, int refreshTmpl, int reconnectFreq, int connTimeout );
int  ipfix_new_data_template( ipfix_t *ifh, ipfix_template_t **templ, int nfields, int id );
int  ipfix_new_option_template( ipfix_t *ifh, ipfix_template_t **templ, int nfields );
int  ipfix_add_field( ipfix_t *ifh, ipfix_template_t *templ, uint32_t enterprise_number, uint16_t type, uint16_t length );
int  ipfix_add_scope_field( ipfix_t *ifh, ipfix_template_t *templ, uint32_t enterprise_number, uint16_t type, uint16_t length );
void ipfix_delete_template( ipfix_t *ifh, ipfix_template_t *templ );
int  ipfix_export( ipfix_t *ifh, ipfix_template_t *templ, void *buffer );
int  ipfix_export_flush( ipfix_t *ifh );
void ipfix_close( ipfix_t *ifh );
int  ipfix_export_array( ipfix_t *ifh, ipfix_template_t *templ, int nfields, void **fields, uint16_t *lengths );

int  ipfix_init( void );
int  ipfix_add_vendor_information_elements( ipfix_field_type_t *fields );
ipfix_field_type_t findIEField(int ie);
void updateIeLenghts();
void ipfix_cleanup( void );


#endif
