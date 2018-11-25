/*! \file ipfix_def.h
*  \brief Hlavi�kov� s�bor obsahuj�ci defin�cie pre informa�n� elementy IPFIX protokolu
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

#ifndef IPFIX_DEF_H
#define IPFIX_DEF_H

#include <sys/types.h>

/*! 
* Defin�cia k�dovania typu int
*/
#define IPFIX_CODING_INT    1
/*! 
* Defin�cia k�dovania typu unsigned int
*/
#define IPFIX_CODING_UINT   2
/*! 
* Defin�cia k�dovania bajtov
*/
#define IPFIX_CODING_BYTES  3
/*! 
* Defin�cia k�dovania re�azcov
*/
#define IPFIX_CODING_STRING 4
/*! 
* Defin�cia k�dovania typu float
*/
#define IPFIX_CODING_FLOAT 5
/*! 
* Defin�cia k�dovania boolean
*/
#define IPFIX_CODING_BOOL 6

/*! 
* Defin�cia k�dovacej funkcie
*/
typedef int (*ipfix_encode_func) (void *, void*, size_t);
/*! 
* Defin�cia k�dovacej funkcie
*/
typedef int (*ipfix_decode_func) (void *, void*, size_t);
/*! 
* Defin�cia k�dovacej funkcie
*/
typedef int (*ipfix_snprint_func) (char *, size_t, void*, size_t);

/*! 
* Typ informa�n�ho elementu pre export
*/
typedef struct
{
	/*! 
	* Enterprise ��slo IE
	*/
	int         eno;
	/*! 
	* Typ IE
	*/
	int         ftype;
	/*! 
	* D�ka IE
	*/
	ssize_t     length;
	/*! 
	* K�dovanie IE
	*/
	int         coding;
	/*! 
	* Pomenovanie IE
	*/
	char        *name;
	/*! 
	* Dokument�cia IE
	*/
	char        *documentation;

} ipfix_field_type_t;

/*! 
* Defin�cia typu po�a pre export
*/
typedef struct ipfix_field
{
	/*! 
	* Intern� smern�k
	*/
	struct ipfix_field   *next;
	/*! 
	* Typ po�a
	*/
	ipfix_field_type_t   *ft;
	/*! 
	* Smern�k na kovaciu funkciu
	*/
	ipfix_encode_func    encode;
	/*! 
	* Smern�k na dek�dovaciu funkciu
	*/
	ipfix_decode_func    decode;
	/*! 
	* Smern�k na konvertovaciu funkciu
	*/
	ipfix_snprint_func   snprint;

} ipfix_field_t;

#define IPFIX_FT_OCTETDELTACOUNT              1
#define IPFIX_FT_PACKETDELTACOUNT             2
#define IPFIX_FT_OBSERVEDFLOWTOTALCOUNTNF     3
#define IPFIX_FT_PROTOCOLIDENTIFIER           4
#define IPFIX_FT_CLASSOFSERVICEIPV4           5
#define IPFIX_FT_TCPCONTROLBITS               6
#define IPFIX_FT_SOURCETRANSPORTPORT          7
#define IPFIX_FT_SOURCEIPV4ADDRESS            8
#define IPFIX_FT_SOURCEIPV4MASK               9
#define IPFIX_FT_INGRESSINTERFACE             10
#define IPFIX_FT_DESTINATIONTRANSPORTPORT     11
#define IPFIX_FT_DESTINATIONIPV4ADDRESS       12
#define IPFIX_FT_DESTINATIONIPV4MASK          13
#define IPFIX_FT_EGRESSINTERFACE              14
#define IPFIX_FT_IPNEXTHOPIPV4ADDRESS         15
#define IPFIX_FT_BGPSOURCEASNUMBER            16
#define IPFIX_FT_BGPDESTINATIONASNUMBER       17
#define IPFIX_FT_BGPNEXTHOPIPV4ADDRESS        18
#define IPFIX_FT_POSTMCASTPACKETDELTACOUNT    19
#define IPFIX_FT_POSTMCASTOCTETDELTACOUNT     20
#define IPFIX_FT_FLOWENDSYSUPTIME             21
#define IPFIX_FT_FLOWSTARTSYSUPTIME           22
#define IPFIX_FT_POSTOCTETDELTACOUNT          23
#define IPFIX_FT_POSTPACKETDELTACOUNT         24
#define IPFIX_FT_MINIMUMPACKETLENGTH          25
#define IPFIX_FT_MAXIMUMPACKETLENGTH          26
#define IPFIX_FT_SOURCEIPV6ADDRESS            27
#define IPFIX_FT_DESTINATIONIPV6ADDRESS       28
#define IPFIX_FT_SOURCEIPV6MASK               29
#define IPFIX_FT_DESTINATIONIPV6MASK          30
#define IPFIX_FT_FLOWLABELIPV6                31
#define IPFIX_FT_ICMPTYPECODEIPV4             32
#define IPFIX_FT_IGMPTYPE                     33
#define IPFIX_FT_FLOWACTIVETIMEOUT            36
#define IPFIX_FT_FLOWINACTIVETIMEOUT          37
#define IPFIX_FT_EXPORTEDOCTETTOTALCOUNT      40
#define IPFIX_FT_EXPORTEDMESSAGETOTALCOUNT    41
#define IPFIX_FT_EXPORTEDFLOWTOTALCOUNT       42
#define IPFIX_FT_SOURCEIPV4PREFIX             44
#define IPFIX_FT_DESTINATIONIPV4PREFIX        45
#define IPFIX_FT_MPLSTOPLABELTYPE             46
#define IPFIX_FT_MPLSTOPLABELIPV4ADDRESS      47
#define IPFIX_FT_MINIMUMTTL                   52
#define IPFIX_FT_MAXIMUMTTL                   53
#define IPFIX_FT_IDENTIFICATIONIPV4           54
#define IPFIX_FT_POSTCLASSOFSERVICEIPV4       55
#define IPFIX_FT_SOURCEMACADDRESS             56
#define IPFIX_FT_POSTDESTINATIONMACADDR       57
#define IPFIX_FT_VLANID                       58
#define IPFIX_FT_POSTVLANID                   59
#define IPFIX_FT_IPVERSION                    60
#define IPFIX_FT_FLOWDIRECTION		      61
#define IPFIX_FT_IPNEXTHOPIPV6ADDRESS         62
#define IPFIX_FT_BGPNEXTHOPIPV6ADDRESS        63
#define IPFIX_FT_IPV6EXTENSIONHEADERS         64
#define IPFIX_FT_MPLSTOPLABELSTACKENTRY       70
#define IPFIX_FT_MPLSLABELSTACKENTRY2         71
#define IPFIX_FT_MPLSLABELSTACKENTRY3         72
#define IPFIX_FT_MPLSLABELSTACKENTRY4         73
#define IPFIX_FT_MPLSLABELSTACKENTRY5         74
#define IPFIX_FT_MPLSLABELSTACKENTRY6         75
#define IPFIX_FT_MPLSLABELSTACKENTRY7         76
#define IPFIX_FT_MPLSLABELSTACKENTRY8         77
#define IPFIX_FT_MPLSLABELSTACKENTRY9         78
#define IPFIX_FT_MPLSLABELSTACKENTRY10        79
#define IPFIX_FT_DESTINATIONMACADDRESS        80
#define IPFIX_FT_POSTSOURCEMACADDRESS         81
#define IPFIX_FT_OCTETTOTALCOUNT              85
#define IPFIX_FT_PACKETTOTALCOUNT             86
#define IPFIX_FT_FRAGMENTOFFSETIPV4           88
#define IPFIX_FT_MPLSVPNROUTEDISTINGUISHER    90
#define IPFIX_FT_APPLICATIONID                95
#define IPFIX_FT_APPLICATIONNAME              96
#define IPFIX_FT_BGPNEXTADJACENTASNUMBER      128
#define IPFIX_FT_BGPPREVADJACENTASNUMBER      129
#define IPFIX_FT_EXPORTERIPV4ADDRESS          130
#define IPFIX_FT_EXPORTERIPV6ADDRESS          131
#define IPFIX_FT_DROPPEDOCTETDELTACOUNT       132
#define IPFIX_FT_DROPPEDPACKETDELTACOUNT      133
#define IPFIX_FT_DROPPEDOCTETTOTALCOUNT       134
#define IPFIX_FT_DROPPEDPACKETTOTALCOUNT      135
#define IPFIX_FT_FLOWENDREASON                136
/*
#define IPFIX_FT_CLASSOFSERVICEIPV6           137
#define IPFIX_FT_POSTCLASSOFSERVICEIPV6       138
*/
#define IPFIX_FT_COMMONPROPERTIESID           137
#define IPFIX_FT_OBSERVATIONPOINTID           138

#define IPFIX_FT_ICMPTYPECODEIPV6             139
#define IPFIX_FT_MPLSTOPLABELIPV6ADDRESS      140
#define IPFIX_FT_LINECARDID                   141
#define IPFIX_FT_PORTID                       142
#define IPFIX_FT_METERINGPROCESSID            143
#define IPFIX_FT_EXPORTINGPROCESSID           144
#define IPFIX_FT_TEMPLATEID                   145
#define IPFIX_FT_WLANCHANNELID                146
#define IPFIX_FT_WLANSSID                     147
#define IPFIX_FT_FLOWID                       148
#define IPFIX_FT_OBSERVATIONDOMAINID          149
#define IPFIX_FT_FLOWSTARTSECONDS             150
#define IPFIX_FT_FLOWENDSECONDS               151
#define IPFIX_FT_FLOWSTARTMILLISECONDS        152
#define IPFIX_FT_FLOWENDMILLISECONDS          153
#define IPFIX_FT_FLOWSTARTMICROSECONDS        154
#define IPFIX_FT_FLOWENDMICROSECONDS          155
#define IPFIX_FT_FLOWSTARTNANOSECONDS         156
#define IPFIX_FT_FLOWENDNANOSECONDS           157
#define IPFIX_FT_FLOWSTARTDELTAMICROSECONDS   158
#define IPFIX_FT_FLOWENDDELTAMICROSECONDS     159
#define IPFIX_FT_SYSTEMINITTIMEMILLISECONDS   160
#define IPFIX_FT_FLOWDURATIONMILLISECONDS     161
//#define IPFIX_FT_IPNEXTHOPASNUMBER            162
#define IPFIX_FT_FLOWDURATIONMICROSECONDS     162
#define IPFIX_FT_OBSERVEDFLOWTOTALCOUNT       163
#define IPFIX_FT_IGNOREDPACKETTOTALCOUNT      164
#define IPFIX_FT_IGNOREDOCTETTOTALCOUNT       165
#define IPFIX_FT_NOTSENTFLOWTOTALCOUNT        166
#define IPFIX_FT_NOTSENTPACKETTOTALCOUNT      167
#define IPFIX_FT_NOTSENTOCTETTOTALCOUNT       168
#define IPFIX_FT_DESTINATIONIPV6PREFIX        169
#define IPFIX_FT_SOURCEIPV6PREFIX             170
#define IPFIX_FT_POSTOCTETTOTALCOUNT          171
#define IPFIX_FT_POSTPACKETTOTALCOUNT         172
#define IPFIX_FT_FLOWKEYINDICATOR             173
#define IPFIX_FT_POSTMCASTPACKETTOTALCOUNT    174
#define IPFIX_FT_POSTMCASTOCTETTOTALCOUNT     175
#define IPFIX_FT_ICMPTYPEIPV4                 176
#define IPFIX_FT_ICMPCODEIPV4                 177
#define IPFIX_FT_ICMPTYPEIPV6                 178
#define IPFIX_FT_ICMPCODEIPV6                 179
#define IPFIX_FT_UDPSOURCEPORT                180
#define IPFIX_FT_UDPDESTINATIONPORT           181
#define IPFIX_FT_TCPSOURCEPORT                182
#define IPFIX_FT_TCPDESTINATIONPORT           183
#define IPFIX_FT_TCPSEQUENCENUMBER            184
#define IPFIX_FT_TCPACKNOWLEDGEMENTNUMBER     185
#define IPFIX_FT_TCPWINDOWSIZE                186
#define IPFIX_FT_TCPURGENTPOINTER             187
#define IPFIX_FT_TCPHEADERLENGTH              188
#define IPFIX_FT_IPHEADERLENGTH               189
#define IPFIX_FT_TOTALLENGTHIPV4              190
#define IPFIX_FT_PAYLOADLENGTHIPV6            191
#define IPFIX_FT_IPTIMETOLIVE                 192
#define IPFIX_FT_NEXTHEADERIPV6               193
#define IPFIX_FT_IPCLASSOFSERVICE             194
#define IPFIX_FT_IPDIFFSERVCODEPOINT          195
#define IPFIX_FT_IPPRECEDENCE                 196
#define IPFIX_FT_FRAGMENTFLAGSIPV4            197
#define IPFIX_FT_OCTETDELTASUMOFSQUARES       198
#define IPFIX_FT_OCTETTOTALSUMOFSQUARES       199
#define IPFIX_FT_MPLSTOPLABELTTL              200
#define IPFIX_FT_MPLSLABELSTACKLENGTH         201
#define IPFIX_FT_MPLSLABELSTACKDEPTH          202
#define IPFIX_FT_MPLSTOPLABELEXP              203
#define IPFIX_FT_IPPAYLOADLENGTH              204
#define IPFIX_FT_UDPMESSAGELENGTH             205
#define IPFIX_FT_ISMULTICAST                  206
#define IPFIX_FT_INTERNETHEADERLENGTHIPV4     207
#define IPFIX_FT_IPV4OPTIONS                  208
#define IPFIX_FT_TCPOPTIONS                   209
#define IPFIX_FT_PADDINGOCTETS                210
//********************************************
#define IPFIX_FT_COLLECTORIPV4ADDRESS         211
#define IPFIX_FT_COLLECTORIPV6ADDRESS         212
#define IPFIX_FT_EXPORTINTERFACE              213
#define IPFIX_FT_EXPORTPROTOCOLVERSION        214
#define IPFIX_FT_EXPORTTRANSPORTPROTOCOL      215
//******************************************** 
#define IPFIX_FT_COLLECTORTRANSPORTPORT       216
#define IPFIX_FT_EXPORTERTRANSPORTPORT        217
#define IPFIX_FT_TCPSYNTOTALCOUNT             218
#define IPFIX_FT_TCPFINTOTALCOUNT             219
#define IPFIX_FT_TCPRSTTOTALCOUNT             220
#define IPFIX_FT_TCPPSHTOTALCOUNT             221
#define IPFIX_FT_TCPACKTOTALCOUNT             222
#define IPFIX_FT_TCPURGTOTALCOUNT             223
#define IPFIX_FT_IPTOTALLENGTH		      224
#define IPFIX_FT_NATORIGINSIDEADDR	      225
#define IPFIX_FT_NATTRANSINSIDEADDR           226
#define IPFIX_FT_NATORIGOUTSIDEADDR	      227
#define IPFIX_FT_NATTRANSOUTSIDEADDR          228
#define IPFIX_FT_NATORIGINSIDEPORT	      229
#define IPFIX_FT_NATTRANSINSIDEPORT           230
#define IPFIX_FT_NATORIGOUTSIDEPORT	      231
#define IPFIX_FT_NATTRANSOUTSIDEPORT          232
#define IPFIX_FT_NATEVENT		      233 	 
#define IPFIX_FT_FWINITIATOROCTETS            234 	 
#define IPFIX_FT_FWRESPONDEROCTETS            235 	 
#define IPFIX_FT_FWEVENT	              236
#define IPFIX_FT_POSTMPLSTOPLABELEXP 	      237 	 
#define IPFIX_FT_TCPWINDOWSCALE		      238 
//su dva elementy s rovnakym nazvom OBSERVATIONPOINTID - zatial som dal process namiesto point
#define IPFIX_FT_ROUNDTRIPTIMENANOSECONDS	240
#define IPFIX_FT_RTTPAIRSTOTALCOUNT		241
#define IPFIX_FT_FIRSTPACKETID			242
#define IPFIX_FT_LASTPACKETID			243
#define IPFIX_FT_FLOWSTARTAFTEREXPORT		244
#define IPFIX_FT_OBSERVATIONPROCESSID	      300 	 
#define IPFIX_FT_SELECTIONSEQUENCEID	      301 	 
#define IPFIX_FT_SELECTORID		      302 	 
#define IPFIX_FT_INFORMATIONELEMENTID	      303 	 
#define IPFIX_FT_SELECTORALGORITHM	      304 	 
#define IPFIX_FT_SAMPLINGPACKETINTERVAL	      305 
#define IPFIX_FT_SAMPLINGPACKETSPACE	      306 	 
#define IPFIX_FT_SAMPLINGTIMEINTERVAL	      307 	 
#define IPFIX_FT_SAMPLINGTIMESPACE	      308 	 
#define IPFIX_FT_SAMPLINGSIZE	              309 	 
#define IPFIX_FT_SAMPLINGPOPULATION	      310 	  
#define IPFIX_FT_SAMPLINGPROBABILITY	      311 	 
#define IPFIX_FT_DATALINKFRAMESIZE	      312 	 
#define IPFIX_FT_IPHEADERPACKETSECTION	      313 	
#define IPFIX_FT_IPPAYLOADPACKETSECTION	      314 	 
#define IPFIX_FT_DATALINKFRAMESECTION	      315 	 
#define IPFIX_FT_MPLSLABELSTACKSECTION	      316 	 
#define IPFIX_FT_MPLSPAYLOADPACKETSECTION     317 	 
#define IPFIX_FT_PACKETSOBSERVED	      318 	 
#define IPFIX_FT_PACKETSSELECTED	      319 	  
#define IPFIX_FT_FIXEDERROR		      320 	 
#define IPFIX_FT_RELATIVEERROR		      321 
#define IPFIX_FT_OBSERVATIONTIMESECONDS	      322 	 
#define IPFIX_FT_OBSERVATIONTIMEMILISECONDS   323 	 
#define IPFIX_FT_OBSERVATIONTIMEMICROSECONDS  324 	 
#define IPFIX_FT_OBSERVATIONTIMENANOSECONDS   325 	  
#define IPFIX_FT_DIGESTHASHVALUE	      326 	 
#define IPFIX_FT_HASHIPPAYLOADOFFSET	      327 	  
#define IPFIX_FT_HASHIPPAYLOADSIZE	      328 	 
#define IPFIX_FT_HASHINITIALISERVALUE	      329 	 
#define IPFIX_FT_HASHOUTPUTRANGEMIN	      330 	  
#define IPFIX_FT_HASHOUTPUTRANGEMAX	      331 	 
#define IPFIX_FT_HASHSELECTEDRANGEMIN	      332 	  
#define IPFIX_FT_HASHSELECTEDRANGEMAX	      333 	  
#define IPFIX_FT_HASHDIGESTOUTPUT	      334 	  	
#define IPFIX_FT_ORIGINALFLOWSPRESENT		375
#define IPFIX_FT_ORIGINALFLOWSINITIATED		376
#define IPFIX_FT_ORIGINALFLOWSCOMPLETED		377
#define IPFIX_FT_DISTINCTCOUNTOFSOURCEIPADDRESS 378
#define IPFIX_FT_DISTINCTCOUNTOFDESTINATIONIPADDRESS 379
#define IPFIX_FT_DISTINCTCOUNTOFSOURCEIPV4ADDRESS 380
#define IPFIX_FT_DISTINCTCOUNTOFDESTINATIONIPV4ADDRESS 381
#define IPFIX_FT_DISTINCTCOUNTOFSOURCEIPV6ADDRESS 382
#define IPFIX_FT_DISTINCTCOUNTOFDESTINATIONIPV6ADDRESS 383

#define NF5_FT_SOURCEADDRESS 8
#define NF5_FT_DESTINATIONADDRESS 12
#define NF5_FT_NEXTHOP 15
#define NF5_FT_INPUTINTERFACE 10
#define NF5_FT_OUTPUTINTERFACE 14
#define NF5_FT_PACKETCOUNT 2
#define NF5_FT_OCTETCOUNT 1
#define NF5_FT_STARTSYSTEMUPTIME 22
#define NF5_FT_ENDSYSTEMUPTIME 21
#define NF5_FT_SOURCEPORT 7
#define NF5_FT_DESTINATIONPORT 11
#define NF5_FT_PADDING1 1001
#define NF5_FT_TCPFLAGS 6
#define NF5_FT_PROTOCOLTYPE 215
#define NF5_FT_TYPEOFSERVICE 4
#define NF5_FT_SOURCEAS 16
#define NF5_FT_DESTINATIONAS 17
#define NF5_FT_SOURCEMASK 9
#define NF5_FT_DESTINATIONMASK 13
#define NF5_FT_PADDING2 1002

#endif
