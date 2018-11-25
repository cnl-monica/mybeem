#!/bin/bash

#! \file beem_adjuster.sh
#  \brief Bash skript generujuci upravenu verziu programu MyBeem

# Author:	David Farkas <david.farkas@student.tuke.sk>
# Date: 	20.5.2013
 
#  Bash skript, ktory na zaklade konfiguracneho suboru config.xml generuje MyBeem "sity na mieru"


#    Copyright (c) 2013 MONICA Research Group / TUKE

#    This file is part of BEEM.

#    BEEM is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    BEEM is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with BEEM.  If not, see <http://www.gnu.org/licenses/>.


# > creates new file (replaces existing file)
# >> adds to the end of the file

dir=$(ls Makefile config.xml 2>&1 | grep cannot)
if [ "$dir" != "" ]
then
	echo ""
	echo "The script needs to be in the same directory as the beem project is!"
	echo ""
	exit
fi

xml=$(xmllint 2>&1 | grep "command not found")
if [ "$xml" != "" ]
then
	echo ""
	echo "You need to install package libxml2-utils to use this script!"
	echo ""
	exit
fi

a=($(xmllint --xpath /configuration/templates/template config.xml | grep "<field>" | tr -d "\t" | tr -d " " | tr -d "<field>" | tr '/' '\n' | grep -v '!'))
b=($(more config.xml | grep "<field enterprise" | tr -d "\t" | tr -d " " | tr -d "<>fieldenterprise" | tr '/' '\n' | grep -v '!' | cut -c 9-))
# array containing IEs from config.xml
c=(${a[*]} ${b[*]})

# syn=($(xmllint --xpath /configuration/synchronization/doSync config.xml | tr -d "<>/doSync"))
# log=($(xmllint --xpath /configuration/logging/doLog config.xml | tr -d "<>/doLog"))
# med=($(xmllint --xpath /configuration/mediator/doMediation config.xml | tr -d "<>/doMediation"))

# $@ - command line arguments in one string

filename="ipfix_infelems.h"
# enterprise=0
im=0

echo "#ifndef _INFELEMS__H_" > $filename
echo "#define _INFELEMS__H_" >> $filename
echo "" >> $filename

# viacriadkovy komentar:
# :<<'COMMENT'
# COMMENT

for ((i=0; i<${#c[*]}; i++))
do
case "${c[$i]}" in
1) echo "#define IPFIX_OCTETDELTACOUNT ${c[$i]}" >> $filename
im=1
;;
2) echo "#define IPFIX_PACKETDELTACOUNT ${c[$i]}" >> $filename
im=1
;;
3) echo "#define IPFIX_DELTAFLOWCOUNT ${c[$i]}" >> $filename
im=1
;;
4) echo "#define IPFIX_PROTOCOLIDENTIFIER ${c[$i]}" >> $filename
im=1
;; # part of the flowID
5) echo "#define IPFIX_IPCLASSOFSERVICE ${c[$i]}" >> $filename
im=1
;;
6) echo "#define IPFIX_TCPCONTROLBITS ${c[$i]}" >> $filename
im=1
;;
7) echo "#define IPFIX_SOURCETRANSPORTPORT ${c[$i]}" >> $filename
im=1
;; # part of the flowID
8) echo "#define IPFIX_SOURCEIPV4ADDRESS ${c[$i]}" >> $filename
im=1
;; # part of the flowID
9) echo "#define IPFIX_SOURCEIPV4PREFIXLENGTH ${c[$i]}" >> $filename
im=1
;;
10) echo "#define IPFIX_INGRESSINTERFACE ${c[$i]}" >> $filename
im=1
;;
11) echo "#define IPFIX_DESTINATIONTRANSPORTPORT ${c[$i]}" >> $filename
im=1
;; # part of the flowID
12) echo "#define IPFIX_DESTINATIONIPV4ADDRESS ${c[$i]}" >> $filename
im=1
;; # part of the flowID
13) echo "#define IPFIX_DESTINATIONIPV4PREFIXLENGTH ${c[$i]}" >> $filename
im=1
;;
14) echo "#define IPFIX_EGRESSINTERFACE ${c[$i]}" >> $filename
im=1
;;
15) echo "#define IPFIX_IPNEXTHOPIPV4ADDRESS ${c[$i]}" >> $filename
im=1
;;
16) echo "#define IPFIX_BGPSOURCEASNUMBER ${c[$i]}" >> $filename
im=1
;;
17) echo "#define IPFIX_BGPDESTINATIONASNUMBER ${c[$i]}" >> $filename
im=1
;;
18) echo "#define IPFIX_BGPNEXTHOPIPV4ADDRESS ${c[$i]}" >> $filename
im=1
;;
19) echo "#define IPFIX_POSTMCASTPACKETDELTACOUNT ${c[$i]}" >> $filename
im=1
;;
20) echo "#define IPFIX_POSTMCASTOCTETDELTACOUNT ${c[$i]}" >> $filename
im=1
;;
21) echo "#define IPFIX_FLOWENDSYSUPTIME ${c[$i]}" >> $filename
im=1
;;
22) echo "#define IPFIX_FLOWSTARTSYSUPTIME ${c[$i]}" >> $filename
im=1
;;
23) echo "#define IPFIX_POSTOCTETDELTACOUNT ${c[$i]}" >> $filename
im=1
;;
24) echo "#define IPFIX_POSTPACKETDELTACOUNT ${c[$i]}" >> $filename
im=1
;;
25) echo "#define IPFIX_MINIMUMIPTOTALLENGTH ${c[$i]}" >> $filename
im=1
;;
26) echo "#define IPFIX_MAXIMUMIPTOTALLENGTH ${c[$i]}" >> $filename
im=1
;;
27) echo "#define IPFIX_SOURCEIPV6ADDRESS ${c[$i]}" >> $filename
im=1
;; # part of the flowID
28) echo "#define IPFIX_DESTINATIONIPV6ADDRESS ${c[$i]}" >> $filename
im=1
;; # part of the flowID
29) echo "#define IPFIX_SOURCEIPV6PREFIXLENGTH ${c[$i]}" >> $filename
im=1
;;
30) echo "#define IPFIX_DESTINATIONIPV6PREFIXLENGTH ${c[$i]}" >> $filename
im=1
;;
31) echo "#define IPFIX_FLOWLABELIPV6 ${c[$i]}" >> $filename
im=1
;;
32) echo "#define IPFIX_ICMPTYPECODEIPV4 ${c[$i]}" >> $filename
im=1
;;
33) echo "#define IPFIX_IGMPTYPE ${c[$i]}" >> $filename
im=1
;;
# 34-35 reserved
36) echo "#define IPFIX_FLOWACTIVETIMEOUT ${c[$i]}" >> $filename
im=1
;;
37) echo "#define IPFIX_FLOWIDLETIMEOUT ${c[$i]}" >> $filename
im=1
;;
# 38-39 reserved
40) echo "#define IPFIX_EXPORTEDOCTETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
41) echo "#define IPFIX_EXPORTEDMESSAGETOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
42) echo "#define IPFIX_EXPORTEDFLOWRECORDTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
# 43 reserved
44) echo "#define IPFIX_SOURCEIPV4PREFIX ${c[$i]}" >> $filename
im=1
;;
45) echo "#define IPFIX_DESTINATIONIPV4PREFIX ${c[$i]}" >> $filename
im=1
;;
46) echo "#define IPFIX_MPLSTOPLABELTYPE ${c[$i]}" >> $filename
im=1
;;
47) echo "#define IPFIX_MPLSTOPLABELIPV4ADDRESS ${c[$i]}" >> $filename
im=1
;;
# 48-51 reserved
52) echo "#define IPFIX_MINIMUMTTL ${c[$i]}" >> $filename
im=1
;;
53) echo "#define IPFIX_MAXIMUMTTL ${c[$i]}" >> $filename
im=1
;;
54) echo "#define IPFIX_FRAGMENTIDENTIFICATION ${c[$i]}" >> $filename
im=1
;;
55) echo "#define IPFIX_POSTIPCLASSOFSERVICE ${c[$i]}" >> $filename
im=1
;;
56) echo "#define IPFIX_SOURCEMACADDRESS ${c[$i]}" >> $filename
im=1
;;
57) echo "#define IPFIX_POSTDESTINATIONMACADDRESS ${c[$i]}" >> $filename
im=1
;;
58) echo "#define IPFIX_VLANID ${c[$i]}" >> $filename
im=1
;;
59) echo "#define IPFIX_POSTVLANID ${c[$i]}" >> $filename
im=1
;;
60) echo "#define IPFIX_IPVERSION ${c[$i]}" >> $filename
im=1
;; # part of the flowID
61) echo "#define IPFIX_FLOWDIRECTION ${c[$i]}" >> $filename
im=1
;;
62) echo "#define IPFIX_IPNEXTHOPIPV6ADDRESS ${c[$i]}" >> $filename
im=1
;;
63) echo "#define IPFIX_BGPNEXTHOPIPV6ADDRESS ${c[$i]}" >> $filename
im=1
;;
64) echo "#define IPFIX_IPV6EXTENSIONHEADERS ${c[$i]}" >> $filename
im=1
;;
# 65-69 reserved
70) echo "#define IPFIX_MPLSTOPLABELSTACKSECTION ${c[$i]}" >> $filename
im=1
;;
71) echo "#define IPFIX_MPLSLABELSTACKSECTION2 ${c[$i]}" >> $filename
im=1
;;
72) echo "#define IPFIX_MPLSLABELSTACKSECTION3 ${c[$i]}" >> $filename
im=1
;;
73) echo "#define IPFIX_MPLSLABELSTACKSECTION4 ${c[$i]}" >> $filename
im=1
;;
74) echo "#define IPFIX_MPLSLABELSTACKSECTION5 ${c[$i]}" >> $filename
im=1
;;
75) echo "#define IPFIX_MPLSLABELSTACKSECTION6 ${c[$i]}" >> $filename
im=1
;;
76) echo "#define IPFIX_MPLSLABELSTACKSECTION7 ${c[$i]}" >> $filename
im=1
;;
77) echo "#define IPFIX_MPLSLABELSTACKSECTION8 ${c[$i]}" >> $filename
im=1
;;
78) echo "#define IPFIX_MPLSLABELSTACKSECTION9 ${c[$i]}" >> $filename
im=1
;;
79) echo "#define IPFIX_MPLSLABELSTACKSECTION10 ${c[$i]}" >> $filename
im=1
;;
80) echo "#define IPFIX_DESTINATIONMACADDRESS ${c[$i]}" >> $filename
im=1
;;
81) echo "#define IPFIX_POSTSOURCEMACADDRESS ${c[$i]}" >> $filename
im=1
;;
82) echo "#define IPFIX_INTERFACENAME ${c[$i]}" >> $filename
im=1
;;
83) echo "#define IPFIX_INTERFACEDESCRIPTION ${c[$i]}" >> $filename
im=1
;;
# 84 reserved
85) echo "#define IPFIX_OCTETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
86) echo "#define IPFIX_PACKETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
# 87 reserved
88) echo "#define IPFIX_FRAGMENTOFFSET ${c[$i]}" >> $filename
im=1
;;
# 89 reserved
90) echo "#define IPFIX_MPLSVPNROUTEDISTINGUISHER ${c[$i]}" >> $filename
im=1
;;
91) echo "#define IPFIX_MPLSTOPLABELPREFIXLENGTH ${c[$i]}" >> $filename
im=1
;;
# 92-93 reserved
94) echo "#define IPFIX_APPLICATIONDESCRIPTION ${c[$i]}" >> $filename
im=1
;;
95) echo "#define IPFIX_APPLICATIONID ${c[$i]}" >> $filename
im=1
;;
96) echo "#define IPFIX_APPLICATIONNAME ${c[$i]}" >> $filename
im=1
;;
# 97 reserved
98) echo "#define IPFIX_POSTIPDIFFSERVCODEPOINT ${c[$i]}" >> $filename
im=1
;;
99) echo "#define IPFIX_MULTICASTREPLICATIONFACTOR ${c[$i]}" >> $filename
im=1
;;
# 100 reserved
101) echo "#define IPFIX_CLASSIFICATIONENGINEID ${c[$i]}" >> $filename
im=1
;;
# 102-127 reserved
128) echo "#define IPFIX_BGPNEXTADJACENTASNUMBER ${c[$i]}" >> $filename
im=1
;;
129) echo "#define IPFIX_BGPPREVADJACENTASNUMBER ${c[$i]}" >> $filename
im=1
;;
130) echo "#define IPFIX_EXPORTERIPV4ADDRESS ${c[$i]}" >> $filename
im=1
;;
131) echo "#define IPFIX_EXPORTERIPV6ADDRESS ${c[$i]}" >> $filename
im=1
;;
132) echo "#define IPFIX_DROPPEDOCTETDELTACOUNT ${c[$i]}" >> $filename
im=1
;;
133) echo "#define IPFIX_DROPPEDPACKETDELTACOUNT ${c[$i]}" >> $filename
im=1
;;
134) echo "#define IPFIX_DROPPEDOCTETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
135) echo "#define IPFIX_DROPPEDPACKETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
136) echo "#define IPFIX_FLOWENDREASON ${c[$i]}" >> $filename
im=1
;;
137) echo "#define IPFIX_COMMONPROPERTIESID ${c[$i]}" >> $filename
im=1
;;
138) echo "#define IPFIX_OBSERVATIONPOINTID ${c[$i]}" >> $filename
im=1
;;
139) echo "#define IPFIX_ICMPTYPECODEIPV6 ${c[$i]}" >> $filename
im=1
;;
140) echo "#define IPFIX_MPLSTOPLABELIPV6ADDRESS ${c[$i]}" >> $filename
im=1
;;
141) echo "#define IPFIX_LINECARDID ${c[$i]}" >> $filename
im=1
;;
142) echo "#define IPFIX_PORTID ${c[$i]}" >> $filename
im=1
;;
143) echo "#define IPFIX_METERINGPROCESSID ${c[$i]}" >> $filename
im=1
;;
144) echo "#define IPFIX_EXPORTINGPROCESSID ${c[$i]}" >> $filename
im=1
;;
145) echo "#define IPFIX_TEMPLATEID ${c[$i]}" >> $filename
im=1
;;
146) echo "#define IPFIX_WLANCHANNELID ${c[$i]}" >> $filename
im=1
;;
147) echo "#define IPFIX_WLANSSID ${c[$i]}" >> $filename
im=1
;;
148) echo "#define IPFIX_FLOWID ${c[$i]}" >> $filename
im=1
;;
149) echo "#define IPFIX_OBSERVATIONDOMAINID ${c[$i]}" >> $filename
im=1
;;
150) echo "#define IPFIX_FLOWSTARTSECONDS ${c[$i]}" >> $filename
im=1
;;
151) echo "#define IPFIX_FLOWENDSECONDS ${c[$i]}" >> $filename
im=1
;;
152) echo "#define IPFIX_FLOWSTARTMILLISECONDS ${c[$i]}" >> $filename
im=1
;;
153) echo "#define IPFIX_FLOWENDMILLISECONDS ${c[$i]}" >> $filename
im=1
;;
154) echo "#define IPFIX_FLOWSTARTMICROSECONDS ${c[$i]}" >> $filename
im=1
;;
155) echo "#define IPFIX_FLOWENDMICROSECONDS ${c[$i]}" >> $filename
im=1
;;
156) echo "#define IPFIX_FLOWSTARTNANOSECONDS ${c[$i]}" >> $filename
im=1
;;
157) echo "#define IPFIX_FLOWENDNANOSECONDS ${c[$i]}" >> $filename
im=1
;;
158) echo "#define IPFIX_FLOWSTARTDELTAMICROSECONDS ${c[$i]}" >> $filename
im=1
;;
159) echo "#define IPFIX_FLOWENDDELTAMICROSECONDS ${c[$i]}" >> $filename
im=1
;;
160) echo "#define IPFIX_SYSTEMINITTIMEMILLISECONDS ${c[$i]}" >> $filename
im=1
;;
161) echo "#define IPFIX_FLOWDURATIONMILLISECONDS ${c[$i]}" >> $filename
im=1
;;
162) echo "#define IPFIX_FLOWDURATIONMICROSECONDS ${c[$i]}" >> $filename
im=1
;;
163) echo "#define IPFIX_OBSERVEDFLOWTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
164) echo "#define IPFIX_IGNOREDPACKETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
165) echo "#define IPFIX_IGNOREDOCTETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
166) echo "#define IPFIX_NOTSENTFLOWTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
167) echo "#define IPFIX_NOTSENTPACKETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
168) echo "#define IPFIX_NOTSENTOCTETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
169) echo "#define IPFIX_DESTINATIONIPV6PREFIX ${c[$i]}" >> $filename
im=1
;;
170) echo "#define IPFIX_SOURCEIPV6PREFIX ${c[$i]}" >> $filename
im=1
;;
171) echo "#define IPFIX_POSTOCTETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
172) echo "#define IPFIX_POSTPACKETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
173) echo "#define IPFIX_FLOWKEYINDICATOR ${c[$i]}" >> $filename
im=1
;;
174) echo "#define IPFIX_POSTMCASTPACKETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
175) echo "#define IPFIX_POSTMCASTOCTETTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
176) echo "#define IPFIX_ICMPTYPEIPV4 ${c[$i]}" >> $filename
im=1
;;
177) echo "#define IPFIX_ICMPCODEIPV4 ${c[$i]}" >> $filename
im=1
;;
178) echo "#define IPFIX_ICMPTYPEIPV6 ${c[$i]}" >> $filename
im=1
;;
179) echo "#define IPFIX_ICMPCODEIPV6 ${c[$i]}" >> $filename
im=1
;;
180) echo "#define IPFIX_UDPSOURCEPORT ${c[$i]}" >> $filename
im=1
;;
181) echo "#define IPFIX_UDPDESTINATIONPORT ${c[$i]}" >> $filename
im=1
;;
182) echo "#define IPFIX_TCPSOURCEPORT ${c[$i]}" >> $filename
im=1
;;
183) echo "#define IPFIX_TCPDESTINATIONPORT ${c[$i]}" >> $filename
im=1
;;
184) echo "#define IPFIX_TCPSEQUENCENUMBER ${c[$i]}" >> $filename
im=1
;;
185) echo "#define IPFIX_TCPACKNOWLEDGEMENTNUMBER ${c[$i]}" >> $filename
im=1
;;
186) echo "#define IPFIX_TCPWINDOWSIZE ${c[$i]}" >> $filename
im=1
;;
187) echo "#define IPFIX_TCPURGENTPOINTER ${c[$i]}" >> $filename
im=1
;;
188) echo "#define IPFIX_TCPHEADERLENGTH ${c[$i]}" >> $filename
im=1
;;
189) echo "#define IPFIX_IPHEADERLENGTH ${c[$i]}" >> $filename
im=1
;;
190) echo "#define IPFIX_TOTALLENGTHIPV4 ${c[$i]}" >> $filename
im=1
;;
191) echo "#define IPFIX_PAYLOADLENGTHIPV6 ${c[$i]}" >> $filename
im=1
;;
192) echo "#define IPFIX_IPTTL ${c[$i]}" >> $filename
im=1
;;
193) echo "#define IPFIX_NEXTHEADERIPV6 ${c[$i]}" >> $filename
im=1
;;
194) echo "#define IPFIX_MPLSPAYLOADLENGTH ${c[$i]}" >> $filename
im=1
;;
195) echo "#define IPFIX_IPDIFFSERVCODEPOINT ${c[$i]}" >> $filename
im=1
;;
196) echo "#define IPFIX_IPPRECEDENCE ${c[$i]}" >> $filename
im=1
;;
197) echo "#define IPFIX_FRAGMENTFLAGS ${c[$i]}" >> $filename
im=1
;;
198) echo "#define IPFIX_OCTETDELTASUMOFSQUARES ${c[$i]}" >> $filename
im=1
;;
199) echo "#define IPFIX_OCTETTOTALSUMOFSQUARES ${c[$i]}" >> $filename
im=1
;;
200) echo "#define IPFIX_MPLSTOPLABELTTL ${c[$i]}" >> $filename
im=1
;;
201) echo "#define IPFIX_MPLSLABELSTACKLENGTH ${c[$i]}" >> $filename
im=1
;;
202) echo "#define IPFIX_MPLSLABELSTACKDEPTH ${c[$i]}" >> $filename
im=1
;;
203) echo "#define IPFIX_MPLSTOPLABELEXP ${c[$i]}" >> $filename
im=1
;;
204) echo "#define IPFIX_IPPAYLOADLENGTH ${c[$i]}" >> $filename
im=1
;;
205) echo "#define IPFIX_UDPMESSAGELENGTH ${c[$i]}" >> $filename
im=1
;;
206) echo "#define IPFIX_ISMULTICAST ${c[$i]}" >> $filename
im=1
;;
207) echo "#define IPFIX_IPV4IHL ${c[$i]}" >> $filename
im=1
;;
208) echo "#define IPFIX_IPV4OPTIONS ${c[$i]}" >> $filename
im=1
;;
209) echo "#define IPFIX_TCPOPTIONS ${c[$i]}" >> $filename
im=1
;;
210) echo "#define IPFIX_PADDINGOCTETS ${c[$i]}" >> $filename
im=1
;;
211) echo "#define IPFIX_COLLECTORIPV4ADDRESS ${c[$i]}" >> $filename
im=1
;;
212) echo "#define IPFIX_COLLECTORIPV6ADDRESS ${c[$i]}" >> $filename
im=1
;;
213) echo "#define IPFIX_EXPORTINTERFACE ${c[$i]}" >> $filename
im=1
;;
214) echo "#define IPFIX_EXPORTPROTOCOLVERSION ${c[$i]}" >> $filename
im=1
;;
215) echo "#define IPFIX_EXPORTTRANSPORTPROTOCOL ${c[$i]}" >> $filename
im=1
;;
216) echo "#define IPFIX_COLLECTORTRANSPORTPORT ${c[$i]}" >> $filename
im=1
;;
217) echo "#define IPFIX_EXPORTERTRANSPORTPORT ${c[$i]}" >> $filename
im=1
;;
218) echo "#define IPFIX_TCPSYNTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
219) echo "#define IPFIX_TCPFINTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
220) echo "#define IPFIX_TCPRSTTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
221) echo "#define IPFIX_TCPPSHTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
222) echo "#define IPFIX_TCPACKTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
223) echo "#define IPFIX_TCPURGTOTALCOUNT ${c[$i]}" >> $filename
im=1
;;
224) echo "#define IPFIX_IPTOTALLENGTH ${c[$i]}" >> $filename
im=1
;;
225) echo "#define IPFIX_POSTNATSOURCEIPV4ADDRESS ${c[$i]}" >> $filename
im=1
;;
226) echo "#define IPFIX_POSTNATDESTINATIONIPV4ADDRESS ${c[$i]}" >> $filename
im=1
;;
227) echo "#define IPFIX_POSTNAPTSOURCETRANSPORTPORT ${c[$i]}" >> $filename
im=1
;;
228) echo "#define IPFIX_POSTNAPTDESTINATIONTRANSPORTPORT ${c[$i]}" >> $filename
im=1
;;
229) echo "#define IPFIX_NATORIGINATINGADDRESSREALM ${c[$i]}" >> $filename
im=1
;;
230) echo "#define IPFIX_NATEVENT ${c[$i]}" >> $filename
im=1
;;
231) echo "#define IPFIX_INITIATOROCTETS ${c[$i]}" >> $filename
im=1
;;
232) echo "#define IPFIX_RESPONDEROCTETS ${c[$i]}" >> $filename
im=1
;;
233) echo "#define IPFIX_FIREWALLEVENT ${c[$i]}" >> $filename
im=1
;;
234) echo "#define IPFIX_INGRESSVRFID ${c[$i]}" >> $filename
im=1
;;
235) echo "#define IPFIX_EGRESSVRFID ${c[$i]}" >> $filename
im=1
;;
236) echo "#define IPFIX_VRFNAME ${c[$i]}" >> $filename
im=1
;;
237) echo "#define IPFIX_POSTMPLSTOPLABELEXP ${c[$i]}" >> $filename
im=1
;;
238) echo "#define IPFIX_TCPWINDOWSCALE ${c[$i]}" >> $filename
im=1
;;
239) echo "#define IPFIX_BIFLOWDIRECTION ${c[$i]}" >> $filename
im=1
;;
240) echo "#define IPFIX_ROUNDTRIPTIMENANOSECONDS ${c[$i]}" >> $filename
im=1
# enterprise=26235
;;
241) echo "#define IPFIX_PACKETPAIRSTOTALCOUNT ${c[$i]}" >> $filename
im=1
# enterprise=26235
;;
242) echo "#define IPFIX_FIRSTPACKETID ${c[$i]}" >> $filename
im=1
# enterprise=26235
;;
243) echo "#define IPFIX_LASTPACKETID ${c[$i]}" >> $filename
im=1
# enterprise=26235
;;
244) echo "#define IPFIX_FLOWSTARTAFTEREXPORT ${c[$i]}" >> $filename
im=1
# enterprise=26235
;;
# 245
# :
# :
# 387-32767 unassigned
*) echo "INVALID ELEMENT \"${c[$i]}\""
;;
esac
done

:<< 'A'
if [ $enterprise -gt 0 ]
then
    	echo "" >> $filename
    	echo "#define IPFIX_ENTERPRISEID $enterprise" >> $filename
fi

if [ $syn == "true" ]
then
        echo "" >> $filename
        echo "#define SYNCHRONIZATION" >> $filename
fi

if [ $log == "true" ]
then
        echo "" >> $filename
        echo "#define SERVERLOGGING" >> $filename
fi

if [ $med == "ru" ]
then
        echo "" >> $filename
        echo "#define MEDIATIONSERVER" >> $filename
fi
A

echo "" >> $filename
echo "#endif //_INFELEMS__H_" >> $filename

if [ $im -gt 0 ]
then
	echo ""
	echo "File ipfix_infelems.h successfully generated!"

        make clean > /dev/null

        m=$(make 2>&1 | grep "rror")

        if [ "$m" != "" ]
        then
            echo ""
            echo "COMPILATION FAILURE!"
            echo "$m"
            echo ""
        else
            echo ""
            echo "BEEM SUCCESSFULLY ADJUSTED!"
            echo "You can start the new Beem..."
            echo ""
        fi
else
	echo ""
	echo "FAILURE!"
	echo "You can not start Beem with an empty Information Model!"
	echo ""
fi
