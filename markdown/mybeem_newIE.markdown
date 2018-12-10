# Implementácia podpory exportu pre mybeem
------------------------------------------

Počas implementácie nového informačného elementu pre nástroj MyBeem treba editovať nasledujúce súbory (uvedený kód demonštruje implementáciu elementu *flowLabelIPv6*):

### 1. ipfix_infelems.h
Tento hlavičkový súbor bol zavedený počas implementácie nástroja na generovanie upravenej verzie programu MyBeem, ktorý je reprezentovaný skriptom beem_adjuster.sh. Výsledná verzia programu MyBeem vždy podporuje len tie informačné elementy, ktoré v tomto hlavičkovom súbore sú zadefinované. Definíciu nového informačného elementu treba uviesť vo forme makra nasledovne:
```
#define IPFIX_NAZOVELEMENTU (identifikator elementu)
```
Teda v prípade informačného elementu *flowLabelIPv6* makro vyzerá nasledovne:
```
#define IPFIX_FLOWLABELIPV6 31
```

### 2. beem_adjuster.sh
Spúšťaním tohto skriptu vieme vytvoriť upravenú verziu programu MyBeem. Tento skript len upravuje obsah predošlého hlavičkového súboru a potom spustí kompiláciu. Do obsahu tohto skriptu treba pridať nasledujúce riadky:
```bash
for ((i=0; i<${#c[*]}; i++))
do
case "${c[$i]}" in
...
31) echo "#define IPFIX_FLOWLABELIPV6 ${c[$i]}" >> $filename
im=1
;;
...
*) echo "INVALID ELEMENT \"${c[$i]}\""
;;
esac
done
```

### 3. capture.c
V tomto súbore je potrebné editovať funkciu processPacket() a to nasledovným spôsobom: Je potrebné rozlíšiť, či sa jedná o IPv4 alebo IPv6 hlavičku a podľa toho editovať príslušnú vetvu. V oboch týchto vetvách sa vypĺňa štruktúra packet_info, do ktorej musíme uložiť hodnoty polí paketu, ktoré sú potrebné pre vyjadrenie hodnoty daného elementu podľa toho, ako je to v popise IPFIX protokolu.
```
void processPacket(struct packet_capturing_thread *t, const u_char *packet)
{
        ...
        
        else if (ntohs(header_ethernet->ether_type) == ETHERTYPE_IPV6)
        {
                ...
                packet_info->ip6_fl = header_ip6->ip6_flow;
                ...
        };
        ...
};
```

### 4. cache.h
V tomto hlavičkovom súbore je potrebné rozšíriť deklaráciu toku vo vyrovnávacej pamäti tokov o zložky predstavujúce hodnoty, ktoré su potrebné pre výpočet hodnoty informačného elementu.
```
struct cache_item
{
        ...
        #ifdef IPFIX_FLOWLABELIPV6
        uint32_t		ip6_fl;
        #endif 
        ...
};
```

### 5. cache.c
Tu je zmeny potrebné vykonať vo funkcii add_packet_to_flow(). Agregujú sa tu hodnoty všetkých paketov prislúchajúcich danému toku a ukladajú sa do vyrovnávacej pamäte tokov. Je tu vypĺňaná štruktúra item, ktorá predstavuje tok, ktorému prislúcha konkrétny paket.
```
void add_packet_to_flow(struct cache_item *item, struct _packet_info_t *packet)
{
        ...
        switch(item->flow_state)
        {
                case 0:
                ...
                #ifdef IPFIX_FLOWLABELIPV6                        
                item->ip6_fl = packet->ip6_fl;
                #endif
                ...
        };
        ...
};
```
Direktíva #ifdef a #endif tiež slúžia na vyznačenie častí zdrojového kódu, ktoré sa majú vynechať, keď sa rozhodneme upraviť MyBeem na takú verziu, v ktorej podporu informačného elementu flowLabelIPv6 nepotrebujeme.

### 6. export.c
V tomto zdrojovom súbore vo funkcii exportFlow() doplníme "case" vetvu konštrukcie switch pre implementovaný informačný element. Definíciu pre informačný element nájdeme v hlavičkovom súbore ipfix_def.h . Taktiež je potrebné overiť, či je daný element správne zadefinovaný v hlavičkovom súbore ipfix_fields.h .
```
int exportFlow (struct cache_item *flow)
{
        ...            
        for(i=0; i < tmpl[0].field_count;i++)
        {
                ...   
                #ifdef IPFIX_FLOWLABELIPV6                       
                case IPFIX_FT_FLOWLABELIPV6:
                memcpy(buf+offset, &flow->ip6_fl, ie.length);
                break;
                #endif
                ...
        }
        ...
};
```

### 7. config.xml
Je potrebne doplniť implementovaný element do konfiguračného súboru a aktualizovať počet implementovaných elementov.
```xml
<configuration>
<templates>
<template id="256">
...
<field>31</field>	<!-- flowLabelIPv6 -->
...
</template>
</templates>
</configuration>
```