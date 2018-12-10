# MyBeem
--------

*  **Verzia**: 1.1-9 
*  **Stav verzie**: vyvíjaná
*   **Autori**:
      * Dávid Farkas
      * Samuel Tremko - bývalý riešiteľ
      * Tomáš Kecsey - bývalý riešiteľ
      * Ľuboš Husivarga - bývalý riešiteľ
      * Viliam Lorinc - bývalý riešiteľ
 
*   **Licencia**: GNU GPLv3
*   **Implemetačné prostredie**: jazyk C v prostredí GNU/Linux 

*   [Návod na tvorbu DEB balíka pre MyBeem](mybeem_debian)
*   [Implementácia podpory exportu nového informačného elementu pre MyBeem](mybeem_newIE)
*   [Changelog](mybeem_changelog)
*   [Používateťská príručka PDF](https://git.cnl.sk/monica/slameter_exporter/raw/master/doc/mybeem_v1.1-9_PP.pdf)
*   [Systémová príručka PDF](https://git.cnl.sk/monica/slameter_exporter/raw/master/doc/mybeem_v1.1-9_SP.pdf)

## Stručný opis
---------------
Program mybeem reprezentuje najnižšiu vrstvu monitorovacieho nástroja SLAmeter. Predstavuje monitorovací a exportovací proces. Tieto procesy slúžia na monitorovanie sieťovej prevádzky a jej parametrov a následným exportovaním nameraných hodnôt do vyššej vrstvy. Program exportuje tieto hodnoty vo formáte konfrontujúcim so štandardami IPFIX, NetFlow a PSAMP. Je to konzolová aplikácia a nemá žiadne grafické rozhranie. Rôzne výpisy programu je možné sledovať priamo v konzole. Program bol vyvíjaný použitím open-source technológií.

## Architektúra programu
------------------------
Jednotlivé komponenty, resp. moduly sú opísané v [systémovej príručke](https://git.cnl.sk/monica/slameter_exporter/raw/master/doc/mybeem_v1.1-9_SP.pdf).

![mybeem](https://git.cnl.sk/uploads/monica/slameter_exporter/081a76b16d/mybeem.png)

## Systémové požiadavky
-----------------------
* **Operačný systém**: GNU/Linux archytektúry *i386* alebo *amd64*
* **Hardvér**:
      * procesor: 1GHz+ (v závislosti od intenzity sieťovej prevádzky)
      * pamäť: 512MB+ (v závislosti od nastavenia cache pamäte)
      * diskový priestor: 10MB
      * ostatné: sieťová karta
* **Softvér**:
      * libpcap-dev verzie 0.8.3 alebo vyššej
      * libxml2-dev verzie 2.6.23 alebo vyššej
      * openssl-dev verzie 0.9.1 alebo vyššej
      * libsctp-dev verzie 1.0.9 alebo vyššej
      * libxml2-utils verzie 2.7.8 alebo vyššej
      * nDPI verzie 1.5.2 (vyžaduje knižnice gawk, gcc, autoconf, build-essential a libtool)

## Inštalácia programu pomocou *.deb* balíka
--------------------------------------------
Inštalácia na architektúru **i386**:
```bash
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/deb/mybeem_1.1-9_i386.deb --no-check-certificate
sudo dpkg -i mybeem_1.1-9_i386.deb
```

Inštalácia na architektúru **amd64**:
```bash
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/deb/mybeem_1.1-9_amd64.deb --no-check-certificate
sudo dpkg -i mybeem_1.1-9_amd64.deb
```

Po správnej inštalácii sa program dá spustiť pomocou príkazu:
```bash
sudo mybeem
```
alebo príkazu:
```bash
sudo /etc/init.d/mybeemd start
```

## Manuálna inštalácia programu
-------------------------------
### 1. Inštalácia nasledujúcich balíkov:
```bash
sudo apt-get install libpcap-dev libxml2-dev libssl-dev libsctp-dev libsctp-dev libssl0.9.8 libsctp-dev libxml2-utils gawk gcc autoconf build-essential libtool
```
### 2. Stiahnúť balík nDPI verzie 1.5.2:
```bash
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/lib/nDPI_1.5.2.tar.gz --no-check-certificate
```
### 3. Postup inštalácie balíka nDPI verzie 1.5.2:
```bash
sudo su
tar zxvf nDPI_1.5.2.tar.gz
cd nDPI
sh autogen.sh
make
make install
echo "export LD_LIBRARY_PATH=\"/usr/local/lib:$LD_LIBRARY_PATH\"" >> ~/.bashrc
```
### 4. Stiahnutie zdrojových kódov:
```bash
wget https://git.cnl.sk/monica/slameter_exporter/repository/archive.tar.gz --no-check-certificate
```
### 5. Vykonanie prekladu:
```bash
tar zxvf archive.tar.gz
cd slameter_exporter.git/src/mybeem
make
```
### 6. Premenovanie binárneho súboru:
```bash
mv beem mybeem
```
### 7. Vytvorenie potrebných podadresárov:
```bash
sudo mkdir /var/log/mybeem
sudo mkdir /etc/mybeem
```
### 8. Nakopírovanie príslušných súborov do zodpovedajúcich adresárov:
```bash
sudo cp mybeem /usr/sbin/
sudo cp config.xml /etc/mybeem/
sudo cp mybeemd /etc/init.d/
```
### 9. Následne je možné program spustiť pomocou príkazu:
```bash
sudo mybeem
```
alebo príkazu:
```bash
sudo /etc/init.d/mybeemd start
```

## Spustenie programu prekladom zdrojových kódov
------------------------------------------------
### 1. Inštalácia nasledujúcich balíkov:
```bash
sudo apt-get install libpcap-dev libxml2-dev libssl-dev libsctp-dev libsctp-dev libssl0.9.8 libsctp-dev libxml2-utils gawk gcc autoconf build-essential libtool
```
### 2. Stiahnúť balík nDPI verzie 1.5.2:
```bash
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/lib/nDPI_1.5.2.tar.gz --no-check-certificate
```
### 3. Postup inštalácie balíka nDPI verzie 1.5.2:
```bash
sudo su
tar zxvf nDPI_1.5.2.tar.gz
cd nDPI
sh autogen.sh
make
make install
echo "export LD_LIBRARY_PATH=\"/usr/local/lib:$LD_LIBRARY_PATH\"" >> ~/.bashrc
```
### 4. Stiahnutie zdrojových kódov:
```bash
wget https://git.cnl.sk/monica/slameter_exporter/repository/archive.tar.gz --no-check-certificate
```
### 5. Vykonanie prekladu:
```bash
tar zxvf archive.tar.gz
cd slameter_exporter.git/src/mybeem
make
```
### 6. Spustenie programu:
```bash
sudo ./beem -c config.xml
```

## Opis parametrov príkazového riadku
-------------------------------------
Pomocou parametrov zadávaných v príkazovom riadku pri spúšťaní programu je možné vykonať určité nastavenia aj bez potreby zmeny konfiguračného súboru. Paleta implementovaných parametrov:

| **Parameter** | **Opis**                           |
| ----------- | ------                           |
| -v          | zobrazí aktuálnu verziu programu |
| -h          | zobrazí informácie               |
| -p [PROTO TYPE] | nastaví typ prorokolu na hodnotu špeciﬁkovanú v [PROTO TYPE]|
| -i [INTERFACE] | nastaví rozhranie na typ špeciﬁkovaný v [INTERFACE]|
| -c [CONFIG FILE] | nastaví konﬁguračný súbor na súbor špeciﬁkovaný v [CONFIG FILE]|
| -l [LOG FILE] | nastaví logovací súbor na súbor špeciﬁkovaný v [LOG FILE]|
| -pc [PCAP FILTER] | nastaví PCAP ﬁlter na ﬁlter špeciﬁkovaný v [PCAP FILTER]|
| -po [PORT NUMBER]  | nastaví číslo portu na číslo špeciﬁkované v [PORT NUMBER]|
| -ho [HOST IP] | nastaví host IP adresu na adresu špeciﬁkovanú v [HOST IP]| 
|-llvl [LOG LEVEL] | nastaví úroveň výpisov na hodnotu špecifikovanú v [LOG LEVEL]|
|-opid [OBSERVATION POINT ID] | nastaví observationPointId na hodnotu špecifikovanú v [OBSERVATION POINT ID]|
|-odid [OBSERVATION DOMAIN ID] | nastaví observationDomainId na hodnotu špecifikovanú v [OBSERVATION DOMAIN ID]|
|-logserv | zapne logovanie na syslog server pri použití konfigurácie z konfiguračného súboru BEEM-u config.xml|
|-logprot [PROTOCOL TYPE] | nastaví protokol pre prenos syslog správi na hodnotu špecifikovanú v [PROTOCOL TYPE]|
|-logaddr [IP ADDRESS] | nastaví IP adresu syslog servra na hodnotu špecifikovanú v [IP ADDRESS]|
|-logport [PORT NUMBER] | nastaví port pre komunikáciu so syslog servrom na hodnotu špecifikovanú v [PORT NUMBER]|
|-aggreg | spustí proces agregácie v programe|

## Opis konfiguračného súboru
-----------------------------
Program je konﬁgurovateľný pomocou konﬁguračného súboru **conﬁg.xml**. Zoznam značiek konﬁguračného súboru a ich vysvetlenie:

| **Parameter** | **Opis** |
| ------------- | -------- |
| conﬁguration | koreňová značka, ktorá ohraničuje všetky konﬁguračné parametre konﬁguračného súboru |
| observationPointId | jedinečný identiﬁkátor pozorovacieho bodu (celočíselná kladná hodnota 1-32767) |
| observationDomainId | jedinečný identifikátor pozorovacej domény (celočíselná kladná hodnota) |
| readﬁle | ak true, príznak čítania zo súboru. Ak false, ”číta” sa zo zvoleného sieťového rozhrania |
| dumpFile | názov súboru z ktorého sa v prípade nastavenia readFile na true bude čítať |
| interface | sieťové rozhranie, z ktorého sa majú odchytávať pakety |
| pcapFilter | typ BPF ﬁltra pre ﬁltrovanie paketov |
| ﬂows | značka ohraničujúca parametre ovplyvňujúce nastavenie tokov |
| biﬂows | prepínač na zapínanie/vypínanie podpory obojsmerných tokov exportérom, false-uniﬂow, true-biﬂow |
| passiveTimeout | nastavenie času v milisekundách pre pasívny timeout. Pasívny timeout je čas, za ktorý keď pre príslušný tok nie je obdržaný žiaden paket, tak daný tok je expirovaný. |
| activeTimeout | nastavenie času v milisekundách pre aktívny timeout. Aktívny timeout je čas, po uplynutí ktorého je príslušný tok expirovaný a údaje exportované aj napriek tomu, že pakety pre príslušný tok sú stále zachytávané. Musí byť väčší ako pasívny timeout. |
| sampling | značka ohraničujúca nastavenia týkajúce sa vzorkovania |
| type | celočíselná hodnota z intervalu 0 až 5 špeciﬁkujúca spôsob vzorkovania |
| parameter1 | prvý parameter pre vzorkovacie funkcie. |
| parameter2 | druhý parameter pre vzorkovacie funkcie. |
| templates | značka ohraničujúca nastavenia týkajúce sa šablón |
| template | značka ohraničujúca nastavenia týkajúce sa jednej konkrétnej šablóny |
| ﬁeld | deﬁnícia poľa v rámci jednej šablóny prostredníctvom identiﬁkačného čísla informačného elementu elementID. Ak je tento element skupinovo (enterprise) špeciﬁcký, značka ﬁeld sa zadáva spolu s atribútom enterprise. |
| mediator | značka ohraničujúca nastavenia pre mediátor |
| doMediation | prepínač na zapnutie/vypnutie služby |
| collector | značka ohraničujúca nastavenia pre kolektor |
| version | špeciﬁkácia verzie používaného kolektora/mediátora (verzia protokolu IPFIX) |
| host | internetová adresa zhromažďovača/mediátora, prípadne localhost |
| port | port, na ktorom kolektor/mediátor očakáva IPFIX správy |
| sync_port | port, na ktorom kolektor očakáva synchronizačné údaje|
| protocol | transportný protokol, ktorý sa použije pri odosielaní IPFIX správ |
| sourceID | identiﬁkátor exportovacej domény |
| refreshTemplateTime | čas, po ktorom má byť používaná šablóna opätovne preposielaná kolektoru/mediátoru. (Nastavenie zavisí od nastavenia ”default template lifetime” v kolektore/mediátore.) |
| reconnectFrequency | frekvencia s akou sa bude mybeem pokúšať pripojiť ku kolektoru/mediátoru v prípade výpadku spojenia v sekundách |
| connectionTimeout | čas po ktorom nastane timeout spojenia medzi mybeem-om a kolektorom/mediátorom |
| synchronization | značka ohraničujúca nastavenie pre synchronizačný server |
| doSync | prepínač na zapnutie/vypnutie synchronizácie voči synchronizačnému serveru, false-zapnutá synchronizácia, true-vypnutá synchronizácia |
| port | port, na ktorom Beem očakáva synchronizačné správy |
| serverAddress | internetová adresa synchronizačného servera |
| serverPort | port, na ktorom synchronizačný server očakáva synchronizačné správy |
| logging | značka ohraničujúca nastavenie pre syslog server |
| sendingProtocol | protokol pre komunikáciu so syslog servrom |
| syslogServIP | IP adresa syslog servra |
| syslogServPort | port pre komunikáciu so syslog servrom |
| messageLogLevel | nastavenie úrovne výpisov programu |
| aggregation | značka ohraničujúca nastavenie pre proces agregácie tokov |
| doAggregation | táto premenná zapína/vypína celý proces agregácie |
| automaticAggregation | v prípade, že je vypnutá agregácia a táto premenná je nastavená na hodnotu "true", agregácia bude spustená pri vyťažení vyrovnávacej pamäte tokov na 85%  |
| aggregationTrigger | časový interval v milisekundách, po uplynutí ktorého bude opakovane dochádzať k spúšťaniu procesu agregácie záznamov o tokoch|
| octetTotalCountForAggregation | počet oktetov, ktorý definuje hraničnú hodnotu pre rozsiahly tok, ktorý už nebude agregovaný |
| first | kľúčová hodnota toku, ktorá má najvyššiu prioritu a bude agregovaná ako posledná |
| second | kľúčová hodnota toku, ktorá má druhú najvyššiu prioritu a bude agregovaná ako predposledná |
| third | kľúčová hodnota toku, ktorá má tretiu najvyššiu prioritu a bude agregovaná ako druhá v poradí |
| fourth | kľúčová hodnota toku, ktorá má najnižšiu prioritu a bude agregovaná ako prvá |
| dpi | značka ohraničujúca nastavenia pre proces DPI |
| doDPI | táto premenná zapína/vypína celý proces DPI |
| protofile | súbor protokolov |