# MyBeem
--------

MyBeem (an IPFIX exporter implemented in C language) represents the lowest component of the SLAmeter network traffic measurement/monitoring tool. MyBeem captures packets from the interface card and orgnaises them into flow records. Flow records are containers that carry the properties (e.g. the total number of bytes of all packets belonging to a certain flow) and characteristics (e.g. source IP address) of the flow. The architectue of the exporter is as follows:

<p align="center">
  <img src="/fig/exporter.png" width="410" title="Architecture of the exporter">
</p>

The flow records are generated by one or more metering processes. The metering process consists of a set of functions including packet capture, filtering, timestamping, sampling, classification and creating/maintaining flow records in the flow cache. Network traffic monitoring is based on the analysis of the exported flow records. The export of flow records represents a push-based mechanism, where the data are transmitted from the exporter(s) to the IPFIX collector(s) over either the TCP, UDP or SCTP protocol.

MyBeem is in full conformity with IPFIX, Netflow and PSAMP. It is a command-line application without any GUI. It provides logging on various levels (info, warning, debug, etc.) that are shown in the terminal. MyBeem was developed using open-source technologies.

*  **Latest version**: 1.1-9 
*  **Version state**: stable, **the development was concluded in 2015**
*  **Developers**:
      *   Dávid Farkas
      *   Samuel Tremko
      *   Tomáš Kecsey
      *   Adrián Pekár
      *   Ľuboš Husivarga
      *   Viliam Lorinc
 
*   **License**: GNU GPLv3
*   **Implementation environment**: C programming language in GNU/Linux environment 

## Documentation

**The documentation is available only in Slovak language:**
 * [User Documentation PDF](https://github.com/cnl-monica/mybeem/tree/master/doc/mybeem_v1.1-9_PP.pdf)
 * [Technical Documenation PDF](https://github.com/cnl-monica/mybeem/tree/master/doc/mybeem_v1.1-9_SP.pdf)

## Other useful documents
------------------------------------------------
 *   [Tutorial on creating a DEB installation package for MyBeem](DEB_TUTORIAL.md)
 *   [Tutorial on implementating a new information element in MyBeem](NEW_IE_TUTORIAL.md)

## System Requirements
-----------------------
* **Operating System:** GNU/Linux *i386* or *amd64* architecture

*  **Hardware**:
      *   processor: 1GHz+ (depends on the traffic load to measure)
      *   memory: 512MB+ (depends on the configure cache size)
      *   size on disk: 10MB
      *   other: network interface card (NIC)

*  **Software**:
      *   libpcap-dev version 0.8.3
      *   libxml2-dev version 2.6.23
      *   openssl-dev version 0.9.1
      *   libsctp-dev version 1.0.9
      *   libxml2-utils version 2.7.8
      *   nDPI version 1.5.2 (requires gawk, gcc, autoconf, build-essential, and libtool packages)


## Installation using the *.deb* package
--------------------------------------------

### Installation on **i386** architectures:

##### 1. Download the package:

```bash
wget https://github.com/cnl-monica/mybeem/tree/master/deb/mybeem_1.1-9_i386.deb --no-check-certificate
```

##### 2. Install the package:

```bash
sudo dpkg -i mybeem_1.1-9_i386.deb
```


### Installation on **amd64** architectures:

##### 1. Download the package:

```bash
wget https://github.com/cnl-monica/mybeem/tree/master/deb/mybeem_1.1-9_amd64.deb --no-check-certificate
```

##### 2. Install the package:

```bash
sudo dpkg -i mybeem_1.1-9_amd64.deb
```

## Manual installation 
-------------------------------

##### 1. Install the following dependences:
```bash
sudo apt-get install libpcap-dev libxml2-dev libssl-dev libsctp-dev libsctp-dev libssl0.9.8 libsctp-dev libxml2-utils gawk gcc autoconf build-essential libtool
```
##### 2. Download nDPI v1.5.2:
```bash
wget https://github.com/cnl-monica/mybeem/tree/master/lib/nDPI_1.5.2.tar.gz --no-check-certificate
```
##### 3. Install nDPI v1.5.2:
```bash
sudo su
tar zxvf nDPI_1.5.2.tar.gz
cd nDPI
sh autogen.sh
make
make install
echo "export LD_LIBRARY_PATH=\"/usr/local/lib:$LD_LIBRARY_PATH\"" >> ~/.bashrc
```
##### 4. Download the source code:
```bash
wget https://github.com/cnl-monica/mybeem/archive/master.zip --no-check-certificate
```
##### 5. Compile the code:
```bash
unzip master.zip
cd mybeem-master/src/mybeem
make
```
##### 6. Change the name of the binary executable (due to historical naming convention):
```bash
mv beem mybeem
```
##### 7. Create the required directories:
```bash
sudo mkdir /var/log/mybeem
sudo mkdir /etc/mybeem
```
##### 8. Copy the files to the directories:
```bash
sudo cp mybeem /usr/sbin/
sudo cp config.xml /etc/mybeem/
sudo cp mybeemd /etc/init.d/
```

## Run the program
------------------------------------------------

After installation the program can be run using the following command:
```bash
sudo ./beem -c config.xml
```

or using the following command:

```bash
sudo /etc/init.d/mybeemd start
```

## Description of command line parameters
-------------------------------------
Using these command-line parameters the program can be also configured without the change of the configuration file. The parameters that can be changed in command-line are as follow:

| **Parameter** | **Description**                          |
| ----------- | ------                           |
| -v          | shows the program version |
| -h          | shows basic information              |
| -p [PROTO TYPE] | sets the protocol to the one specified in [PROTO TYPE]|
| -i [INTERFACE] | sets the interface to the one specified in [INTERFACE]|
| -c [CONFIG FILE] | sets the configuration file to the one specified in [CONFIG FILE]|
| -l [LOG FILE] | sets the log file to the one specified in [LOG FILE]|
| -pc [PCAP FILTER] | sets the PCAP file to the one specified in [PCAP FILTER]|
| -po [PORT NUMBER]  | sets the port number to the one specified in [PORT NUMBER]|
| -ho [HOST IP] | sets the host IP address to the one specified in [HOST IP]| 
|-llvl [LOG LEVEL] | sets the log level to the one specified in [LOG LEVEL]|
|-opid [OBSERVATION POINT ID] | sets the observationPointID to the one specified in [OBSERVATION POINT ID]|
|-odid [OBSERVATION DOMAIN ID] | sets the observationDomainID to the one specified in [OBSERVATION DOMAIN ID]|
|-logserv | turns on logging on the syslog server when using the configuration in the config.xml file|
|-logprot [PROTOCOL TYPE] | sets the protocol for sending syslog messages to the one specified in [PROTOCOL TYPE]|
|-logaddr [IP ADDRESS] | sets the IP address of syslog server to the one specified in [IP ADDRESS]|
|-logport [PORT NUMBER] | sets the port for the communication with the syslog server to the one specified in [PORT NUMBER]|
|-aggreg | sets the process of aggregation in the program|

## Description of the configuration file
-----------------------------
The program can be configured using the **conﬁg.xml** configuration file. The parameters of this file and their description is as follow:

| **Parameter** | **Description** |
| ------------- | -------- |
| conﬁguration | root label for all configurations in the configuration file |
| observationPointId | unique ID of the observation (measurement) point (integer in the range of 1-32767) |
| observationDomainId | unique ID of the observation (measurement) domain (positive integer) |
| readﬁle | if true, then packets will be read from the file. if false, then packets will be sniffed from NIC |
| dumpFile | name of the file to read from when readfile is set to true |
| interface | interface from which packets are going to be captured |
| pcapFilter | BPF ﬁlter type for packet filtering |
| ﬂows | (sub)label for flow related configuration |
| biﬂows | sets the direcation of flow measurement, false-uniﬂow, true-biﬂow |
| passiveTimeout | time in miliseconds for passive timeout. Passive timeout is the time after its expiration the flow is considered to be expired if no packets belonging to the flow have been observed. |
| activeTimeout | time in miliseconds for active timeout. Active timeout is the time that expires the flows on a regular basis even if there is a continuous flow of packets belonging to the flow. |
| sampling | (sub)label for flow related configuration |
| type | integer in the range of 0 to0 5 that specifies sampling |
| parameter1 | first parameter for the sampling function |
| parameter2 | second parameter of the sampling function |
| templates | (sub)label for template related configuration |
| template | (sub)label for configuration of one specific template |
| ﬁeld | definition within one template using the elementID of the information element (see [IPFIX Information Elements][https://www.iana.org/assignments/ipfix/ipfix.xhtml]). If this element is enterprise related, the field is set together with the enterpriseID. |
| mediator | (sub)label for mediator related configuration |
| doMediation | sets the mediator, true - mediator will be used, false - mediator won't be used |
| collector | sub(label) for collector related configuration |
| version | specifies the version of the collector/mediator (IPFIX protocol version) |
| host | IP address (localhost) of the collector/mediator |
| port | port on which the collector/mediator is expecting IPFIX messages |
| sync_port | port on which the collector/mediator expects synchronisation messages |
| protocol | transport protocol for sending IPFIX messages |
| sourceID | ID of the export domain |
| refreshTemplateTime | time for resending the used IPFIX template to the collector/mediator (the configuration depends on the ”default template lifetime” configured in the collector/mediator. |
| reconnectFrequency | frequency in which mybeem will try to reconnect with the collector/mediator if the connection is for some reason interrupted. |
| connectionTimeout | time after whose expiration the connection between mybeem and the collector/mediator is closed |
| synchronization | (sub)label for synchronisation related configuration |
| doSync | sets synchronisation to on/of, false-synchronisation is off, true-synchronisation is on |
| port | port on which mybeen expects synchronisation messages |
| serverAddress | IP address of the synchronisation server |
| serverPort | port on which the synchronisation server expects sync. messages |
| logging | (sub)label for syslog related configuration |
| sendingProtocol | protocol for communicating with the syslog server |
| syslogServIP | IP address of the syslog server |
| syslogServPort | port for communicating with the syslog server |
| messageLogLevel | sets the level of syslog messages |
| aggregation | (sub)label for aggregation related configuration |
| doAggregation | sets aggregation, true - aggregation is on, false - aggregation is off |
| automaticAggregation | if doAggregation is false and the memory utilisation exceeds 85%, aggregation will automatically start to prevent program crash. True - automatic aggregation will be used, false - automatic aggregation won't be used. |
| aggregationTrigger | frequency in milliseconds for aggregation |
| octetTotalCountForAggregation | threshold for mice flow aggregation |
| first | flow key that has the highest priority |
| second | flow key that has the seconds highest priority |
| third | flow key that has the third highest priority  |
| fourth | flow key that has the least priority (this is going to be aggregated as first) |
| dpi | (sub)label for DPI related configuration |
| doDPI | sets DPI to on/off |
| protofile | file with protocols |
