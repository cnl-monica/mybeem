# MyBeem
--------

MyBeem (an IPFIX exporter implemented in C language) represents the lowest component of the SLAmeter network traffic measurement/monitoring tool. MyBeem captures packets from the interface card and orgnaises them into flow records. Flow records are containers that carry the properties (e.g. the total number of bytes of all packets belonging to a certain flow) and characteristics (e.g. source IP address) of the flow. 

The flow records are generated by one or more metering processes. The metering process consists of a set of functions including packet capture, filtering, timestamping, sampling, classification and creating/maintaining flow records in the flow cache. Network traffic monitoring is based on the analysis of the exported flow records.

<p align="center">
  <img src="/fig/exporter.png" width="356" title="Architecture of the exporter">
</p>


The export of flow records represents a push-based mechanism, where the data are transmitted from the exporter(s) to the IPFIX collector(s) over either the TCP, UDP or SCTP protocol.

MyBeem is in full conformity with IPFIX, Netflow and PSAMP. It is a command-line application without any GUI. It provides logging on various levels (info, warning, debug, etc.) that are shown in the terminal. MyBeem was developed using open-source technologies.

*  **Latest version**: 1.1-9 
*  **Version state**: stable
*  **Developers**:
      *   Dávid Farkas
      *   Samuel Tremko
      *   Tomáš Kecsey
      *   Ľuboš Husivarga
      *   Viliam Lorinc
 
*   **License**: GNU GPLv3
*   **Implementation environment**: C programming language in GNU/Linux environment 

## Documentation

**The documentation is available only in Slovak language:**
 * [User Documentation PDF](https://github.com/cnl-monica/mybeem/tree/master/doc/mybeem_v1.1-9_PP.pdf)
 * [Technical Documenation PDF](https://github.com/cnl-monica/mybeem/tree/master/doc/mybeem_v1.1-9_SP.pdf)

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
Installation on **i386** architectures:
```bash
wget https://github.com/cnl-monica/mybeem/tree/master/deb/mybeem_1.1-9_i386.deb --no-check-certificate
sudo dpkg -i mybeem_1.1-9_i386.deb
```

Installation on **amd64** architectures:
```bash
wget https://github.com/cnl-monica/mybeem/tree/master/deb/mybeem_1.1-9_amd64.deb --no-check-certificate
sudo dpkg -i mybeem_1.1-9_amd64.deb
```

After installation the program can be run using the following command:
```bash
sudo mybeem
```
or using the following command:
```bash
sudo /etc/init.d/mybeemd start
```

## Manual installation 
-------------------------------
##### 1. Install the following packages:
```bash
sudo apt-get install libpcap-dev libxml2-dev libssl-dev libsctp-dev libsctp-dev libssl0.9.8 libsctp-dev libxml2-utils gawk gcc autoconf build-essential libtool
```
##### 2. Download nDPI v1.5.2:
```bash
wget https://github.com/cnl-monica/mybeem/tree/master/lib/nDPI_1.5.2.tar.gz --no-check-certificate
```
##### 3. Installation of nDPI v1.5.2:
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
##### 7. Creating the required directories:
```bash
sudo mkdir /var/log/mybeem
sudo mkdir /etc/mybeem
```
### 8. Copy the files to the directories:
```bash
sudo cp mybeem /usr/sbin/
sudo cp config.xml /etc/mybeem/
sudo cp mybeemd /etc/init.d/
```
##### 9. The program can be run using the following command:
```bash
sudo mybeem
```
or using:
```bash
sudo /etc/init.d/mybeemd start
```

## Running the program via source code compilation
------------------------------------------------
##### 1. Install the following packages:
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
##### 6. Run the program:
```bash
sudo ./beem -c config.xml
```

## Other useful documents
------------------------------------------------
 *   [Tutorial on creating a DEB installation package for MyBeem](mybeem_debian)
 *   [Tutorial on implementating a new information element in MyBeem](mybeem_newIE)
