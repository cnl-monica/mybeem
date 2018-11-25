# Tutorial on creating DEB packages for MyBeem
---------------------------------------

**Helper scripts:**

When creating a .deb packages, helper scripts can be also used that automate some of the tasks related to the package creation.


```
md5sums.sh - this scripts shows the md5 checksum for all the files.
remove~.sh - this script removes all the files ending with the tilde (~) symbol (these files are created by the OS).
build.sh - this script creates the package itself and checks its correctness using the lintian tool.
```
These scripts are available for download:
```bash
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/deb/build/md5sums.sh --no-check-certificate
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/deb/build/remove~.sh --no-check-certificate
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/deb/build/build.sh --no-check-certificate
```
For using these scripts, it is necessary to first set the following variables:
* SRC_BIN - absolute path to the binary executable that is aimed to be added to the package.
* DST_BIN - absolute path to the binary executable in the package.

The package is created using the following command:
```bash
./build.sh package_name.deb
```

Creating a deb package for the exporter involves the following steps:

### 1. Creating the directory and file structure:

First we create the structure of directories and files. For simplicity, this sctructure can be downloaded from [here](https://git.cnl.sk/monica/slameter_exporter/raw/master/deb/debian.tar.gz). Alternatively, an older version of the deb package can be also extracted which can be subsequently updated.
```
debian/DEBIAN/conffiles          - contains the paths of the configuration files ( /etc/mybeem/config.xml, /etc/init.d/mybeemd )
debian/DEBIAN/control            - contains information about the package and the program
debian/DEBIAN/md5sums            - md5 hash for every file except files in the DEBIAN folder. MD5 hash can be obtained using the *md5sum nameoffile* command.
debian/DEBIAN/postinst           - script that is run after package installation
debian/DEBIAN/postrm             - script that is run after package removal (uninstallation)
debian/DEBIAN/preinst            - script that is run before package installation  
debian/DEBIAN/prerm              - script that is run before package removal (uninstallation)
debian/etc/init.d/mybeemd        - mybeem daemon
debian/etc/mybeem/config.xml     - configuration file for mybeem
debian/usr/sbin/mybeem           - binary executable of mybeem
debian/usr/share/doc/mybeem/changelog.Debian.gz
debian/usr/share/doc/mybeem/changelog.gz    - it is necessary to install the devscripts package. To edit changelog files refer to *man debchange*
debian/usr/share/doc/mybeem/copyright
debian/usr/share/man/man8/mybeem.8.gz       - To edit it is necessary to know how to create/update man pages
```

**Control file:**

Example of control file:
```
Package: mybeem
Version: 1.1-3
Section: net
Priority: extra
Architecture: i386
Depends: libc6 (>= 2.3.6-6~), libpcap0.8 (>= 0.9.3-1), libxml2 (>= 2.7.4)
Installed-size: 152
Maintainer: Adrian Pekar <adrian.pekar@cnl.sk>
Description: BasicMeter Exporting and Measuring process
 .
 For details about MyBeem and MONICA project please visit our homepage at:
 https://git.kpi.fei.tuke.sk/monica
```
We can obtain the size (Installed-size) based on the size of the **debian/** directory (in KiB = 1024 bytes).
A more detailed description of the files is provided in Section 5.3 of http://www.debian.org/doc/debian-policy/ch-controlfields.html

**Scripts**:
```
debian/DEBIAN/postinst   - script that is run after package installation
debian/DEBIAN/postrm     - script that is run after package removal (uninstallation)
debian/DEBIAN/preinst    - script that is run before package installation  
debian/DEBIAN/prerm      - script that is run before package removal (uninstallation)
```

### 2. Creating the .deb package:
After updating the individual files and their information the deb package can be created using the following command:
```bash
fakeroot dpkg-deb --build debian/
```
For executing this command it is necessary to have *fakeroot* installed. After executing the command the package will be created under the name **debian.deb**.

### 3. Checking the .deb package:
Using the following command we can check the package for its compatibility with the DEBIAN package requirements:
```bash
lintian debian.deb
```

### 4. At last we rename the .deb package:
We rename the **debian.deb** file to **mybeem_*version*_*architecture*.deb**.
