# Návod na tvorbu DEB balíka pre MyBeem
---------------------------------------

**Pomocné skripty:**

Pri tvorbe .deb balíka je možné využiť aj pomocné skripty, ktoré automatizujú niektoré činnosti spojené s vytváraním balíka.
```
md5sums.sh - skript vypíše md5 súčty pre všetky potrebné súbory v potrebnej forme
remove~.sh - skript odstráni všeky súbory končiace znakom tilda, teda záložné súbory vytvorené operačným systémom
build.sh - skript na samotné vytvorenie balíka. Skript vykoná potrebné úkony pre vytvorenie balíka, ktorý nasledne skontroluje pomocou nástroja lintian.
```
Tieto skripty je možné stiahnuť pomocou príkazu:
```bash
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/deb/build/md5sums.sh --no-check-certificate
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/deb/build/remove~.sh --no-check-certificate
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/deb/build/build.sh --no-check-certificate
```
Pre použitie skriptu je potrebné najprv nastavit hodnoty týchto premenných:
* SRC_BIN - absolútna cesta k spustiteľnému súboru, ktorý sa má vložiť do balíka.
* DST_BIN - relatívna cesta k spustiteľnému súboru v balíku.

Samotné vytvorenie balíka sa vykoná zadaním príkazu:
```bash
./build.sh nazov_balika.deb
```

Vytvorenie deb balíka pre exportér spočíva v týchto krokoch:

### 1. Vytvorenie štruktúry priečinkov a súborov:
Vytvoríme nasledujúcu štruktúru priečinkov s nasledujúcimi súbormi (- opis niektorých súborov). Pre zjednodušenie práce sa nasledujúca štruktúra so všetkými súbormi je stiahnuteľná z [tohto](https://git.cnl.sk/monica/slameter_exporter/raw/master/deb/debian.tar.gz) miesta. Alebo sa dá rozbaliť aj inštalačný deb balík staršej verzie programu MyBeem a potom stačí len aktualizovať jednotlivé súbory.
```
debian/DEBIAN/conffiles          - obsahuje cesty pre konfiguračné súbory ( /etc/mybeem/config.xml, /etc/init.d/mybeemd )
debian/DEBIAN/control            - obsahuje informácie o balíku a programe
debian/DEBIAN/md5sums            - md5 hash pre každý súbor okrem súborov v priečinku DEBIAN. MD5 hash môžeme získať pomocou príkazu md5sum menoSuboru
debian/DEBIAN/postinst           - skript ktorý sa spustí po inštalácii balíka
debian/DEBIAN/postrm             - skript ktorý sa spustí po odstránení balíka
debian/DEBIAN/preinst            - skript ktorý sa spustí pred inštaláciou balíka  
debian/DEBIAN/prerm              - skript ktorý sa spustí pred odstránení balíka
debian/etc/init.d/mybeemd        - mybeem daemon
debian/etc/mybeem/config.xml     - konfiguračný súbor pre mybeem
debian/usr/sbin/mybeem           - spustiteľný súbor programu mybeem
debian/usr/share/doc/mybeem/changelog.Debian.gz
debian/usr/share/doc/mybeem/changelog.gz    - treba nainštalovať balík devscripts. Na úpravu changelog súborov viď. man debchange.
debian/usr/share/doc/mybeem/copyright
debian/usr/share/man/man8/mybeem.8.gz       - na úpravu je potrebná znalosť vytvárania man stránok
```

**Control súbor:**

Príklad control súboru:
```
Package: mybeem
Version: 1.1-3
Section: net
Priority: extra
Architecture: i386
Depends: libc6 (>= 2.3.6-6~), libpcap0.8 (>= 0.9.3-1), libxml2 (>= 2.7.4)
Installed-size: 152
Maintainer: Tomas Kecsey <keckus@gmail.com>
Description: BasicMeter Exporting and Measuring process
 .
 For details about MyBeem and MONICA project please visit our homepage at:
 http://wiki.cnl.tuke.sk/Monica
```
Veľkosť (Installed-size) môžeme zistiť pomocou zistenia veľkosti súboru **debian/** (v KiB = 1024 bajtov).
Podrobnejší opis control súborov sa nachádza na nasledujúcej stránke v sekcii 5.3: http://www.debian.org/doc/debian-policy/ch-controlfields.html

**Skripty**:
```
/debian/DEBIAN/postinst    - skript vykonajúci sa po inštalácii
/debian/DEBIAN/postrm      - skript vykonajúci sa po odstránení
/debian/DEBIAN/preinst     - skript vykonajúci sa pred inštaláciou
/debian/DEBIAN/prerm       - skript vykonajúci sa pred odstránením
```

### 2. Vytvorenie .deb inštalačného balíka:
Po aktualizácii jednotlivých súborov a údajov deb balíka je potrebné tento balík vytvoriť pomocou príkazu:
```bash
fakeroot dpkg-deb --build debian/
```
Pre vykonanie príkazu je potrebné nainštalovať nástroj fakeroot. Vytvorí sa inštalačný balík s názvom **debian.deb**.

### 3. Kontrola .deb inštalačného balíka:
Nasledujúcim príkazom je možné prekontrolovať balík a zistiť či vyhovuje štandardným požiadavkám DEBIAN inštalačných balíkov:
```bash
lintian debian.deb
```

### 4. Úprava názvu výsledného .deb inštalačného balíka:
Súbor **debian.deb** premenujeme na **mybeem_*verzia*_*architektura*.deb**.
