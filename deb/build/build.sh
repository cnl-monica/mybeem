#!/bin/bash

SRC_BIN=/home/keci/Desktop/5.ROCNIK/SVNpracovny/mybeem/beem
DST_BIN=debian/usr/sbin/mybeem


# vlozenie aktualneho vykonatelneho suboru (za prvy argument je potrebne dat cestu k vykonatelnemu suboru)
echo "Copying file $SRC_BIN to $DST_BIN ..."
cp  $SRC_BIN $DST_BIN
# vlozenie aktualnych md5sums
echo "Generating md5 checksums ..."
./md5sums.sh > debian/DEBIAN/md5sums
# zmazanie zaloznych suborov
echo "Removing backup files ..."
./remove~.sh
# odstranenie nepotrebnych symbolov z mybeem
echo "Stripping $DST_BIN ..."
strip $DST_BIN
# vytvorenie balika
fakeroot dpkg --build debian/
# premenovanie balika
echo "Renaming package to $1 ..."
mv debian.deb $1
echo "########### Checking package validity ###########"
# overenie balika
lintian $1
