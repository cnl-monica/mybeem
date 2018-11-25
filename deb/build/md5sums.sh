#!/bin/bash

cd debian
md5sum etc/init.d/mybeemd
md5sum etc/mybeem/config.xml
md5sum usr/sbin/mybeem
md5sum usr/share/doc/mybeem/copyright
md5sum usr/share/doc/mybeem/changelog.Debian.gz
md5sum usr/share/man/man8/mybeem.8.gz
