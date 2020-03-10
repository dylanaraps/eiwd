#!/bin/sh

[ "$1" ] && autoreconf -fis

make clean

./configure \
    --prefix=/usr \
    --disable-client \
    --disable-dbus-policy \
    --disable-systemd-service \
    --disable-monitor \
    --disable-manual-pages \
    --disable-wired

make
