#!/bin/sh

[ "$1" ] && autoreconf -fis

make clean

./configure \
    --prefix=/usr \
    --localstatedir=/var \
    --disable-client \
    --disable-dbus-policy \
    --disable-dbus \
    --disable-systemd-service \
    --disable-monitor \
    --disable-manual-pages \
    --disable-wired

make
