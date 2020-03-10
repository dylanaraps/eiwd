#!/bin/sh

[ "$1" ] && autoreconf -fis

make clean

./configure \
    --prefix=/usr \
    --localstatedir=/var \
    --disable-dbus \
    --disable-manual-pages

make
