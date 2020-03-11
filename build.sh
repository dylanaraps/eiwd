#!/bin/sh

[ "$1" ] && autoreconf -fi

make clean

./configure \
    --prefix=/usr \
    --localstatedir=/var \
    --disable-dbus \
    --disable-manual-pages

make
