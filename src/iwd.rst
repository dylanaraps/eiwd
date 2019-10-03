=====
 iwd
=====

------------------------
Internet wireless daemon
------------------------

:Author: Marcel Holtmann <marcel@holtmann.org>
:Copyright: 2013-2019 Intel Corporation
:Version: iwd
:Date: 22 September 2019
:Manual section: 8
:Manual group: Linux Connectivity

SYNOPSIS
========

**iwd** [*options* ...]

DESCRIPTION
===========

Daemon for managing Wireless devices on Linux.

The iNet Wireless Daemon (iwd) project aims to provide a comprehensive
Wi-Fi connectivity solution for Linux based devices. The core goal of
the project is to optimize resource utilization: storage, runtime memory
and link-time costs. This is accomplished by not depending on any external
libraries and utilizes features provided by the Linux Kernel to the maximum
extent possible. The result is a self-contained environment that only
depends on the Linux Kernel and the runtime C library.

OPTIONS
=======

--version, -v           Show version number and exit.
--help, -h              Show help message and exit.

SEE ALSO
========

iwctl(1), iwmon(1), hwsim(1), ead(8)

http://iwd.wiki.kernel.org
