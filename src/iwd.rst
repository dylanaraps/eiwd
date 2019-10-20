=====
 iwd
=====

------------------------
Internet wireless daemon
------------------------

:Author: Marcel Holtmann <marcel@holtmann.org>
:Author: Denis Kenzior <denkenz@gmail.com>
:Author: Andrew Zaborowski <andrew.zaborowski@intel.com>
:Author: Tim Kourt <tim.a.kourt@linux.intel.com>
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
Wi-Fi connectivity solution for Linux based devices.  The core goal of
the project is to optimize resource utilization: storage, runtime memory
and link-time costs.  This is accomplished by not depending on any external
libraries and utilizes features provided by the Linux Kernel to the maximum
extent possible.  The result is a self-contained environment that only
depends on the Linux Kernel and the runtime C library.

OPTIONS
=======

--version, -v           Show version number and exit.
--help, -h              Show help message and exit.

ENVIRONMENT
===========

*$STATE_DIRECTORY* is used for network configuration files.  See section
*iwd.network* for details.

*$CONFIGURATION_DIRECTORY* is used for daemon configuration settings.  Only
the file **main.conf** is currently read from this directory.  See *iwd.conf*
for details.

*$IWD_RTNL_DEBUG* set to ``1`` enables RTNL debugging.

*$IWD_DHCP_DEBUG* set to ``1`` enables DHCP debugging.

*$IWD_TLS_DEBUG* set to ``1`` enables TLS debugging.

*$IWD_WSC_DEBUG_KEYS* set to ``1`` enables WSC debug keys.

SEE ALSO
========

iwd.conf(5), iwd.network(5), iwctl(1), iwmon(1), hwsim(1), ead(8),
systemd.exec(5)

http://iwd.wiki.kernel.org
