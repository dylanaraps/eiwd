===========
 main.conf
===========

--------------------------------------
Configuration file for wireless daemon
--------------------------------------

:Author: Marcel Holtmann <marcel@holtmann.org>
:Copyright: 2013-2019 Intel Corporation
:Version: iwd
:Date: 22 September 2019
:Manual section: 5
:Manual group: Linux Connectivity

SYNOPSIS
========

**main.conf**

DESCRIPTION
===========

The *main.conf* configuration file configures the system-wide settings for
**iwd**.  This file lives in the configuration directory specified by the
environment variable *$CONFIGURATION_DIRECTORY*, which is normally provided
by **systemd**.  In the absence of such an environment variable it defaults
to */etc/iwd*.  If no *main.conf* is present, then default values are
chosen.  The presence of *main.conf* is not required.

SETTINGS
========

The settings are split into several categories.  Each category has a group
associated with it and described in separate tables below.

General Settings
----------------

The group ``[General]`` contains general settings.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - enable_network_config
     - Values: true, false (default)

       Enable network configuration.

       Setting this option to *true* enables **iwd** to configure the network
       interfaces with the IP addresses.  There are two types IP addressing
       supported by **iwd**: static and dynamic.  The static IP addresses are
       configured through the network configuration files.  If no static IP
       configuration has been provided for a network, iwd will attempt to
       obtain the dynamic addresses from the network through the built-in
       DHCP client.

       The network configuration feature is disabled by default.

   * - dns_resolve_method
     - Values: resolvconf, systemd (default)

       Indicate a DNS resolution method used by the system.

       This configuration option must be used in conjunction with
       ``enable_network_config`` and provides the choice of system resolver
       integration.

       If not specified, ``systemd`` is used as default.

SEE ALSO
========

iwd(8)
