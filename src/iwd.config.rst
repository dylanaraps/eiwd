=====
 iwd
=====

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

Configuration file **main.conf**

DESCRIPTION
===========

The *main.conf* configuration file configures the system-wide settings for
**iwd**.  This file lives in the configuration directory specified by the
environment variable *$CONFIGURATION_DIRECTORY*, which is normally provided
by **systemd**.  In the absence of such an environment variable it defaults
to */etc/iwd*.  If no *main.conf* is present, then default values are
chosen.  The presence of *main.conf* is not required.

FILE FORMAT
===========

See *iwd.network* for details on the file format.

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

Blacklist
---------

The group ``[Blacklist]`` contains settings related to blacklisting of BSSes.
If iwd determines that a connection to a BSS fails for a reason that indicates
the BSS is currently misbehaving or misconfigured (e.g. timeouts, unexpected
status/reason codes, etc), then iwd will blacklist this BSS and avoid connecting
to it for a period of time.  These options let the user control how long
a misbehaved BSS spends on the blacklist.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - InitialTimeout
     - Values: uint64 value in seconds (default: **60**)

       The initial time that a BSS spends on the blacklist.
   * - Multiplier
     - Values: unsigned int value in seconds (default: **30**)

       If the BSS was blacklisted previously and another connection attempt
       has failed after the initial timeout has expired, then the BSS blacklist
       time will be extended by a multiple of *Multiplier* for each
       unsuccessful attempt up to *MaxiumTimeout* time in seconds.
   * - MaximumTimeout
     - Values: uint64 value in seconds (default: **86400**)

       Maximum time that a BSS is blacklisted.

Rank
----

The group ``[Rank]`` contains settings related to ranking of networks for
autoconnect purposes.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - BandModifier5Ghz
     - Values: floating point value (default: **1.0**)

       Increase or decrease the preference for 5GHz access points by increasing
       or decreasing the value of this modifier.  5GHz networks are already
       preferred due to their increase throughput / data rate.  However, 5GHz
       networks are highly RSSI sensitive, so it is still possible for IWD to
       prefer 2.4Ghz APs in certain circumstances.

Scan
----

The group ``[Scan]`` contains settings related to scanning functionality.
No modification from defaults is normally required.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - DisablePeriodicScan
     - Values: true, **false**

       Disable periodic scan. Setting this option to 'true' will prevent iwd
       from issuing the periodic scans for the available networks while
       disconnected.  The behavior of the user-initiated scans isn't affected.
       The periodic scan is enabled by default.
   * - DisableRoamingScan
     - Values: trrue, **false**

       Disable roaming scan. Setting this option to 'true' will prevent iwd
       from trying to scan when roaming decisions are activated.  This can
       prevent iwd from roaming properly, but can be useful for networks
       operating under extremely low rssi levels where roaming isn't possible.

SEE ALSO
========

iwd(8), iwd.network(5)
