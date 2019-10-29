=======
 iwctl
=======

---------------------------------
Internet wireless control utility
---------------------------------

:Author: Marcel Holtmann <marcel@holtmann.org>
:Copyright: 2013-2019 Intel Corporation
:Version: iwctl
:Date: 22 September 2019
:Manual section: 1
:Manual group: Linux Connectivity

SYNOPSIS
========

**iwctl** [*options* ...] [*commands* ...]

DESCRIPTION
===========

Tool for configuring **iwd** daemon via D-Bus interface. It supports both an
interactive mode and command line mode.

OPTIONS
=======

--username, -u          Provide username.
--password, -p          Provide password.
--passphrase, -P        Provide passphrase.
--dont-ask, -v          Don't ask for missing credentials.
--help, -h              Show help message and exit.

EXAMPLES
========

Interactive mode
----------------

To start an interactive mode and list all available commands do:
.. code-block::

   $ iwctl
   [iwd]# help

To connect to a network:
.. code-block::

   [iwd]# device list
   [iwd]# station DEVICE scan
   [iwd]# station DEVICE get-networks
   [iwd]# station DEVICE connect SSID

Command line mode
-----------------

To list all available commands in command line mode and exit do:
.. code-block::

   $ iwctl --help

To connect to a network:
.. code-block::

   $ iwctl device list
   $ iwctl station DEVICE scan
   $ iwctl station DEVICE get-networks
   $ iwctl --passphrase=PASSPHRASE station DEVICE connect SSID

SEE ALSO
========

iwd(8)
