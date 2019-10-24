=====
 iwd
=====

-----------------------------------------
Network configuration for wireless daemon
-----------------------------------------

:Author: Marcel Holtmann <marcel@holtmann.org>
:Author: Denis Kenzior <denkenz@gmail.com>
:Author: Andrew Zaborowski <andrew.zaborowski@intel.com>
:Author: Tim Kourt <tim.a.kourt@linux.intel.com>
:Copyright: 2013-2019 Intel Corporation
:Version: iwd
:Date: 22 September 2019
:Manual section: 5
:Manual group: Linux Connectivity

SYNOPSIS
========

Network configuration files ``.open``, ``.psk`` and ``.8021x``

DESCRIPTION
===========

**iwd** stores information on known networks, and reads information on
pre-provisioned networks, from small text configuration files.  Those files
live in the state directory specified by the environment variable
*$STATE_DIRECTORY*, which is normally provided by **systemd**.  In the absence
of such an environment variable it defaults to *$LIBDIR/iwd*, which normally
is set to */var/lib/iwd*.  You can create, modify or remove those files.
**iwd** monitors the directory for changes and will update its state
accordingly.  **iwd** will also modify these files in the course of network
connections or as a result of D-Bus API invocations.

FILE FORMAT
===========

The syntax is similar to that of GNOME keyfile syntax (which is based on the
format defined in the Desktop Entry Specification, see
*http://freedesktop.org/Standards/desktop-entry-spec*).  The recognized groups
as well as keys and values in each group are documented here.  Defaults are
written in bold.

For completeness we include the description of the file syntax here. This is
the syntax that the ell library's l_settings class implements. The syntax is
based on lines and lines are delimited by newline characters.

Empty lines are ignored and whitespace at the beginning of a line is ignored.
Comment lines have ``#`` as their first non-whitespace character.

Key-value lines contain a setting key, an equal sign and the value of the
setting.  Whitespace preceding the key, the equal sign or the value, is
ignored.  The key must be a continuous string of alphanumeric and underscore
characters and minus signs only.  The value starts at the first non-whitespace
character after the first equal sign on the line and ends at the end of the
line and must be correctly UTF-8-encoded. A boolean value can be ``true`` or
``false`` but ``0`` or ``1`` are also allowed.  Integer values are written
in base 10.  String values, including file paths and hexstrings, are written
as is except for five characters that may be backslash-escaped: space,
``\t``, ``\r``, ``\n`` and backslash itself.  The latter three must be
escaped.  A space character must be escaped if it is the first character
in the value string and is written as ``\s``.

Settings are interpreted depending on the group they are in.  A group starts
with a group header line and contains all settings until the next group's
header line.  A group header line contains a ``[`` character followed by
the group name and a ``]`` character.  Whitespace is allowed before the
``[`` and after the ``]``.  A group name consists of printable characters
other than ``[`` and ``]``.

NAMING
======

File names are based on the network's SSID and security type: Open,
PSK-protected or 802.1x. The name consist of the encoding of the SSID
followed by ``.open``, ``.psk`` or ``.8021x``.  The SSID appears verbatim
in the name if it contains only alphanumeric characters, spaces, underscores
or minus signs.  Otherwise it is encoded as an equal sign followed by the
lower-case hex encoding of the name.

SETTINGS
========

The settings below are split into several sections and grouped into broad
categories.  Each category has a group associated with it which is given at
the beginning of each sub-section.  Recognized keys and valid values are listed
following the group definition.

General Settings
----------------

The group ``[General]`` contains general settings.

.. list-table::
   :header-rows: 1
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - Key
     - Description
   * - AutoConnect
     - Values: **true**, false

       Whether the network can be connected to automatically
   * - Hidden
     - Values: true, **false**

       Whether the network is hidden, i.e. its SSID must be included in an
       active scan request

Network Authentication Settings
-------------------------------

The group ``[Security]`` contains settings for Wi-Fi security and
authentication configuration.

.. list-table::
   :header-rows: 1
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - Key
     - Description
   * - Passphrase
     - 8..63 character string

       Passphrase to be used when connecting to WPA-Personal networks.
       Required when connecting to WPA3-Personal (SAE) networks.  Also
       required if the *PreSharedKey* is not provided.  If not provided in
       settings, the agent will be asked for the passphrase at connection
       time.
   * - PreSharedKey
     - 64 character hex string

       Processed passphrase for this network in the form of a hex-encoded 32
       byte pre-shared key.  Must be provided if *Passphrase* is omitted.
   * - EAP-Method
     - one of the following methods:

       AKA, AKA', GTC, MD5, MSCHAPV2, PEAP, PWD, SIM, TLS, TTLS
   * - EAP-Identity
     - string

       Identity string transmitted in plaintext.  Depending on the EAP method,
       this value can be optional or mandatory.  GTC, MD5, MSCHAPV2, PWD
       require an identity, so if not provided, the agent will be asked for it
       at connection time.  TLS based methods (PEAP, TLS, TTLS) might still
       require an *EAP-Identity* to be set, depending on the RADIUS server
       configuration.
   * - EAP-Password
     - string

       Password to be provided for WPA-Enterprise authentication.  If not
       provided, the agent will be asked for the password at connection time.
       Required by: GTC, MD5, MSCHAPV2, PWD.
   * - EAP-Password-Hash
     - hex string

       Some EAP methods can accept a pre-hashed version of the password.  For
       MSCHAPV2, a MD4 hash of the password can be given here.
   * - | EAP-TLS-CACert,
       | EAP-TTLS-CACert,
       | EAP-PEAP-CACert
     - absolute file path or embedded pem

       Path to a PEM-formatted X.509 root certificate list to use for trust
       verification of the authenticator.  The authenticator's server's
       certificate chain must be verified by at least one CA in the list for
       the authentication to succeed.  If omitted, then authenticator's
       certificate chain will not be verified (not recommended.)
   * - EAP-TLS-ClientCert
     - absolute file path or embedded pem

       Path to a PEM-formatted client X.509 certificate or certificate chain
       to send on server request.
   * - EAP-TLS-ClientKey
     - absolute file path or embedded pem

       Path to a PEM-formatted client PKCS#8 private key corresponding to the
       public key provided in *EAP-TLS-ClientCert*.
   * - | EAP-TLS-
       | ClientKeyPassphrase
     - string

       Decryption key for the client private key file.  This is used if the
       private key given by *EAP-TLS-ClientKey* is encrypted.  If not provided,
       then the agent is asked for the passphrase at connection time.
   * - | EAP-TLS-ServerDomainMask,
       | EAP-TTLS-ServerDomainMask,
       | EAP-PEAP-ServerDomainMask
     - string

       A mask for the domain names contained in the server's certificate. At
       least one of the domain names present in the certificate's Subject
       Alternative Name extension's DNS Name fields or the Common Name has to
       match at least one mask, or authentication will fail.  Multiple masks
       can be given separated by semicolons.  The masks are split into segments
       at the dots.  Each segment has to match its corresponding label in the
       domain name. An asterisk segment in the mask matches any label.  An
       asterisk segment at the beginning of the mask matches one or more
       consecutive labels from the beginning of the domain string.
   * - | EAP-TTLS-Phase2-Method
     - | The following values are allowed:
       |    Tunneled-CHAP,
       |    Tunneled-MSCHAP,
       |    Tunneled-MSCHAPv2,
       |    Tunneled-PAP or
       |    a valid EAP method name (see *EAP-Method*)

       Phase 2 authentication method for EAP-TTLS.  Can be either one of the
       TTLS-specific non-EAP methods (Tunneled-\*), or any EAP method
       documented here.  The following two settings are used if any of the
       non-EAP methods is used.
   * - | EAP-TTLS-Phase2-Identity
     - The secure identity/username string for the TTLS non-EAP Phase 2
       methods.  If not provided IWD will request a username at connection
       time.
   * - | EAP-TTLS-Phase2-Password
     - Password string for the TTLS non-EAP Phase 2 methods. If not provided
       IWD will request a passphrase at connection time.
   * - EAP-TTLS-Phase2-*
     - Any settings to be used for the inner EAP method if one was specified
       as *EAP-TTLS-Phase2-Method*, rather than a TTLS-specific method. The
       prefix *EAP-TTLS-Phase2-* replaces the *EAP-* prefix in the setting
       keys and their usage is unchanged.  Since the inner method's
       negotiation is encrypted, a secure identity string can be provided.
   * - EAP-PEAP-Phase2-*
     - Any settings to be used for the inner EAP method with EAP-PEAP as the
       outer method. The prefix *EAP-PEAP-Phase2-* replaces the *EAP-* prefix
       in the setting keys and their usage is unchanged. Since the inner
       method's negotiation is encrypted, a secure identity string can be
       provided.

SEE ALSO
========

iwd(8), iwd.config(5)
