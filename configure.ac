AC_PREREQ(2.60)
AC_INIT(iwd, 0.0)

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests silent-rules
					tar-pax no-dist-gzip dist-xz])
AC_CONFIG_HEADERS(config.h)
AC_USE_SYSTEM_EXTENSIONS

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

AC_PROG_CC
AC_PROG_INSTALL

AC_OUTPUT(Makefile)
