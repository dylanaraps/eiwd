
AM_MAKEFLAGS = --no-print-directory

ACLOCAL_AMFLAGS = -I build-aux

noinst_LTLIBRARIES = ell/libell-internal.la

ell_sources = ell/ell.h ell/private.h \
			ell/util.h ell/util.c \
			ell/test.h ell/test.c \
			ell/queue.h ell/queue.c \
			ell/hashmap.h ell/hashmap.c \
			ell/string.h ell/string.c \
			ell/settings.h ell/settings.c \
			ell/main.h ell/main.c \
			ell/idle.h ell/idle.c \
			ell/signal.h ell/signal.c \
			ell/timeout.h ell/timeout.c \
			ell/io.h ell/io.c \
			ell/log.h ell/log.c \
			ell/plugin.h ell/plugin.c \
			ell/checksum.h ell/checksum.c \
			ell/netlink.h ell/netlink.c \
			ell/dbus-private.h \
			ell/dbus.h ell/dbus.c \
			ell/dbus-service.h ell/dbus-service.c

ell_libell_internal_la_SOURCES = $(ell_sources)

bin_PROGRAMS = src/iwd client/iwctl

src_iwd_SOURCES = src/main.c
src_iwd_LDADD = ell/libell-internal.la

client_iwctl_SOURCES = client/main.c
client_iwctl_LDADD = ell/libell-internal.la

AM_CFLAGS = -fvisibility=hidden

MAINTAINERCLEANFILES = Makefile.in configure config.h.in aclocal.m4

DISTCLEANFILES = $(BUILT_SOURCES)

BUILT_SOURCES = ell/internal

ell/internal: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_sources) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(top_srcdir)/../../ell/$$f ; \
		fi \
	done > $@

maintainer-clean-local:
	-rm -rf build-aux ell
