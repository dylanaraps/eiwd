
AM_MAKEFLAGS = --no-print-directory

ACLOCAL_AMFLAGS = -I build-aux

noinst_LTLIBRARIES = ell/libell-internal.la

ell_sources = ell/ell.h ell/private.h ell/missing.h \
			ell/util.h ell/util.c \
			ell/test.h ell/test.c \
			ell/queue.h ell/queue.c \
			ell/hashmap.h ell/hashmap.c \
			ell/ringbuf.h ell/ringbuf.c \
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
			ell/netlink-private.h \
			ell/netlink.h ell/netlink.c \
			ell/genl-private.h \
			ell/genl.h ell/genl.c \
			ell/dbus-private.h \
			ell/dbus.h ell/dbus.c \
			ell/dbus-kernel.c \
			ell/dbus-util.c \
			ell/dbus-message.c \
			ell/dbus-service.h ell/dbus-service.c \
			ell/gvariant-private.h \
			ell/gvariant-util.c \
			ell/siphash-private.h \
			ell/siphash.c \
			ell/hwdb.h ell/hwdb.c \
			ell/cipher-private.h \
			ell/cipher.h ell/cipher.c \
			ell/random.h ell/random.c \
			ell/uintset.h ell/uintset.c \
			ell/base64.h ell/base64.c \
			ell/pem.h ell/pem.c \
			ell/tls-private.h \
			ell/tls.h ell/tls.c

ell_libell_internal_la_SOURCES = $(ell_sources)

bin_PROGRAMS = src/iwd client/iwctl monitor/iwmon

src_iwd_SOURCES = src/main.c linux/nl80211.h linux/kdbus.h \
					src/kdbus.h src/kdbus.c \
					src/netdev.h src/netdev.c \
					src/wiphy.h src/wiphy.c \
					src/sha1.h src/sha1.c \
					src/ie.h src/ie.c \
					src/dbus.h src/dbus.c \
					src/manager.h src/manager.c \
					src/crypto.h src/crypto.c \
					src/mpdu.h src/mpdu.c \
					src/eapol.h src/eapol.c \
					src/scan.h src/scan.c \
					src/util.h src/util.c \
					src/agent.h src/agent.c \
					src/storage.h src/storage.c \
					src/network.h src/network.c \
					src/wsc.h src/wsc.c \
					iwd.h
src_iwd_LDADD = ell/libell-internal.la

client_iwctl_SOURCES = client/main.c linux/kdbus.h \
					src/kdbus.h src/kdbus.c
client_iwctl_LDADD = ell/libell-internal.la

monitor_iwmon_SOURCES = monitor/main.c linux/nl80211.h \
					monitor/nlmon.h monitor/nlmon.c \
					monitor/pcap.h monitor/pcap.c \
					monitor/display.h monitor/display.c \
					src/ie.h src/ie.c \
					src/wsc.h src/wsc.c \
					src/mpdu.h src/mpdu.c \
					src/util.h src/util.c \
					src/sha1.h src/sha1.c \
					src/crypto.h src/crypto.c \
					src/eapol.h src/eapol.c
monitor_iwmon_LDADD = ell/libell-internal.la

noinst_PROGRAMS = tools/hwsim

tools_hwsim_LDADD = ell/libell-internal.la

unit_tests = unit/test-cmac-aes \
		unit/test-hmac-md5 unit/test-hmac-sha1 unit/test-hmac-sha256 \
		unit/test-pbkdf2-sha1 unit/test-prf-sha1 \
		unit/test-crypto unit/test-eapol unit/test-mpdu \
		unit/test-ie unit/test-ssid-to-utf8 unit/test-ssid-security \
		unit/test-arc4 unit/test-wsc

if MAINTAINER_MODE
noinst_PROGRAMS += $(unit_tests)
endif

unit_test_cmac_aes_SOURCES = unit/test-cmac-aes.c \
					src/sha1.h src/sha1.c \
					src/crypto.h src/crypto.c
unit_test_cmac_aes_LDADD = ell/libell-internal.la

unit_test_arc4_SOURCES = unit/test-arc4.c \
					src/sha1.h src/sha1.c \
					src/crypto.h src/crypto.c

unit_test_arc4_LDADD = ell/libell-internal.la

unit_test_hmac_md5_SOURCES = unit/test-hmac-md5.c \
					src/sha1.h src/sha1.c \
					src/crypto.h src/crypto.c
unit_test_hmac_md5_LDADD = ell/libell-internal.la

unit_test_hmac_sha1_SOURCES = unit/test-hmac-sha1.c \
					src/sha1.h src/sha1.c
unit_test_hmac_sha1_LDADD = ell/libell-internal.la

unit_test_hmac_sha256_SOURCES = unit/test-hmac-sha256.c \
					src/sha1.h src/sha1.c \
					src/crypto.h src/crypto.c
unit_test_hmac_sha256_LDADD = ell/libell-internal.la

unit_test_pbkdf2_sha1_SOURCES = unit/test-pbkdf2-sha1.c \
					src/sha1.h src/sha1.c
unit_test_pbkdf2_sha1_LDADD = ell/libell-internal.la

unit_test_prf_sha1_SOURCES = unit/test-prf-sha1.c \
					src/sha1.h src/sha1.c
unit_test_prf_sha1_LDADD = ell/libell-internal.la

unit_test_ie_SOURCES = unit/test-ie.c src/ie.h src/ie.c
unit_test_ie_LDADD = ell/libell-internal.la

unit_test_crypto_SOURCES = unit/test-crypto.c \
				src/sha1.h src/sha1.c \
				src/crypto.h src/crypto.c
unit_test_crypto_LDADD = ell/libell-internal.la

unit_test_mpdu_SOURCES = unit/test-mpdu.c \
				src/mpdu.h src/mpdu.c
unit_test_mpdu_LDADD = ell/libell-internal.la

unit_test_eapol_SOURCES = unit/test-eapol.c \
				src/sha1.h src/sha1.c \
				src/crypto.h src/crypto.c \
				src/ie.h src/ie.c \
				src/eapol.h src/eapol.c
unit_test_eapol_LDADD = ell/libell-internal.la

unit_test_ssid_to_utf8_SOURCES = src/util.h src/util.c \
				unit/test-ssid-to-utf8.c
unit_test_ssid_to_utf8_LDADD = ell/libell-internal.la

unit_test_ssid_security_SOURCES = unit/test-ssid-security.c src/ie.h src/ie.c \
				src/scan.h src/scan.c
unit_test_ssid_security_LDADD = ell/libell-internal.la

unit_test_wsc_SOURCES = unit/test-wsc.c src/wsc.h src/wsc.c
unit_test_wsc_LDADD = ell/libell-internal.la

TESTS = $(unit_tests)

manual_pages = doc/iwmon.1

dist_man_MANS = $(manual_pages)

EXTRA_DIST = $(manual_pages:.1=.txt)

AM_CFLAGS = -fvisibility=hidden

MAINTAINERCLEANFILES = Makefile.in configure config.h.in aclocal.m4

DISTCLEANFILES = $(BUILT_SOURCES) $(unit_tests) $(manual_pages)

BUILT_SOURCES = ell/internal

ell/internal: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_sources) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(top_srcdir)/../../ell/$$f ; \
		fi \
	done > $@

%.1: %.txt
	$(AM_V_GEN)$(A2X) --doctype manpage --format manpage $(srcdir)/$<

maintainer-clean-local:
	-rm -rf build-aux ell
