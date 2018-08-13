
AM_MAKEFLAGS = --no-print-directory

ACLOCAL_AMFLAGS = -I build-aux

builtin_modules =
builtin_sources =

noinst_LTLIBRARIES = ell/libell-internal.la

if DBUS_POLICY
dbus_datadir = @DBUS_DATADIR@/dbus-1/system.d
dist_dbus_data_DATA = src/iwd-dbus.conf
endif

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
			ell/dbus-util.c \
			ell/dbus-message.c \
			ell/dbus-service.h ell/dbus-service.c \
			ell/dbus-filter.c \
			ell/dbus-name-cache.c \
			ell/gvariant-private.h \
			ell/gvariant-util.c \
			ell/siphash-private.h \
			ell/siphash.c \
			ell/hwdb.h ell/hwdb.c \
			ell/cipher.h ell/cipher.c \
			ell/random.h ell/random.c \
			ell/uintset.h ell/uintset.c \
			ell/base64.h ell/base64.c \
			ell/pem.h ell/pem.c \
			ell/tls-private.h \
			ell/tls.h ell/tls.c \
			ell/tls-record.c \
			ell/uuid.h ell/uuid.c \
			ell/key.h ell/key.c \
			ell/key-private.h \
			ell/asn1-private.h \
			ell/pkcs5.h ell/pkcs5.c \
			ell/pkcs5-private.h \
			ell/file.h ell/file.c \
			ell/dbus-client.h ell/dbus-client.c \
			ell/net.h ell/net.c \
			ell/dhcp.h ell/dhcp.c ell/dhcp-transport.c \
			ell/dhcp-private.h ell/dhcp-lease.c \
			ell/fswatch.h ell/fswatch.c

ell_libell_internal_la_SOURCES = $(ell_sources)

bin_PROGRAMS =

libexec_PROGRAMS = src/iwd

src_iwd_SOURCES = src/main.c linux/nl80211.h \
					src/netdev.h src/netdev.c \
					src/wiphy.h src/wiphy.c \
					src/device.h src/device.c \
					src/ie.h src/ie.c \
					src/dbus.h src/dbus.c \
					src/crypto.h src/crypto.c \
					src/mpdu.h src/mpdu.c \
					src/eapol.h src/eapol.c \
					src/handshake.h src/handshake.c \
					src/scan.h src/scan.c \
					src/util.h src/util.c \
					src/common.h src/common.c \
					src/agent.h src/agent.c \
					src/storage.h src/storage.c \
					src/network.h src/network.c \
					src/wscutil.h src/wscutil.c \
					src/wsc.c \
					src/eap-wsc.h src/eap-wsc.c \
					src/eap.h src/eap.c src/eap-private.h \
					src/eap-md5.c \
					src/eap-tls.c src/eap-ttls.c \
					src/eap-mschapv2.c src/eap-mschapv2.h \
					src/backtrace.h src/backtrace.c \
					src/knownnetworks.h \
					src/knownnetworks.c \
					src/rfkill.h src/rfkill.c \
					src/watchlist.h src/watchlist.c \
					src/ftutil.h src/ftutil.c \
					src/iwd.h src/eap-sim.c src/eap-aka.c \
					src/simutil.h src/simutil.c \
					src/ap.h src/ap.c \
					src/simauth.h src/simauth.c \
					src/plugin.h src/plugin.c \
					src/eap-peap.c \
					src/eap-gtc.c \
					src/eap-pwd.c \
					src/ecc.h src/ecc.c \
					src/adhoc.h src/adhoc.c \
					src/sae.h src/sae.c \
					$(builtin_sources)

src_iwd_LDADD = ell/libell-internal.la -ldl

src_iwd_DEPENDENCIES = ell/libell-internal.la

if SYSTEMD_SERVICE
src_iwd_DEPENDENCIES += src/iwd.service

systemd_unitdir = @SYSTEMD_UNITDIR@
systemd_unit_DATA = src/iwd.service

dbus_busdir = @DBUS_BUSDIR@
dbus_bus_DATA = src/net.connman.iwd.service
endif

if CLIENT
bin_PROGRAMS += client/iwctl

client_iwctl_SOURCES = client/main.c \
			client/adapter.c \
			client/agent.h client/agent.c \
			client/agent-manager.h client/agent-manager.c \
			client/ad-hoc.c \
			client/ap.c \
			client/command.h client/command.c \
			client/dbus-proxy.h client/dbus-proxy.c \
			client/device.h client/device.c \
			client/display.h client/display.c \
			client/known-networks.c \
			client/network.h client/network.c \
			client/properties.h client/properties.c \
			client/wsc.c
client_iwctl_LDADD = ell/libell-internal.la -lreadline
endif

if MONITOR
bin_PROGRAMS += monitor/iwmon

monitor_iwmon_SOURCES = monitor/main.c linux/nl80211.h \
					monitor/nlmon.h monitor/nlmon.c \
					monitor/pcap.h monitor/pcap.c \
					monitor/display.h monitor/display.c \
					src/ie.h src/ie.c \
					src/wscutil.h src/wscutil.c \
					src/mpdu.h src/mpdu.c \
					src/util.h src/util.c \
					src/crypto.h src/crypto.c \
					src/watchlist.h src/watchlist.c \
					src/eapol.h src/eapol.c \
					src/handshake.h src/handshake.c \
					src/eap.h src/eap.c src/eap-private.h \
					src/eap-tls.c src/eap-ttls.c
monitor_iwmon_LDADD = ell/libell-internal.la
endif

noinst_PROGRAMS = tools/hwsim
noinst_PROGRAMS += tools/test-runner

tools_hwsim_SOURCES = tools/hwsim.c src/mpdu.h \
					src/util.h src/util.c \
					src/storage.h src/storage.c \
					src/common.h src/common.c
tools_hwsim_LDADD = ell/libell-internal.la
tools_test_runner_LDADD = ell/libell-internal.la

if SIM_HARDCODED
builtin_modules += sim_hardcoded
builtin_sources += plugins/sim_hardcoded.c
endif

if OFONO
builtin_modules += ofono
builtin_sources += plugins/ofono.c
endif

unit_tests = unit/test-cmac-aes \
		unit/test-hmac-md5 unit/test-hmac-sha1 unit/test-hmac-sha256 \
		unit/test-prf-sha1 unit/test-kdf-sha256 \
		unit/test-crypto unit/test-eapol unit/test-mpdu \
		unit/test-ie unit/test-ssid-to-utf8 unit/test-ssid-security \
		unit/test-arc4 unit/test-wsc unit/test-eap-mschapv2 \
		unit/test-eap-sim unit/test-client unit/test-ecc


ell_pem_files = cert-ca-key.pem cert-client-key.pem cert-client-key-pkcs8.pem \
		cert-server-key.pem cert-server-key-pkcs8.pem \
		cert-ca.pem cert-client.pem cert-server.pem

if MAINTAINER_MODE
noinst_PROGRAMS += $(unit_tests)
noinst_DATA = ell/unit/test_data
endif

unit_test_eap_sim_SOURCES = unit/test-eap-sim.c \
		src/crypto.h src/crypto.c src/simutil.h src/simutil.c \
		src/ie.h src/ie.c \
		src/watchlist.h src/watchlist.c \
		src/eapol.h src/eapol.c \
		src/handshake.h src/handshake.c \
		src/eap.h src/eap.c src/eap-private.h \
		src/util.h src/util.c \
		src/simauth.h src/simauth.c \
		src/eap-sim.c

unit_test_eap_sim_LDADD = ell/libell-internal.la

unit_test_cmac_aes_SOURCES = unit/test-cmac-aes.c \
					src/crypto.h src/crypto.c
unit_test_cmac_aes_LDADD = ell/libell-internal.la

unit_test_arc4_SOURCES = unit/test-arc4.c \
					src/crypto.h src/crypto.c

unit_test_arc4_LDADD = ell/libell-internal.la

unit_test_hmac_md5_SOURCES = unit/test-hmac-md5.c \
					src/crypto.h src/crypto.c
unit_test_hmac_md5_LDADD = ell/libell-internal.la

unit_test_hmac_sha1_SOURCES = unit/test-hmac-sha1.c \
					src/crypto.h src/crypto.c
unit_test_hmac_sha1_LDADD = ell/libell-internal.la

unit_test_hmac_sha256_SOURCES = unit/test-hmac-sha256.c \
					src/crypto.h src/crypto.c
unit_test_hmac_sha256_LDADD = ell/libell-internal.la

unit_test_prf_sha1_SOURCES = unit/test-prf-sha1.c \
					src/crypto.h src/crypto.c
unit_test_prf_sha1_LDADD = ell/libell-internal.la

unit_test_kdf_sha256_SOURCES = unit/test-kdf-sha256.c \
					src/crypto.h src/crypto.c
unit_test_kdf_sha256_LDADD = ell/libell-internal.la

unit_test_ie_SOURCES = unit/test-ie.c src/ie.h src/ie.c
unit_test_ie_LDADD = ell/libell-internal.la

unit_test_crypto_SOURCES = unit/test-crypto.c \
				src/crypto.h src/crypto.c
unit_test_crypto_LDADD = ell/libell-internal.la

unit_test_mpdu_SOURCES = unit/test-mpdu.c \
				src/mpdu.h src/mpdu.c \
				src/ie.h src/ie.c
unit_test_mpdu_LDADD = ell/libell-internal.la

unit_test_eapol_SOURCES = unit/test-eapol.c \
				src/crypto.h src/crypto.c \
				src/ie.h src/ie.c \
				src/watchlist.h src/watchlist.c \
				src/eapol.h src/eapol.c \
				src/handshake.h src/handshake.c \
				src/eap.h src/eap.c src/eap-private.h \
				src/eap-tls.c src/eap-ttls.c \
				src/eap-md5.c src/util.c
unit_test_eapol_LDADD = ell/libell-internal.la

unit_test_ssid_to_utf8_SOURCES = src/util.h src/util.c \
				unit/test-ssid-to-utf8.c
unit_test_ssid_to_utf8_LDADD = ell/libell-internal.la

unit_test_ssid_security_SOURCES = unit/test-ssid-security.c src/ie.h src/ie.c \
				src/common.h src/common.c
unit_test_ssid_security_LDADD = ell/libell-internal.la

unit_test_wsc_SOURCES = unit/test-wsc.c src/wscutil.h src/wscutil.c \
				src/crypto.h src/crypto.c \
				src/ie.h src/ie.c \
				src/watchlist.h src/watchlist.c \
				src/eapol.h src/eapol.c \
				src/handshake.h src/handshake.c \
				src/eap.h src/eap.c src/eap-private.h \
				src/util.h src/util.c \
				src/eap-wsc.h src/eap-wsc.c
unit_test_wsc_LDADD = ell/libell-internal.la

unit_test_eap_mschapv2_SOURCES = src/eap-mschapv2.h src/eap-mschapv2.c \
				src/eap.c src/eap.h src/eap-private.h \
				unit/test-eap-mschapv2.c

unit_test_eap_mschapv2_LDADD = ell/libell-internal.la

unit_test_client_SOURCES = unit/test-client.c \
				client/adapter.c \
				client/agent.h client/agent.c \
				client/agent-manager.h client/agent-manager.c \
				client/command.h client/command.c \
				client/dbus-proxy.h client/dbus-proxy.c \
				client/display.h client/display.c \
				client/network.h client/network.c \
				client/properties.h client/properties.c
unit_test_client_LDADD = ell/libell-internal.la -lreadline

unit_test_ecc_SOURCES = unit/test-ecc.c src/ecc.c src/ecc.h
unit_test_ecc_LDADD = ell/libell-internal.la

TESTS = $(unit_tests)

manual_pages = doc/iwmon.1

if BUILD_DOCS
dist_man_MANS = $(manual_pages)
endif

EXTRA_DIST = src/genbuiltin src/iwd.service.in src/net.connman.iwd.service \
			doc/main.conf $(manual_pages:.1=.txt)

AM_CFLAGS = -fvisibility=hidden

CLEANFILES = src/iwd.service

DISTCHECK_CONFIGURE_FLAGS = --disable-dbus-policy --disable-systemd-service

DISTCLEANFILES = $(BUILT_SOURCES) $(unit_tests) $(manual_pages)

MAINTAINERCLEANFILES = Makefile.in configure config.h.in aclocal.m4

BUILT_SOURCES = ell/internal src/builtin.h

ell/internal: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_sources) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(abs_srcdir)/../ell/$$f ; \
		fi \
	done > $@
	$(AM_V_at)$(MKDIR_P) linux
	$(AM_V_GEN)for f in $(ell_linux_headers) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t linux -f $(abs_srcdir)/../ell/$$f ; \
		fi \
	done > $@

ell/unit/test_data: Makefile
	$(AM_V_at)$(MKDIR_P) ell/unit
	$(AM_V_GEN)for f in $(ell_pem_files) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell/unit -f $(abs_srcdir)/../ell/unit/$$f ; \
		fi \
	done > $@

SED_PROCESS = $(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
		$(SED) -e 's,@libexecdir\@,$(libexecdir),g' \
		< $< > $@

%.service: %.service.in Makefile
	$(SED_PROCESS)

%.1: %.txt
	$(AM_V_GEN)$(A2X) --doctype manpage --format manpage $(srcdir)/$<

maintainer-clean-local:
	-rm -rf build-aux ell

src/builtin.h: src/genbuiltin config.status
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@
