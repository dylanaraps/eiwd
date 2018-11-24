/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/wiphy.h"
#include "src/dbus.h"
#include "src/eap.h"
#include "src/eapol.h"
#include "src/scan.h"
#include "src/rfkill.h"
#include "src/ap.h"
#include "src/plugin.h"
#include "src/simauth.h"
#include "src/adhoc.h"

#include "src/backtrace.h"

static struct l_genl *genl;
static struct l_genl_family *nl80211;
static struct l_settings *iwd_config;
static struct l_timeout *timeout;
static const char *interfaces;
static const char *nointerfaces;
static const char *phys;
static const char *nophys;
static const char *config_dir;
static const char *plugins;
static const char *noplugins;
static const char *debugopt;
static bool terminating;

static void main_loop_quit(struct l_timeout *timeout, void *user_data)
{
	l_main_quit();
}

static void iwd_shutdown(void)
{
	if (terminating)
		return;

	terminating = true;

	if (!nl80211) {
		l_main_quit();
		return;
	}

	dbus_shutdown();
	netdev_shutdown();

	timeout = l_timeout_create(1, main_loop_quit, NULL, NULL);
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		iwd_shutdown();
		break;
	}
}

const struct l_settings *iwd_get_config(void)
{
	return iwd_config;
}

static void usage(void)
{
	printf("iwd - Wireless daemon\n"
		"Usage:\n");
	printf("\tiwd [options]\n");
	printf("Options:\n"
		"\t-B, --dbus-debug       Enable D-Bus debugging\n"
		"\t-i, --interfaces       Interfaces to manage\n"
		"\t-I, --nointerfaces     Interfaces to ignore\n"
		"\t-p, --phys             Phys to manage\n"
		"\t-P, --nophys           Phys to ignore\n"
		"\t-c, --config           Configuration directory to use\n"
		"\t-l, --plugin           Plugins to include\n"
		"\t-L, --noplugin         Plugins to exclude\n"
		"\t-d, --debug            Enable debug output\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "dbus-debug",   no_argument,       NULL, 'B' },
	{ "version",      no_argument,       NULL, 'v' },
	{ "interfaces",   required_argument, NULL, 'i' },
	{ "nointerfaces", required_argument, NULL, 'I' },
	{ "phys",         required_argument, NULL, 'p' },
	{ "nophys",       required_argument, NULL, 'P' },
	{ "config",       required_argument, NULL, 'c' },
	{ "plugin",       required_argument, NULL, 'l' },
	{ "noplugin",     required_argument, NULL, 'L' },
	{ "debug",        optional_argument, NULL, 'd' },
	{ "help",         no_argument,       NULL, 'h' },
	{ }
};

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void nl80211_appeared(void *user_data)
{
	struct l_genl_family *nl80211 = user_data;

	if (terminating)
		return;

	l_debug("Found nl80211 interface");

	if (!wiphy_init(nl80211, phys, nophys))
		l_error("Unable to init wiphy functionality");

	netdev_set_nl80211(nl80211);

	if (!scan_init(nl80211))
		l_error("Unable to init scan functionality");

	ap_init(nl80211);
	adhoc_init(nl80211);
}

static void nl80211_vanished(void *user_data)
{
	l_debug("Lost nl80211 interface");

	ap_exit();
	adhoc_exit();
	scan_exit();
	wiphy_exit();
}

static void request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	if (!success) {
		l_error("Name request failed");
		goto fail_exit;
	}

	if (!l_dbus_object_manager_enable(dbus))
		l_warn("Unable to register the ObjectManager");

	genl = l_genl_new_default();
	if (!genl) {
		l_error("Failed to open generic netlink socket");
		goto fail_exit;
	}

	if (getenv("IWD_GENL_DEBUG"))
		l_genl_set_debug(genl, do_debug, "[GENL] ", NULL);

	nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);
	if (!nl80211) {
		l_error("Failed to open nl80211 interface");
		goto fail_exit;
	}

	l_genl_family_set_watches(nl80211, nl80211_appeared, nl80211_vanished,
								nl80211, NULL);
	return;

fail_exit:
	l_main_quit();
}

static void dbus_ready(void *user_data)
{
	struct l_dbus *dbus = user_data;

	l_dbus_name_acquire(dbus, "net.connman.iwd", false, false, true,
				request_name_callback, NULL);
}

static void dbus_disconnected(void *user_data)
{
	l_info("D-Bus disconnected, quitting...");
	iwd_shutdown();
}

static void print_koption(const void *key, void *value, void *user_data)
{
	l_info("\t%s", (const char *) key);
}

static int check_crypto()
{
	int r = 0;
	struct l_hashmap *options = l_hashmap_string_new();
	struct l_hashmap *optional = l_hashmap_string_new();

	if (!l_checksum_is_supported(L_CHECKSUM_SHA1, true)) {
		r = -ENOTSUP;
		l_error("No HMAC(SHA1) support found");
		l_hashmap_insert(options, "CONFIG_CRYPTO_USER_API_HASH", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_SHA1", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_HMAC", &r);
		l_hashmap_insert(optional, "CONFIG_CRYPTO_SHA1_SSSE3", &r);
	}

	if (!l_checksum_is_supported(L_CHECKSUM_MD5, true)) {
		r = -ENOTSUP;
		l_error("No HMAC(MD5) support found");
		l_hashmap_insert(options, "CONFIG_CRYPTO_USER_API_HASH", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_MD5", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_HMAC", &r);
	}

	if (!l_checksum_cmac_aes_supported()) {
		r = -ENOTSUP;
		l_error("No CMAC(AES) support found");
		l_hashmap_insert(options, "CONFIG_CRYPTO_USER_API_HASH", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_AES", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_CMAC", &r);
		l_hashmap_insert(optional, "CONFIG_CRYPTO_AES_X86_64", &r);
		l_hashmap_insert(optional, "CONFIG_CRYPTO_AES_NI_INTEL", &r);
	}

	if (!l_checksum_is_supported(L_CHECKSUM_SHA256, true)) {
		r = -ENOTSUP;
		l_error("No HMAC(SHA256) support not found");
		l_hashmap_insert(options, "CONFIG_CRYPTO_USER_API_HASH", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_HMAC", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_SHA256", &r);
		l_hashmap_insert(optional, "CONFIG_CRYPTO_SHA256_SSSE3", &r);
	}

	if (!l_checksum_is_supported(L_CHECKSUM_SHA512, true)) {
		l_warn("No HMAC(SHA512) support found, "
				"certain TLS connections might fail");
		l_hashmap_insert(options, "CONFIG_CRYPTO_SHA512", &r);
		l_hashmap_insert(optional, "CONFIG_CRYPTO_SHA512_SSSE3", &r);
	}

	if (!l_cipher_is_supported(L_CIPHER_ARC4)) {
		r = -ENOTSUP;
		l_error("RC4 support not found");
		l_hashmap_insert(options,
				"CONFIG_CRYPTO_USER_API_SKCIPHER", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_ARC4", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_ECB", &r);
	}

	if (!l_cipher_is_supported(L_CIPHER_DES) ||
			!l_cipher_is_supported(L_CIPHER_DES3_EDE_CBC)) {
		r = -ENOTSUP;
		l_error("DES support not found");
		l_hashmap_insert(options,
				"CONFIG_CRYPTO_USER_API_SKCIPHER", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_DES", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_ECB", &r);
		l_hashmap_insert(optional, "CONFIG_CRYPTO_DES3_EDE_X86_64", &r);
	}

	if (!l_cipher_is_supported(L_CIPHER_AES)) {
		r = -ENOTSUP;
		l_error("AES support not found");
		l_hashmap_insert(options,
				"CONFIG_CRYPTO_USER_API_SKCIPHER", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_AES", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_ECB", &r);
		l_hashmap_insert(optional, "CONFIG_CRYPTO_AES_X86_64", &r);
		l_hashmap_insert(optional, "CONFIG_CRYPTO_AES_NI_INTEL", &r);
	}

	if (!l_cipher_is_supported(L_CIPHER_DES3_EDE_CBC)) {
		l_warn("No CBC(DES3_EDE) support found, "
				"certain TLS connections might fail");
		l_hashmap_insert(options, "CONFIG_CRYPTO_DES", &r);
		l_hashmap_insert(options, "CONFIG_CRYPTO_CBC", &r);
		l_hashmap_insert(optional, "CONFIG_CRYPTO_DES3_EDE_X86_64", &r);
	}

	if (!l_cipher_is_supported(L_CIPHER_AES_CBC)) {
		l_warn("No CBC(AES) support found, "
				"WPS will not be available");
		l_hashmap_insert(options, "CONFIG_CRYPTO_CBC", &r);
	}

	if (!l_key_is_supported(L_KEY_FEATURE_DH)) {
		l_warn("No Diffie-Hellman support found, "
				"WPS will not be available");
		l_hashmap_insert(options, "CONFIG_KEY_DH_OPERATIONS", &r);
	}

	if (!l_key_is_supported(L_KEY_FEATURE_RESTRICT)) {
		l_warn("No keyring restrictions support found.");
		l_hashmap_insert(options, "CONFIG_KEYS", &r);
	}

	if (!l_key_is_supported(L_KEY_FEATURE_CRYPTO)) {
		l_warn("No asymmetric key support found.");
		l_warn("TLS based WPA-Enterprise authentication methods will"
				" not function.");
		l_warn("Kernel 4.20+ is required for this feature.");
		l_hashmap_insert(options, "CONFIG_ASYMMETRIC_KEY_TYPE", &r);
		l_hashmap_insert(options,
				"CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE", &r);
		l_hashmap_insert(options, "CONFIG_X509_CERTIFICATE_PARSER", &r);
		l_hashmap_insert(options, "CONFIG_PKCS7_MESSAGE_PARSER", &r);
		l_hashmap_insert(options,
					"CONFIG_PKCS8_PRIVATE_KEY_PARSER", &r);
	};

	if (l_hashmap_isempty(options))
		goto done;

	l_info("The following options are missing in the kernel:");

	if (l_hashmap_remove(options, "CONFIG_CRYPTO_USER_API_HASH"))
		l_info("\tCONFIG_CRYPTO_USER_API_HASH");

	if (l_hashmap_remove(options, "CONFIG_CRYPTO_USER_API_SKCIPHER"))
		l_info("\tCONFIG_CRYPTO_USER_API_SKCIPHER");

	l_hashmap_foreach(options, print_koption, NULL);

	if (!l_hashmap_isempty(optional)) {
		l_info("The following optimized implementations might be "
			"available:");
		l_hashmap_foreach(optional, print_koption, NULL);
	}

done:
	l_hashmap_destroy(options, NULL);
	l_hashmap_destroy(optional, NULL);

	return r;
}

int main(int argc, char *argv[])
{
	bool enable_dbus_debug = false;
	int exit_status;
	struct l_dbus *dbus;
	char *config_path;
	uint32_t eap_mtu;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "Bi:I:p:P:c:d::vh",
							main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'B':
			enable_dbus_debug = true;
			break;
		case 'i':
			interfaces = optarg;
			break;
		case 'I':
			nointerfaces = optarg;
			break;
		case 'p':
			phys = optarg;
			break;
		case 'P':
			nophys = optarg;
			break;
		case 'c':
			config_dir = optarg;
			break;
		case 'l':
			plugins = optarg;
			break;
		case 'L':
			noplugins = optarg;
			break;
		case 'd':
			if (optarg)
				debugopt = optarg;
			else if (argv[optind] && argv[optind][0] != '-')
				debugopt = argv[optind++];
			else
				debugopt = "*";
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	l_log_set_stderr();

	if (check_crypto() < 0)
		return EXIT_FAILURE;

	if (!l_main_init())
		return EXIT_FAILURE;

	if (debugopt)
		l_debug_enable(debugopt);

#ifdef HAVE_BACKTRACE
	__iwd_backtrace_init();
#endif

	l_info("Wireless daemon version %s", VERSION);

	if (!config_dir)
		config_dir = DAEMON_CONFIGDIR;

	config_path = l_strdup_printf("%s/%s", config_dir, "main.conf");
	iwd_config = l_settings_new();

	if (!l_settings_load_from_file(iwd_config, config_path))
		l_warn("Skipping optional configuration file %s", config_path);

	l_free(config_path);

	__eapol_set_config(iwd_config);

	if (!l_settings_get_uint(iwd_config, "EAP", "mtu", &eap_mtu))
		eap_mtu = 1400; /* on WiFi the real MTU is around 2304 */

	exit_status = EXIT_FAILURE;

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	if (!dbus) {
		l_error("Failed to initialize D-Bus");
		goto fail_dbus;
	}

	if (enable_dbus_debug)
		l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);

	l_dbus_set_ready_handler(dbus, dbus_ready, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, dbus_disconnected, NULL, NULL);
	dbus_init(dbus);

	eap_init(eap_mtu);
	eapol_init();
	rfkill_init();

	if (!netdev_init(interfaces, nointerfaces))
		goto fail_netdev;

	if (!device_init())
		goto fail_device;

	station_init();
	wsc_init();
	network_init();
	known_networks_init();
	sim_auth_init();
	plugin_init(plugins, noplugins);

	exit_status = l_main_run_with_signal(signal_handler, NULL);

	plugin_exit();
	sim_auth_exit();
	known_networks_exit();
	network_exit();
	wsc_exit();
	station_exit();
	device_exit();
fail_device:
	netdev_exit();
fail_netdev:
	rfkill_exit();
	eapol_exit();
	eap_exit();

	l_genl_family_unref(nl80211);
	l_genl_unref(genl);
	dbus_exit();
	l_dbus_destroy(dbus);
fail_dbus:
	l_settings_free(iwd_config);

	l_timeout_remove(timeout);

	l_main_exit();

	return exit_status;
}
