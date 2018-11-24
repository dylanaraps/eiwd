AC_PREREQ(2.60)
AC_INIT(iwd, 0.12)

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(build-aux)

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests silent-rules
					tar-pax no-dist-gzip dist-xz])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

PKG_PROG_PKG_CONFIG

COMPILER_FLAGS

AC_LANG_C

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_LN_S

LT_PREREQ(2.2)
LT_INIT([disable-static])

AC_ARG_ENABLE(optimization, AC_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -O0"
	fi
])

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

AC_ARG_ENABLE(pie, AC_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi
])

if (test "${prefix}" = "NONE"); then
	dnl no prefix and no localstatedir, so default to /var
	if (test "$localstatedir" = '${prefix}/var'); then
		AC_SUBST([localstatedir], ['/var'])
	fi

	prefix="${ac_default_prefix}"
fi

if (test "$localstatedir" = '${prefix}/var'); then
	daemon_storagedir="${prefix}/var/lib/iwd"
	wired_storagedir="${prefix}/var/lib/ead"
else
	daemon_storagedir="${localstatedir}/lib/iwd"
	wired_storagedir="${localstatedir}/lib/ead"
fi

AC_DEFINE_UNQUOTED(DAEMON_STORAGEDIR, "${daemon_storagedir}",
			[Directory for Wireless daemon storage files])
AC_DEFINE_UNQUOTED(DAEMON_CONFIGDIR, "/etc/iwd",
			[Directory for Wireless daemon configuration])

AC_DEFINE_UNQUOTED(WIRED_STORAGEDIR, "${wired_storagedir}",
			[Directory for Ethernet daemon storage files])

AC_CHECK_HEADERS(linux/types.h linux/if_alg.h)

# In maintainer mode: try to build with application backtrace and disable PIE.
if (test "${USE_MAINTAINER_MODE}" = yes); then
	AC_SEARCH_LIBS([backtrace], [execinfo],
		[
			AC_DEFINE([HAVE_BACKTRACE], [1],
				[Define to 1 if you have backtrace(3).])
			CFLAGS="$CFLAGS -fno-PIE"
			LDFLAGS="$LDFLAGS -no-pie"
		])
fi

AC_ARG_ENABLE([daemon], AC_HELP_STRING([--disable-daemon],
				[don't install iwd system daemon]),
					[enable_daemon=${enableval}])
AM_CONDITIONAL(DAEMON, test "${enable_daemon}" != "no")

AC_ARG_ENABLE([client], AC_HELP_STRING([--disable-client],
				[don't install iwctl client utility]),
					[enable_client=${enableval}])
AM_CONDITIONAL(CLIENT, test "${enable_client}" != "no")
if (test "${enable_client}" != "no"); then
	AC_CHECK_HEADERS(readline/readline.h, enable_readline=yes,
			AC_MSG_ERROR(readline header files are required))
fi
AM_CONDITIONAL(CLIENT, test "${enable_client}" != "no")

AC_ARG_ENABLE([monitor], AC_HELP_STRING([--disable-monitor],
				[don't install iwmon monitor utility]),
					[enable_monitor=${enableval}])
AM_CONDITIONAL(MONITOR, test "${enable_monitor}" != "no")

AC_ARG_ENABLE([dbus-policy], AC_HELP_STRING([--disable-dbus-policy],
				[don't install D-Bus system policy files]),
					[enable_dbus_policy=${enableval}])
AM_CONDITIONAL(DBUS_POLICY, test "${enable_dbus_policy}" != "no")

AC_ARG_WITH([dbus-datadir], AC_HELP_STRING([--with-dbus-datadir=DIR],
				[path to D-Bus data directory]),
					[path_dbus_datadir=${withval}])
if (test "${enable_dbus_policy}" != "no" && test -z "${path_dbus_datadir}"); then
	AC_MSG_CHECKING([D-Bus data directory])
	path_dbus_datadir="`$PKG_CONFIG --variable=datadir dbus-1`"
	if (test -z "${path_dbus_datadir}"); then
		path_dbus_datadir="`$PKG_CONFIG --variable=sysconfdir dbus-1`"
		if (test -z "${path_dbus_datadir}"); then
			AC_MSG_ERROR([D-Bus data directory is required])
		fi
	fi
	AC_MSG_RESULT([${path_dbus_datadir}])
fi
AC_SUBST(DBUS_DATADIR, [${path_dbus_datadir}])

AC_ARG_ENABLE([systemd-service], AC_HELP_STRING([--disable-systemd-service],
				[don't install systemd service files]),
					[enable_systemd_service=${enableval}])
AM_CONDITIONAL(SYSTEMD_SERVICE, test "${enable_systemd_service}" != "no")

AC_ARG_WITH([dbus-busdir], AC_HELP_STRING([--with-dbus-busdir=DIR],
				[path to D-Bus bus services directory]),
					[path_dbus_busdir=${withval}])
if (test "${enable_systemd_service}" != "no" && test -z "${path_dbus_busdir}"); then
	AC_MSG_CHECKING([D-Bus bus services directory])
	path_dbus_busdir="`$PKG_CONFIG --variable=system_bus_services_dir dbus-1`"
	if (test -z "${path_dbus_busdir}"); then
		AC_MSG_ERROR([D-Bus bus services directory is required])
	fi
	AC_MSG_RESULT([${path_dbus_busdir}])
fi
AC_SUBST(DBUS_BUSDIR, [${path_dbus_busdir}])

AC_ARG_WITH([systemd-unitdir], AC_HELP_STRING([--with-systemd-unitdir=DIR],
				[path to systemd unit directory]),
					[path_systemd_unitdir=${withval}])
if (test "${enable_systemd_service}" != "no" && test -z "${path_systemd_unitdir}"); then
	AC_MSG_CHECKING([systemd unit directory])
	path_systemd_unitdir="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"
	if (test -z "${path_systemd_unitdir}"); then
		AC_MSG_ERROR([systemd unit directory is required])
	fi
	AC_MSG_RESULT([${path_systemd_unitdir}])
fi
AC_SUBST(SYSTEMD_UNITDIR, [${path_systemd_unitdir}])

AC_ARG_ENABLE([external_ell], AC_HELP_STRING([--enable-external-ell],
				[enable external Embedded Linux library]),
					[enable_external_ell=${enableval}])
if (test "${enable_external_ell}" = "yes"); then
	if (test "${enable_daemon}" != "no" ||
			test "${enable_client}" != "no" ||
			test "${enable_monitor}" != "no" ||
			test "${enable_wired}" = "yes" ||
			test "${enable_hwsim}" = "yes"); then
		ell_min_version="0.15"
	else
		ell_min_version="0.5"
	fi
	PKG_CHECK_MODULES(ELL, ell >= ${ell_min_version}, dummy=yes,
		AC_MSG_ERROR(Embedded Linux library >= ${ell_min_version} is required))
	AC_SUBST(ELL_CFLAGS)
	AC_SUBST(ELL_LIBS)
fi
AM_CONDITIONAL(EXTERNAL_ELL, test "${enable_external_ell}" = "yes")

AC_ARG_ENABLE([sim_hardcoded], AC_HELP_STRING([--enable-sim-hardcoded],
				[enable hard coded SIM keys]),
					[enable_sim_hardcoded=${enableval}])
AM_CONDITIONAL(SIM_HARDCODED, test "${enable_sim_hardcoded}" = "yes")

AC_ARG_ENABLE([ofono], AC_HELP_STRING([--enable-ofono],
				[enable oFono SIM authentication support]),
					[enable_ofono=${enableval}])
AM_CONDITIONAL(OFONO, test "${enable_ofono}" = "yes")

AC_ARG_ENABLE([wired], AC_HELP_STRING([--enable-wired],
				[enable Ethernet authentication support]),
					[enable_wired=${enableval}])
AM_CONDITIONAL(WIRED, test "${enable_wired}" = "yes")

AC_ARG_ENABLE([hwsim], AC_HELP_STRING([--enable-hwsim],
				[enable Wireless simulation utility]),
					[enable_hwsim=${enableval}])
AM_CONDITIONAL(HWSIM, test "${enable_hwsim}" = "yes")

AC_ARG_ENABLE([tools], AC_HELP_STRING([--enable-tools],
				[enable internal testing utilities]),
					[enable_tools=${enableval}])
AM_CONDITIONAL(TOOLS, test "${enable_tools}" = "yes")

AC_ARG_ENABLE([docs], AC_HELP_STRING([--enable-docs],
				[build documentation and manual pages]),
					[enable_docs=${enableval}])
if (test "${enable_docs}" = "yes"); then
	AC_PATH_PROG(A2X, [a2x], [], $PATH:/sbin:/usr/sbin)
fi
AM_CONDITIONAL(BUILD_DOCS, test "$A2X" != "")

AC_CONFIG_FILES(Makefile)

AC_OUTPUT

AC_MSG_RESULT([
	$PACKAGE_NAME $VERSION
])
