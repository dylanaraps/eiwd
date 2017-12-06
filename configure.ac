AC_PREREQ(2.60)
AC_INIT(iwd, 0.0)

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

AC_ARG_ENABLE(sim_hardcoded, AC_HELP_STRING([--disable-sim-hardcoded],
			[disable hard coded SIM keys]),
			[enable_sim_hardcoded=${enableval}])
AM_CONDITIONAL(SIM_HARDCODED, test "${enable_sim_hardcoded}" != "no")

if (test "${prefix}" = "NONE"); then
	dnl no prefix and no localstatedir, so default to /var
	if (test "$localstatedir" = '${prefix}/var'); then
		AC_SUBST([localstatedir], ['/var'])
	fi

	prefix="${ac_default_prefix}"
fi

if (test "$localstatedir" = '${prefix}/var'); then
	storagedir="${prefix}/var/lib/iwd"
else
	storagedir="${localstatedir}/lib/iwd"
fi

AC_DEFINE_UNQUOTED(STORAGEDIR, "${storagedir}",
			[Directory for the storage files])
AC_DEFINE_UNQUOTED(CONFIGDIR, "/etc/iwd", [Configuration directory])

AC_CHECK_HEADERS(linux/types.h linux/if_alg.h)

AC_CHECK_HEADERS(readline/readline.h, enable_readline=yes,
			AC_MSG_ERROR(readline header files are required))

AC_ARG_WITH([dbusconfdir], AC_HELP_STRING([--with-dbusconfdir=DIR],
				[path to D-Bus configuration directory]),
					[path_dbusconfdir=${withval}])
if (test -z "${path_dbusconfdir}"); then
	AC_MSG_CHECKING([D-Bus configuration directory])
	path_dbusconfdir="`$PKG_CONFIG --variable=sysconfdir dbus-1`"
	if (test -z "${path_dbusconfdir}"); then
		AC_MSG_ERROR([D-Bus configuration directory is required])
	fi
	AC_MSG_RESULT([${path_dbusconfdir}])
fi
AC_SUBST(DBUS_CONFDIR, [${path_dbusconfdir}])

AC_PATH_PROG(A2X, [a2x], [], $PATH:/sbin:/usr/sbin)
AM_CONDITIONAL(BUILD_DOCS, test "$A2X" != "")

AC_CONFIG_FILES(Makefile)

AC_OUTPUT

AC_MSG_RESULT([
	$PACKAGE_NAME $VERSION
])
