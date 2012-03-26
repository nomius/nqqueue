dnl vim: set sw=8 sts=8 noet :

AC_INIT([NQqueue], [0.3])
AC_PREREQ(2.5)
AM_INIT_AUTOMAKE(1.9)
AM_PROG_LIBTOOL
LIBTOOL="$LIBTOOL --silent"
AC_PROG_CC
AC_CONFIG_HEADER(config.h)
AC_PROG_CC_C_O
# check for required programs
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB
AC_PROG_MAKE_SET
AC_TYPE_SIZE_T
AC_TYPE_PID_T
AC_C_BIGENDIAN
AC_C_INLINE
AC_CHECK_SIZEOF(int, 32)
NQQUEUE_HOME="/var/qmail/nqqueue"
QMAILDUID=`stat -c "%U" /var/qmail/bin/qmail-queue`
NOFILESGID=`stat -c "%G" /var/qmail/bin/qmail-queue`
AC_DEFINE_UNQUOTED([NQQUEUE_HOME], "${NQQUEUE_HOME}", [Do not change this])
AC_DEFINE_UNQUOTED([NQQUEUE_WORKDIR], "${NQQUEUE_HOME}/queue", [Do not change this either])
AC_DEFINE([CONTROLDIR], ["/var/qmail/control"], [Do not change this])
AC_DEFINE([QMAILQUEUE], ["/var/qmail/bin/qmail-queue"], [Full path to qmail-queue])

AC_SUBST(NQQUEUE_HOME)
AC_SUBST(QMAILDUID)
AC_SUBST(NOFILESGID)

LIBS=""
case "$host_os" in
	*darwin* | *rhapsody* | *macosx*)
		AC_DEFINE_UNQUOTED(OSX,1,[This is an OS X system])
		build_target="macosx"
		;;
	linux*)
		AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
		build_target="linux"
		LIBS="-ldl"
		;;
	freebsd*)
		AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
		AC_DEFINE_UNQUOTED(FREEBSD,1,[This is a FreeBSD system])
		build_target="freebsd"
		;;
	openbsd*)
		AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
		AC_DEFINE_UNQUOTED(OPENBSD,1,[This is an OpenBSD system])
		build_target="openbsd"
		;;
	netbsd*)
		AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
		AC_DEFINE_UNQUOTED(NETBSD,1,[This is a NetBSD system])
		build_target="netbsd"
		;;
	*solaris*)
		AC_DEFINE_UNQUOTED(SOLARIS,1,[This is a Solaris system])
		AC_DEFINE_UNQUOTED(_REENTRANT,1,[Need with solaris or errno doesnt work])
		build_target="solaris"
		;;
	*)
		AC_MSG_RESULT(Unrecognised OS $host_os)
		AC_DEFINE_UNQUOTED(OTHEROS,1,[Some strange OS])
		;;
esac

LIBS="-lpthread $LIBS"
AC_SUBST(LIBS)

##############################################################################

AC_ARG_ENABLE([dspam], [  --enable-dspam=yes|no        build dspam plugin. default yes.], [BUILD_DSPAM="$enableval"], [BUILD_DSPAM=yes])
case $BUILD_DSPAM in
	no)
        BUILD_DSPAM=no
	;;
	*)
		BUILD_DSPAM=yes
		AC_MSG_CHECKING([whether we can locate the dspam program])
		dspam=`which dspam 2>/dev/null`
		if test "x$dspam" = "x"; then
			echo
			AC_MSG_ERROR([Could not find dspam in PATH. use --enable-dspam=no. or change your PATH])
		else
			echo
			echo Building dspam plugin with dspam in $dspam
			AC_DEFINE_UNQUOTED([DSPAM_BINARY], "$dspam", [dspam enabled])
		fi
	;;
esac
AM_CONDITIONAL(BUILD_DSPAM, test "x$BUILD_DSPAM" = "xyes")

##############################################################################

AC_ARG_ENABLE([spamassassin], [  --enable-spamassassin=yes|no build spamassassin plugin. default yes.], [BUILD_SPAMASSASSIN="$enableval"], [BUILD_SPAMASSASSIN=yes])
case $BUILD_SPAMASSASSIN in
	no)
        BUILD_SPAMASSASSIN=no
	;;
	*)
		BUILD_SPAMASSASSIN=yes
		AC_MSG_CHECKING([whether we can locate the dspam program])
		spamc=`which spamc 2>/dev/null`
		if test "x$spamc" = "x"; then
			echo
			AC_MSG_ERROR([Could not find spamc in PATH. use --enable-spamassassin=no. or change your PATH])
		else
			echo
			echo Building spamassassin plugin with spamc in $spamc
			AC_DEFINE_UNQUOTED([SPAMC_BINARY], "$spamc", [spamassassin enabled])
		fi
	;;
esac
AM_CONDITIONAL(BUILD_SPAMASSASSIN, test "x$BUILD_SPAMASSASSIN" = "xyes")


##############################################################################

AC_ARG_ENABLE([clamav], [  --enable-clamav=yes|no       build clamav dspam plugin. default yes.], [BUILD_CLAMAV="$enableval"], [BUILD_CLAMAV=yes])
case $BUILD_CLAMAV in
	no)
        BUILD_CLAMAV=no
	;;
	*)
		BUILD_CLAMAV=yes
		AC_MSG_CHECKING([whether we can locate the clamdscan program])
		clamav=`which clamdscan 2>/dev/null`
		if test "x$clamav" = "x"; then
			echo
			AC_MSG_ERROR([Could not find clamdscan in PATH. use --enable-clamav=no. or change your PATH])
		else
			echo
			echo Building clamav plugin with clamdscan in $clamav
			AC_DEFINE_UNQUOTED([CLAMAV_BINARY], "$clamav", [clamav enabled])
		fi
	;;
esac
AM_CONDITIONAL(BUILD_CLAMAV, test "x$BUILD_CLAMAV" = "xyes")

##############################################################################

AC_ARG_ENABLE([black], [  --enable-black=yes|no        build blacklist plugin. default yes.], [BUILD_BLACK="$enableval"], [BUILD_BLACK=yes])
case $BUILD_BLACK in
	no)
        BUILD_BLACK=no
	;;
	*)
		BUILD_BLACK=yes
		echo Building blacklist plugin
	;;
esac
AM_CONDITIONAL(BUILD_BLACK, test "x$BUILD_BLACK" = "xyes")

##############################################################################

AC_ARG_ENABLE([quarantine], [  --enable-quarantine=yes|no   build quarantine plugin. default yes.], [BUILD_QUARANTINE="$enableval"], [BUILD_QUARANTINE=yes])
case $BUILD_QUARANTINE in
	no)
        BUILD_QUARANTINE=no
	;;
	*)
		BUILD_QUARANTINE=yes
		echo Building quarantine plugin
	;;
esac
AM_CONDITIONAL(BUILD_QUARANTINE, test "x$BUILD_QUARANTINE" = "xyes")

##############################################################################

AC_ARG_ENABLE([vquad], [  --enable-vquad=yes|no        build vpopmail support for quarantine plugin. default yes.], [BUILD_VQUAD="$enableval"], [BUILD_VQUAD=yes])
case $BUILD_VQUAD in
	no)
        BUILD_VQUAD=no
	;;
	*)
		if test "x$BUILD_VQUAD" = "xyes" ; then
			if test "x$BUILD_QUARANTINE" = "xyes" ; then
				AM_PROG_CC_C_O
				BUILD_VQUAD=yes
				AC_DEFINE_UNQUOTED([HAVE_VPOPMAIL], 1, [have vpopmail for vquad])
				echo Building vpopmail support for quarantine plugin
			else
				BUILD_VQUAD=no
			fi
		else
			echo I can not build vpopmail support for quarantine since quarantine was disabled
		fi
	;;
esac
AM_CONDITIONAL(BUILD_VQUAD, test "x$BUILD_VQUAD" = "xyes")

##############################################################################

if test "x$BUILD_VQUAD" = "xyes"; then
    AC_ARG_WITH([vpopmail], [  --with-vpopmail=<path>  prefix of vpopmail installation. e.g. /usr/local or /home], [VPOPMAIL_PREFIX=$with_vpopmail],
    AC_MSG_ERROR([You must call configure with the --with-vpopmail option when
                  requesting vquad. This tells configure where to find the
                  vpopmail C library and headers.
                  e.g. --with-vpopmail=/usr/local or --with-vpopmail=/home]))

    if test "x$VPOPMAIL_PREFIX" = "xyes"; then
        AC_MSG_ERROR([You must call configure with the --with-vpopmail option when
                  requesting vquad. This tells configure where to find the
                  vpopmail C library and headers.
                  e.g. --with-vpopmail=/usr/local or --with-vpopmail=/home])
    fi
    AC_SUBST(VPOPMAIL_PREFIX)
    VPOPMAIL_LIBS="${VPOPMAIL_PREFIX}/lib/libvpopmail.a"
    VPOPMAIL_CFLAGS="-I${VPOPMAIL_PREFIX}/include"
    AC_SUBST(VPOPMAIL_LIBS)
    AC_SUBST(VPOPMAIL_CFLAGS)
fi

##############################################################################

AC_ARG_ENABLE([regex], [  --enable-regex=yes|no        build regex support for address in configuration file.], [BUILD_REGEX="$enableval"], [BUILD_REGEX=yes])
if test "x$BUILD_REGEX" = "xyes"; then
	BUILD_REGEX=yes
	AC_CHECK_FUNCS(regexec,,[AC_CHECK_LIB(regex,regexec, AC_DEFINE(HAVE_REGEXEC,1,[Define to 1 if you have regex support.]),[AC_MSG_ERROR([No regex library found])])])
	echo Building regex support for adress parsing in configuration file
else
	echo Regex support in configuration file disabled
fi

dnl output
AC_OUTPUT(
	Makefile
	src/Makefile
	src/plugins/Makefile
	src/plugins/general/Makefile
	src/plugins/user/Makefile
)

