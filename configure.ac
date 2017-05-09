dnl +----------------------------------------------------------------------+
dnl |                              Init                                    |
dnl +----------------------------------------------------------------------+

AC_INIT([mod_authnz_ibmdb2], [2.2.7-dev], [https://github.com/tessus/mod_authnz_ibmdb2/issues])
AC_MSG_NOTICE([Configuring $PACKAGE_NAME $PACKAGE_VERSION])

dnl +----------------------------------------------------------------------+
dnl |                          Configure Options                           |
dnl +----------------------------------------------------------------------+

AC_ARG_WITH(apxs,
            AS_HELP_STRING([--with-apxs=FILE],
                            [FILE is the pathname of the Apache tool [apxs]]),
            [APXS="$with_apxs"])
AC_ARG_WITH(IBM_DB2,
            AS_HELP_STRING([--with-IBM_DB2=DIR],
                            [DIR is the IBM DB2 instance or home directory where the
                            DB2 application development headers and libraries are located]),
            [IBM_DB2="$with_IBM_DB2"])
AC_ARG_ENABLE([man-pages],
            AS_HELP_STRING([--disable-man-pages],
                            [do not install man pages @<:@default: no@:>@]),
            [man_pages=${enableval}], [man_pages=yes])
AC_ARG_ENABLE([activation],
            AS_HELP_STRING([--enable-activation],
                            [activate module in Apache config @<:@default: no@:>@]),
            [activation=${enableval}], [activation=no])

if test "x${activation}" != "xno" && test "x${activation}" != "xyes"; then
    AC_MSG_ERROR([--enable-activation can be either yes or no.])
fi
if test "x${man_pages}" != "xno" && test "x${man_pages}" != "xyes"; then
    AC_MSG_ERROR([--enable-man_pages can be either yes or no.])
fi

dnl +----------------------------------------------------------------------+
dnl |                          config.nice macro                           |
dnl +----------------------------------------------------------------------+

AC_DEFUN([AC_CONFIG_NICE],
[
  test -f $1 && mv $1 $1.old
  rm -f $1.old
  cat >$1<<EOF
#! /bin/sh
#
# Created by configure

EOF

  for var in CFLAGS CXXFLAGS CPPFLAGS LDFLAGS LIBS CC CXX; do
    eval val=\$$var
    if test -n "$val"; then
      echo "$var='$val' \\" >> $1
    fi
  done

  for arg in [$]0 "[$]@"; do
    echo "'[$]arg' \\" >> $1
  done
  echo '"[$]@"' >> $1
  chmod +x $1
])
AC_CONFIG_NICE(config.nice)

dnl +----------------------------------------------------------------------+
dnl |                        Additional Init Macros                        |
dnl +----------------------------------------------------------------------+

AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_CANONICAL_HOST

dnl +----------------------------------------------------------------------+
dnl |                          Process Arguments                           |
dnl +----------------------------------------------------------------------+

if test -n "${APXS}"; then
    AC_CHECK_FILE([$APXS], [], [APXS=no])
fi
if test -z "${APXS}"; then
    AC_PATH_PROGS(APXS, apxs2 apxs, no, [/usr/local/apache/bin:/usr/sbin:/usr/local/apache2/bin:$PATH])
fi
if test "$APXS" = no; then
    AC_MSG_ERROR([apxs not found. set apxs with --with-apxs.])
fi
AC_SUBST(APXS)

if test -n "$IBM_DB_HOME"; then
    DB2DIR=$IBM_DB_HOME
fi
# option --with-apxs overrides the ENV var
if test -n "$IBM_DB2"; then
    DB2DIR=$IBM_DB2
fi

if test -n "$CFLAGS"; then
    MOD_CFLAGS="-Wc,\"$CFLAGS\""
fi
if test -n "$LDFLAGS"; then
    MOD_LDFLAGS="-Wc,\"$LDFLAGS\""
fi
MOD_CFLAGS="-I${DB2DIR}/include $MOD_CFLAGS"
MOD_LDFLAGS="-L${DB2DIR}/lib $MOD_LDFLAGS"
AC_SUBST(MOD_CFLAGS)
AC_SUBST(MOD_LDFLAGS)

CFLAGS="$CFLAGS -I${DB2DIR}/include"
CPPFLAGS="$CPPFLAGS -I${DB2DIR}/include"
LDFLAGS="$LDFLAGS -L${DB2DIR}/lib"

AC_CHECK_HEADERS([sqlcli1.h])
AC_SEARCH_LIBS([SQLConnect], [db2],
                ,
                AC_MSG_ERROR([DB2 CLI libraries not found. set DB2 HOME with --with-IBM_DB2.]))
AC_SUBST(DB2DIR)

dnl +----------------------------------------------------------------------+
dnl |                          Check Apache Version                        |
dnl +----------------------------------------------------------------------+

# my own super test to check fo the right Apache release
AC_DEFUN([AX_CHECK_APACHE_22_OR_GT],
[
    AC_MSG_CHECKING([if Apache release is 2.2 or above])
    cat > conftest2.c << EOF
    #include "ap_release.h"
    int main(){
    if (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER >= 2)
        return 0;
    else
        return -1;
    }
EOF
    AINC_DIR=`${APXS} -q exp_includedir`
    if (($CC $CFLAGS -I $AINC_DIR -o conftest2 conftest2.c  >&5) && (./conftest2))
    then
        #AC_MSG_RESULT([Apache release verified. All good.])
        AC_MSG_RESULT([yes])
        [$2]
    else
        #AC_MSG_RESULT([Apache release not 2.2 or above. Panic.])
        AC_MSG_RESULT([no])
        [$3]
    fi
])dnl

AX_CHECK_APACHE_22_OR_GT(,,AC_MSG_ERROR([This module only works with Apache 2.2 and above.]))

dnl +----------------------------------------------------------------------+
dnl |                   OS specific flags and settings                     |
dnl +----------------------------------------------------------------------+

AC_MSG_CHECKING(for architecture)

case "$host_os" in
linux*)
    ARCH="linux"
    ;;
aix*)
    ARCH="aix"
    ;;
darwin*|rhapsody*)
    ARCH="osx"
    ;;
*solaris*)
    ARCH="solaris"
    ;;
hpux*)
    ARCH="hpux"
    ;;
freebsd*)
    ARCH="freebsd"
    ;;
netbsd*)
    ARCH="netbsd"
    ;;
osf*)
    ARCH="osf"
    ;;
openbsd*)
    ARCH="openbsd"
    ;;
*)
    ARCH="unknown"
    ;;
esac

AC_MSG_RESULT([$ARCH ($host_os)])

if test "x$ARCH" = "xaix"; then
    DB2_LDFLAGS="-Wl,-G,-blibpath:$DB2DIR/lib"
else
    DB2_LDFLAGS="-Wl,-rpath,$DB2DIR/lib"
fi
AC_SUBST(DB2_LDFLAGS)

if test "x$ARCH" = "xosx"; then
    EXTRA_LDFLAGS="-Wc,\"-arch x86_64\" -Wl,\"-arch x86_64\""
    AC_SUBST(EXTRA_LDFLAGS)
fi

dnl +----------------------------------------------------------------------+
dnl |                           Process Options                            |
dnl +----------------------------------------------------------------------+

AC_MSG_CHECKING(whether we want to activate the module in Apache config)
if test "x${activation}" = "xno"; then
    AC_MSG_RESULT([no])
    ACTIVATE=-A
else
    AC_MSG_RESULT([yes])
    ACTIVATE=-a
fi
AC_SUBST(ACTIVATE)

AC_MSG_CHECKING(whether we want to install the man pages)
if test "x${man_pages}" = "xyes"; then
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi
AM_CONDITIONAL([NO_MAN_PAGES], [test x$man_pages = xno])

dnl +----------------------------------------------------------------------+
dnl |                          Create config.h                             |
dnl +----------------------------------------------------------------------+

echo "#define MODULE \"$PACKAGE_NAME\"" >src/config.h
echo "#define RELEASE \"$PACKAGE_VERSION\"" >>src/config.h

dnl +----------------------------------------------------------------------+
dnl |                              Output                                  |
dnl +----------------------------------------------------------------------+

MOD_LOC=`${APXS} -q exp_libexecdir`
CONF_LOC=`${APXS} -q exp_sysconfdir`

AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])
AC_OUTPUT

echo "

+----------------------------------------------------------------------+
|                        Configuration Summary                         |
+----------------------------------------------------------------------+


    mod_authnz_ibmdb2:     ${PACKAGE_VERSION}

    Detected OS:           ${host_os}
    Compilation arch:      ${ARCH}

    apxs:                  ${APXS}
    DB2 home:              ${DB2DIR}

    Activate module:       ${activation}
    Install man pages:     ${man_pages}

    Module location:       ${MOD_LOC}


+----------------------------------------------------------------------+
|                         Now run: make install                        |
|                        (as root or with sudo)                        |
|                                                                      |
|               http://tessus.github.io/mod_authnz_ibmdb2              |
+----------------------------------------------------------------------+

"
