AC_INIT([mmilter], [0.1], [matteo@dancingbear.it])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

AC_SEARCH_LIBS(pthread_create, pthread lpthread)


AC_CHECK_HEADERS([stdio.h unistd.h])

if test -d /usr/lib/libmilter ; then
        LDFLAGS="$LDFLAGS -L/usr/lib/libmilter"
fi
AC_CHECK_LIB(milter, mi_stop,,[
        AC_SEARCH_LIBS(sm smutil)
        AC_CHECK_LIB(milter, mi_stop,,[
                AC_MSG_ERROR([Cannot find libmilter])
        ])
])

AC_CHECK_HEADERS(libmilter/mfapi.h,,[
        AC_MSG_ERROR([mfapi.h not found])
])

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT
