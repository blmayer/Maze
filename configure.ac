#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Maze], [0.0.1], [bleemayer@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIRS([m4])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_CC
LT_INIT

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h string.h sys/socket.h unistd.h])

# Checks for library functions.
AC_CHECK_FUNCS([socket])

AC_CONFIG_FILES([Makefile
		 src/randomstr/Makefile
		 src/webng/Makefile
		 src/browser/Makefile
		 src/server/Makefile])

AC_OUTPUT

