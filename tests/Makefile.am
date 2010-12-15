## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = subdir-objects

AM_LDFLAGS = @EXEC_LDFLAGS@   

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Werror -Wall -DSBINDIR='"$(sbindir)"' -ggdb

if BUILD_GTPDUMP
  GTPDUMP_SOURCES=check_gtpie_utils.c check_gtpie_utils.h
  GTPDUMP_LIBS=-lgtpdump -L../gtpdump
endif

TESTS = check_libs
check_PROGRAMS = check_libs
check_libs_SOURCES = check_libs.c \
										check_libgtp.c check_libgtp.h \
										$(GTPDUMP_SOURCES)

check_libs_CFLAGS = @CHECK_CFLAGS@
check_libs_LDADD =  @CHECK_LIBS@ @LIBOBJS@ @EXEC_LDADD@ -lgtp -L../gtp $(GTPDUMP_LIBS)
