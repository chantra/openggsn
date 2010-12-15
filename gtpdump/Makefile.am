
lib_LTLIBRARIES = libgtpdump.la
include_HEADERS = gtpie_utils.h
bin_PROGRAMS = gtpdump

AUTOMAKE_OPTIONS = subdir-objects

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Werror -Wall -DSBINDIR='"$(sbindir)"' -ggdb $(PCAP_CFLAGS)


gtpdump_DEPENDENCIES = libgtpdump.la

libgtpdump_la_SOURCES = gtpie_utils.c gtpie_utils.h
gtpdump_SOURCES = gtpdump.c ../lib/syserr.h ../lib/syserr.c gtpdump_options.c gtpdump_options.h

gtpdump_LDADD = @LIBOBJS@ @EXEC_LDADD@ -lgtp -L../gtp -lgtpdump -L. $(PCAP_LIBS)
#ggsn_SOURCES = ggsn.c cmdline.c cmdline.h

