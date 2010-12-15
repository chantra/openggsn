ACLOCAL_AMFLAGS = -I m4

if BUILD_GTPDUMP
  GTPDUMP_DIR = gtpdump
endif

if BUILD_UNITTESTS
  UNITTESTS_DIR = tests
endif

if BUILD_GGSN
  GGSN_DIR=ggsn
endif

if BUILD_SGSNEMU
  SGSNEMU_DIR=sgsnemu
endif


SUBDIRS = \
			gtp \
			$(GGSN_DIR) \
			$(SGSNEMU_DIR) \
			$(GTPDUMP_DIR) \
			$(UNITTESTS_DIR) \
			doc
