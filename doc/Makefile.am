if BUILD_GGSN
  GGSN_MAN = ggsn.8
endif
if BUILD_SGSNEMU
  SGSNEMU_MAN = sgsnemu.8
endif

man_MANS = $(GGSN_MAN) $(SGSNEMU_MAN)
man_aux = $(man_MANS:.1=.x)
EXTRA_DIST = $(man_MANS)

