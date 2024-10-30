#
# Makefile extension for lxc
#
TMPVAR := $(CONFIGURE_ARGS)
CONFIGURE_ARGS = $(filter-out --enable-hashes=solaris, $(TMPVAR))
