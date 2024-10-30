#
## Makefile for NSS PPE UIO driver
#

obj ?= .

obj-m += nss-ppe-uio.o

nss-ppe-uio-objs = nss_ppe_uio.o

INCLUDE := \
	  -I$(STAGING_DIR)/usr/include/qca-ssdk \
	  -I$(STAGING_DIR)/usr/include/qca-nss-ppe

#
## Base files
#
ccflags-y += $(INCLUDE)
ccflags-y += -Wno-unused-value -Wno-unused-variable -Wno-unused-function -Wno-format -Wall -I$(obj)
ccflags-y += -DPPE_UIO_DEBUG_LEVEL=3
