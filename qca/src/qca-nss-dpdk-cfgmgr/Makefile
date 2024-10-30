#
# Makefile for the config manager
#
ccflags-y := -I$(obj) -I$(obj)/.. -I$(obj)/exports
ccflags-y += -Wall -Werror

export BUILD_ID = \"Build Id: $(shell date +'%m/%d/%y, %H:%M:%S')\"
ccflags-y += -DCFGMGR_DPDK_BUILD_ID="$(BUILD_ID)"

obj-y += src/
obj ?= .
