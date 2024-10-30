#
# Makefile for the config manager
#
ccflags-y := -I$(obj)/../exports -I$(obj)/..
ccflags-y += -DCFGMGR_DPDK_BUILD_ID="$(BUILD_ID)"

obj-m += qca-nss-dpdk-cfgmgr.o
qca-nss-dpdk-cfgmgr-objs := cfgmgr_base.o
qca-nss-dpdk-cfgmgr-objs += cfgmgr_k2u.o
qca-nss-dpdk-cfgmgr-objs += cfgmgr_test.o
qca-nss-dpdk-cfgmgr-objs += cfgmgr_ecm.o
qca-nss-dpdk-cfgmgr-objs += cfgmgr_wlan.o
qca-nss-dpdk-cfgmgr-objs += cfgmgr_core.o

ccflags-y += -DCFGMGR_DEBUG_LEVEL=4

