include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=netstandby-eawtp-drv
PKG_SOURCE_PROTO:=git
PKG_BRANCH:=master
PKG_RELEASE:=2
LOCAL_SRC:=$(TOPDIR)/qca/src/qca-net-standby/driver/eawtp

include $(INCLUDE_DIR)/local-development.mk
ifeq ($(DUMP)$(PKG_VERSION),)
  PKG_VERSION:=$(shell git ls-remote $(PKG_SOURCE_URL) $(PKG_BRANCH) | cut -b -7)
endif

PKG_BUILD_DEPENDS :=
MAKE_OPTS:=

include $(INCLUDE_DIR)/package.mk

define KernelPackage/netstandby-eawtp-drv
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Standby eawtp module
  DEPENDS:=@TARGET_ipq53xx +kmod-qca-nss-dp +kmod-qca-wifi @!LINUX_3_18
  FILES:=$(PKG_BUILD_DIR)/qca-net-standby-eawtp.ko
endef

define KernelPackage/netstandby-eawtp-drv/Description
Kernel module for ErP network standby framework to interface
with subsystem drivers and netstandby application library
endef

EXTRA_CFLAGS+= \
	-I$(STAGING_DIR)/usr/include/qca-nss-ppe \
	-I$(STAGING_DIR)/usr/include/qca-ssdk \
	-I$(STAGING_DIR)/usr/include/qca-ssdk/fal \
	-I$(STAGING_DIR)/usr/include/qca-ssdk/init \
	-I$(STAGING_DIR)/usr/include/qca-nss-dp \
	-I$(LINUX_DIR)/user_headers/include/

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" $(strip $(MAKE_OPTS)) \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		M="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		modules
endef

define Build/InstallDev
	$(call Build/InstallDev/netstandby-eawtp-drv,$(1))
endef

$(eval $(call KernelPackage,netstandby-eawtp-drv))
