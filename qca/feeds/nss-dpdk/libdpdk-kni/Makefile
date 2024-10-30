include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=dpdk
PKG_VERSION:=21.11.2
PKG_RELEASE:=$(AUTORELEASE)
PKG_LICENSE:=BSD-3-Clause-and-GPL-2.0
PKG_LICENSE_FILES:=license/bsd-3-clause.txt license/gpl-2.0.txt

PKG_SOURCE_URL:=http://fast.dpdk.org/rel/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_HASH:=58cc5cfa54db6122782d458c73dec4532710facdc5a8a78d5a91cc4fdba97f7a
PKG_BUILD_DIR:=$(BUILD_DIR)/dpdk-stable-$(PKG_VERSION)
PATCH_DIR:=patches/

PKG_INSTALL:=1
PKG_BUILD_DEPENDS:=meson/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include ../../packages/devel/meson/meson.mk

MESON_ARGS+= -Denable_docs=false  -Denable_drivers=kni -Denable_kmods=true -Dkernel_dir=$(LINUX_DIR) -Ddisable_drivers=event/*

define Package/libdpdk-kni
  SECTION:=libs
  CATEGORY:=Libraries
  DEPENDS:= +libpcap +libopenssl +zlib +jansson +libatomic +libelf
  TITLE:=Set of libraries and drivers for fast packet processing
  URL:=https://www.dpdk.org
  TARGET_LDFLAGS+=-lpcap
  TARGET_CFLAGS+=-g
endef

define Package/libdpdk-kni/description
  DPDK is a set of libraries and drivers for fast packet processing.
  It supports many processor architectures and both FreeBSD and Linux.
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/openwrt-build/kernel/linux/kni/rte_kni.ko $(1)/usr/bin/

endef

define Package/libdpdk-kni/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/openwrt-build/kernel/linux/kni/rte_kni.ko $(1)/usr/bin/
endef

$(eval $(call BuildPackage,libdpdk-kni))
