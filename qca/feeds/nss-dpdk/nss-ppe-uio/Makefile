include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=nss-ppe-uio
LOCAL_SRC:=$(TOPDIR)/qca/src/nss-ppe-uio
PKG_RELEASE:=1

include $(INCLUDE_DIR)/local-development.mk

ifeq ($(DUMP)$(PKG_VERSION),)
  PKG_VERSION:=$(shell git ls-remote $(PKG_SOURCE_URL) $(PKG_BRANCH) | cut -b -7)
endif

include $(INCLUDE_DIR)/package.mk

define KernelPackage/$(PKG_NAME)
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Support
  TITLE:= UIO driver for PPE
  DEPENDS:= +kmod-qca-ssdk-nohnat +TARGET_ipq95xx:kmod-qca-nss-ppe
  FILES:=$(PKG_BUILD_DIR)/nss-ppe-uio.ko
  AUTOLOAD:=$(call AutoLoad,31,nss-ppe-uio)
endef

define KernelPackage/$(PKG_NAME)/Description
  uio driver for PPE
endef

define KernelPackage/$(PKG_NAME)/install
  $(INSTALL_DIR) $(1)/usr/bin
endef

EXTRA_CFLAGS += -I$(STAGING_DIR)/usr/include/qca-ssdk

define Build/Compile
  $(MAKE) $(EXTRA_CFLAGS) -C "$(LINUX_DIR)" \
    CROSS_COMPILE="$(TARGET_CROSS)" \
    ARCH="$(LINUX_KARCH)" \
    M="$(PKG_BUILD_DIR)" \
    modules
endef

$(eval $(call KernelPackage,$(PKG_NAME)))
