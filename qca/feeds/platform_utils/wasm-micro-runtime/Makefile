include $(TOPDIR)/rules.mk

PKG_NAME:=libwamr
PKG_VERSION:=1.3.2
PKG_RELEASE:=1
PKG_SOURCE:=WAMR-$(PKG_VERSION).tar.gz

PKG_SOURCE_URL:=https://github.com/bytecodealliance/wasm-micro-runtime/archive/refs/tags
PKG_HASH:=58961ba387ed66ace2dd903597f1670a42b8154a409757ae6f06f43fe867a98c
CMAKE_INSTALL:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/wasm-micro-runtime-WAMR-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/$(PKG_NAME)
  SECTION:=libs
  CATEGORY:= Libraries
  MAINTAINER:=Bytecode Alliance
  TITLE:=Library implementing the WebAssembly Micro Runtime
  LICENSE:=Apache License v2.0 with LLVM Exceptions
  DEPENDS:=@TARGET_ipq50xx_generic||TARGET_ipq60xx_generic||TARGET_ipq95xx_generic||TARGET_ipq53xx_generic||TARGET_ipq807x_generic +libstdcpp
endef

define Package/$(PKG_NAME)/description
 WebAssembly Micro Runtime (WAMR) is a lightweight standalone WebAssembly (Wasm) runtime with small footprint, high performance and highly configurable features for applications cross from embedded, IoT, edge to Trusted Execution Environment (TEE), smart contract, cloud native and so on.
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/libwamr
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/include/*.h $(1)/usr/include/libwamr/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libiwasm.so $(1)/usr/lib/
endef

define Package/${PKG_NAME}/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/product-mini/platforms/linux/iwasm $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libiwasm.so $(1)/usr/lib
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
