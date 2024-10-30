include $(TOPDIR)/rules.mk

PKG_NAME:=python3-pyelftools
PKG_VERSION:=master
PKG_RELEASE:=1
PKG_MAINTAINER:=Eli Bendersky <eliben@gmail.com>
PKG_LICENSE:=LGPL-2.1+
PKG_LICENSE_FILES:=COPYING

PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/eliben/pyelftools.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=15f032b22a9b870b66d3238822724addda643ca3
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_FIXUP:=libtool

include $(INCLUDE_DIR)/package.mk
include ../python3-package.mk

define Package/python3-pyelftools
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Library for analyzing ELF files and DWARF debugging information
  URL:=https://github.com/eliben/pyelftools.git
  DEPENDS:= \
	  +python3-light \
	  +python3-distutils \
	  +python3-multiprocessing \
	  +python3-sqlite3 \
	  +python3-ctypes
  VARIANT:=python3
endef

define Package/python3-pyelftools/description
 pyelftools is a pure-Python library for parsing and analyzing
 ELF files and DWARF debugging information.
endef

define Build/InstallDev
	$(CP) $(PKG_BUILD_DIR)/elftools $(STAGING_DIR)/../hostpkg/lib/python3.7/site-packages/
endef

PYTHON3_PKG_SETUP_ARGS:=

$(eval $(call Py3Package,$(PKG_NAME)))
$(eval $(call BuildPackage,$(PKG_NAME)))
