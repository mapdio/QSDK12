#
# Makefile extension for nat46
#

define nat46_append
   DEPENDS+=+kmod-nf-conntrack6
endef

define nat46_installdev_append
	mkdir -p -m 0777 $(1)/usr/include/nat46
	$(CP) $(PKG_BUILD_DIR)/nat46/modules/*.h $(1)/usr/include/nat46/
endef

Package/nat46 += $(newline)$(nat46_append)
Build/InstallDev += $(newline)$(nat46_installdev_append)
