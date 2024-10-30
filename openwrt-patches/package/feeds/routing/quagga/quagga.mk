# Recipe extension for package : rp-pppoe-relay

QUAGGA:=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))

define quagga_install_append
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DATA) $(QUAGGA)/files/quagga.hotplug $(1)/etc/hotplug.d/iface/70-quagga
endef

define quagga-ripd_install_append
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(QUAGGA)/files/ripd.config $(1)/etc/config/ripd
endef

Package/quagga/install += $(newline)$(quagga_install_append)
Package/quagga-ripd/install += $(newline)$(quagga-ripd_install_append)
