# Recipe extension for package : mcproxy

MCPROXY:=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))

define mcproxy_install_append
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DATA) $(MCPROXY)/files/mcproxy.hotplug $(1)/etc/hotplug.d/iface/55-mcproxy
endef

Package/mcproxy/install += $(newline)$(mcproxy_install_append)
