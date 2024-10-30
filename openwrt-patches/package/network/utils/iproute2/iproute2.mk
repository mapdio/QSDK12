# Recipe extension for package : ipqroute2

define _tc-full_install_append
	$(INSTALL_DIR) $(1)/lib/debug
	$(INSTALL_BIN) ./files/tc.debug $(1)/lib/debug/tc
endef

Package/tc-full/install += $(newline)$(tc-full_install_append)
