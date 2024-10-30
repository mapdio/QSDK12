ifeq ($(ARCH), aarch64_be)
	OPENSSL_TARGET:=linux-aarch64-openwrt
else
	OPENSSL_TARGET:=linux-$(call qstrip,$(CONFIG_ARCH))-openwrt
endif
