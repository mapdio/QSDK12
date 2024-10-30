# Recipe extension for syslog-ng

define syslog-ng_append
    DEPENDS+=+PACKAGE_logstreamer:librdkafka
endef

ifdef CONFIG_PACKAGE_logstreamer
	CONFIGURE_ARGS += \
			  --enable-kafka=yes
endif

Package/syslog-ng += $(newline)$(syslog-ng_append)
