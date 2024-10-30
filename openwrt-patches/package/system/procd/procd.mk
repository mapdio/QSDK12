#
# Recipe extension for systat
#

ifeq ($(CONFIG_PACKAGE_kmod-ath11k)$(CONFIG_PACKAGE_kmod-ath12k),)
TARGET_CFLAGS+= -DFASTBOOT
endif
