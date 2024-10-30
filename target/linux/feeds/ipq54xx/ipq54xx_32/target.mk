
ARCH:=arm
SUBTARGET:=ipq54xx_32
BOARDNAME:=QTI IPQ54xx(32bit) based boards
CPU_TYPE:=cortex-a7

define Target/Description
	Build firmware image for IPQ54xx SoC devices.
endef

DEFAULT_PACKAGES += \
	uboot-devsoc-mmc32 uboot-devsoc-norplusmmc32 \
	uboot-devsoc-norplusnand32 uboot-devsoc-nand32
