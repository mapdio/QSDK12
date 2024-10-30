#!/bin/sh
#
# Copyright (c) 2015-2016, 2019, The Linux Foundation. All rights reserved.
# Copyright (c) 2023, Qualcomm Innovation Center, Inc. All rights reserved.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL  WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

type ipq_board_name &>/dev/null  || ipq_board_name() {
	echo $(board_name) | sed 's/^\([^-]*-\)\{1\}//g'
}

. /lib/functions.sh

ipq9574_wifi_load()
{
	if [ -f /lib/modules/$(uname -r)/ath11k.ko ]; then
		insmod ath11k
		insmod ath11k_ahb
		insmod ath11k_pci
		sleep 2
		wifi up
	else
		wifi load
	fi
}

ipq9574_wifi_unload()
{
	lsmod | grep ath11k > /dev/null
	if [ $? -eq 0 ]; then
		wifi down
		sleep 2
		rmmod ath11k_pci
		rmmod ath11k_ahb
		rmmod ath11k
	else
		wifi unload
	fi
}

ipq9574_wifi_reload()
{
	ipq9574_wifi_unload
	ipq9574_wifi_load
}

ipq5332_wifi_load()
{
	if [ -f /lib/modules/$(uname -r)/ath12k.ko ]; then
		insmod ath12k
		sleep 2
		wifi up
	else
		wifi load
	fi
}

ipq5332_wifi_unload()
{
	lsmod | grep ath12k > /dev/null
	if [ $? -eq 0 ]; then
		wifi down
		sleep 2
		rmmod ath12k
	else
		wifi unload
	fi
}

ipq5332_wifi_reload()
{
	ipq5332_wifi_unload
	ipq5332_wifi_load
}

board=$(ipq_board_name)
case "$1" in
	load)
		case "$board" in
		ap-al* | db-al*)
			ipq9574_wifi_load ;;
		ap-mi* | db-mi*)
			ipq5332_wifi_load ;;
		esac ;;
	unload)
		case "$board" in
		ap-al* | db-al*)
			ipq9574_wifi_unload ;;
		ap-mi* | db-mi*)
			ipq5332_wifi_unload ;;
		esac ;;
	reload)
		case "$board" in
		ap-al* | db-al*)
			ipq9574_wifi_reload ;;
		ap-mi* | db-mi*)
			ipq5332_wifi_reload ;;
		esac ;;
esac
