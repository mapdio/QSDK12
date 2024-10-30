/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * @file dpdk_core_msg_types.h
 *	Wlan cmd and event defination for dpdk
 */

#ifndef _DPDK_CORE_MSG_TYPES_H_
#define _DPDK_CORE_MSG_TYPES_H_

#include "cfgmgr_def.h"

/*
 * dpdk_core_msg_types
 *	DPDK Configuration message types.
 */
enum dpdk_core_msg_types {
	DPDK_CORE_MSG_TYPE_SETUP,		/* DPFE state is active. Also shares the net. */
	DPDK_CORE_MSG_TYPE_INTERFACE_INIT,		/* DPFE interface init */

	/*
	 * Route related messages.
	 */
	DPDK_CORE_MSG_TYPE_ROUTE_REG,		/* DPFE post routing hook. */
	DPDK_CORE_MSG_TYPE_ROUTE_UNREG,		/* DPFE unregister post routing hook. */
	DPDK_CORE_MSG_TYPE_POST_ROUTE_INFO,	/* DPFE post routing info. */

	/* Add new commands before this */
	DPDK_CORE_MSG_TYPE_MAX
};

/*
 * dpdk_core_dpfe_setup
 *	DPFE setup message.
 */
struct dpdk_core_dpfe_setup {
};

/*
 * dpdk_core_intf_init
 *	Interface init message
 */
struct dpdk_core_intf_init_msg {
	uint8_t port;
	uint32_t ifnum;
	char if_name[16];	// KNI device name size.
};

/*
 * dpdk_core_dpfe_route
 *	Add DPFE route message.
 */
struct dpdk_core_dpfe_route {
	uint8_t tos;
	uint8_t proto;
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t src_ip;
	uint32_t dest_ip;
	uint32_t mask;
	uint32_t resv;
};

/*
 * dpdk_core_msg
 *	DPDK core message.
 */
struct dpdk_core_msg {
	struct cfgmgr_cmn_msg cmn;

	union {
		struct dpdk_core_dpfe_setup dcds_msg;
		struct dpdk_core_intf_init_msg intf_msg;
		struct dpdk_core_dpfe_route dcdr_msg;
	} msg;
} __attribute__((packed));

#endif /* _DPDK_CORE_MSG_TYPES_H_ */
