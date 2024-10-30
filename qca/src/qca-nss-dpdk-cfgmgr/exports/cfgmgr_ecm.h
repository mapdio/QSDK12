/*
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
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

#include "dpfe_api.h"
#include "cfgmgr_def.h"

/**
 * @file cfgmgr_ecm.h
 *	Config Manager definitions for WIFI.
 */
#ifndef _CFGMGR_ECM_H_
#define _CFGMGR_ECM_H_

#define DPDK_MSG_SOCK_DATA_SIZE 1024
#define CFGMGR_MSG_TYPE_ECM 0x01

/*
 * cfgmgr_ecm_msg_types
 *     Message types for ECM communication.
 */
enum cfgmgr_ecm_msg_type {
       CFGMGR_ECM_MSG_TYPE_IPV4_CREATE,		/* IPv4 Create message from Kernel to Userspace */
       CFGMGR_ECM_MSG_TYPE_IPV4_DESTROY,	/* IPv4 Destroy message from Kernel to Userspace */
       CFGMGR_ECM_MSG_TYPE_IPV4_STATS_SYNC_MANY,/* IPv4 Stats Sync message from Kernel to Userspace */
       CFGMGR_ECM_MSG_TYPE_IPV6_CREATE,		/* IPv6 Create message from Userspace to Kernel */
       CFGMGR_ECM_MSG_TYPE_IPV6_DESTROY,	/* IPv6 Destroy message from Userspace to Kernel */
       CFGMGR_ECM_MSG_TYPE_IPV6_STATS_SYNC_MANY,/* IPv6 Stats Sync message from Userspace to Kernel */
       CFGMGR_ECM_MSG_TYPE_MAX,			/* Maximum number of messages */
};

/**
 * Tx command status.
 */
typedef enum {
	DPDK_DRV_TX_SUCCESS = 0,		/**< Success. */
	DPDK_DRV_TX_FAILURE,			/**< Tx failed. */
	DPDK_DRV_TX_FAILURE_NOT_READY,		/**< Failure due to DPFE state uninitialized. */
	DPDK_DRV_TX_FAILURE_TOO_LARGE,		/**< Command is too large to fit in one message. */
	DPDK_DRV_TX_FAILURE_TOO_SHORT,		/**< Command or packet is shorter than expected. */
	DPDK_DRV_TX_FAILURE_NOT_SUPPORTED,	/**< Command or packet not accepted for forwarding. */
	DPDK_DRV_TX_FAILURE_NOT_ENABLED,	/**< Failure due to DPFE not enabled. */
} dpdk_drv_tx_status_t;

/*
 * cfgmgr_ecm_msg
 *	Message structure for ECM message.
 *
 * This message type is used for sending and receiving all the ECM
 * related messages.
 */
struct cfgmgr_ecm_ipv4_msg {
	struct cfgmgr_cmn_msg cmn_msg;
	struct dpfe_ipv4_msg dpfe_ipv4_msg;
} __attribute__ ((aligned(sizeof(void*))));

typedef void (*dpdk_drv_msg_callback_t)(void *app_data, void *msg);

/**
 * Indicates whether the l2 feature flag is enabled or disabled.
 *
 * @return
 * True if enabled; false if disabled.
 */
extern bool dpdk_drv_is_l2_feature_enabled(void);

/**
 * Gets the maximum number of IPv4 connections supported by the DPFE acceleration engine.
 *
 * @return
 * The maximum number of connections that can be accelerated by the DPFE.
 */
extern int dpdk_drv_ipv4_max_conn_count(void);

/**
 * Transmits a message to the DPFE.
 *
 * @param	msg		The IPv4 message.
 *
 * @return
 * The status of the Tx operation (#dpdk_drv_tx_status_t).
 */
dpdk_drv_tx_status_t cfgmgr_ecm_ipv4_tx_msg(struct cfgmgr_ecm_ipv4_msg *cfg_ecm_ipv4_msg);

/*
 * cfgmgr_ecm_ipv6_msg
 *	Message structure for ECM message.
 *
 * This message type is used for sending and receiving all the ECM
 * related messages.
 */
struct cfgmgr_ecm_ipv6_msg {
	struct cfgmgr_cmn_msg cmn_msg;
	struct dpfe_ipv6_msg dpfe_ipv6_msg;
} __attribute__ ((aligned(sizeof(void*))));

/**
 * Gets the maximum number of IPv6 connections supported by the DPFE acceleration engine.
 *
 * @return
 *  The maximum number of connections that can be accelerated by the DPFE; integer.
 */
extern int dpdk_drv_ipv6_max_conn_count(void);

/**
 * Transmits a message to the DPFE.
 *
 * @param	msg		The IPv6 message.
 *
 * @return
 * The status of the Tx operation (#dpdk_drv_tx_status_t).
 */
dpdk_drv_tx_status_t cfgmgr_ecm_ipv6_tx_msg(struct cfgmgr_ecm_ipv6_msg *cfg_ecm_ipv6_msg);

int32_t cfgmgr_core_get_ifnum_by_netdev(struct net_device *netdev);

#endif /* _CFGMGR_ECM_H_ */
