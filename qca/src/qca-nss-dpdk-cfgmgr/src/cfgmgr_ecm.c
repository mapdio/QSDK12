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

#include "cfgmgr_base.h"

bool dpdk_drv_is_l2_feature_enabled(void) {
	return false;
}
EXPORT_SYMBOL(dpdk_drv_is_l2_feature_enabled);

int dpdk_drv_ipv4_max_conn_count(void) {
	return 128;
}
EXPORT_SYMBOL(dpdk_drv_ipv4_max_conn_count);

int dpdk_drv_ipv6_max_conn_count(void) {
	return 128;
}
EXPORT_SYMBOL(dpdk_drv_ipv6_max_conn_count);

dpdk_drv_tx_status_t cfgmgr_ecm_tx_msg(struct cfgmgr_cmn_msg *cfg_cmn_msg)
{
	struct cfgmgr_send_info info = {0};
	int ret;

	/*
	 * Fill info object.
	 */
	cfgmgr_error("%px: Message to send len=%d \n", cfg_cmn_msg, cfg_cmn_msg->msg_len);

	info.pid = 0;
	info.flags |= CFGMGR_K2U_SEND_INFO_MULTICAST;
	info.ifnum = CFGMGR_INTERFACE_ECM;
	info.resp_sock_data = cfg_cmn_msg->sock_data;

	ret = cfgmgr_k2u_msg_send(&info, cfg_cmn_msg, cfg_cmn_msg->msg_len);
	if (ret) {
		cfgmgr_error("%px: Unable to send the message.\n", cfg_cmn_msg);
		return DPDK_DRV_TX_FAILURE;
	}

	cfgmgr_error("%px: Message of type %d sent.\n", cfg_cmn_msg, CFGMGR_MSG_TYPE_ECM);

	return DPDK_DRV_TX_SUCCESS;
}

dpdk_drv_tx_status_t cfgmgr_ecm_ipv6_tx_msg(struct cfgmgr_ecm_ipv6_msg *cfg_ecm_ipv6_msg)
{
	return cfgmgr_ecm_tx_msg(&cfg_ecm_ipv6_msg->cmn_msg);
}
EXPORT_SYMBOL(cfgmgr_ecm_ipv6_tx_msg);

dpdk_drv_tx_status_t cfgmgr_ecm_ipv4_tx_msg(struct cfgmgr_ecm_ipv4_msg *cfg_ecm_ipv4_msg)
{
	return cfgmgr_ecm_tx_msg(&cfg_ecm_ipv4_msg->cmn_msg);
}
EXPORT_SYMBOL(cfgmgr_ecm_ipv4_tx_msg);

/*
 * cfgmgr_ecm_doit_handler()
 *	ECM rx message handler for all ECM messages.
 */
static int cfgmgr_ecm_doit_handler(struct sk_buff *skb, struct genl_info *info)
{
	struct cfgmgr_ctx *cmc = &cmc_ctx;
	struct cfgmgr_cmn_msg *cmn;
	struct cfgmgr_ecm_ipv4_msg *cfg_ecm_ipv4_msg __attribute__((unused));
	struct cfgmgr_ecm_ipv6_msg *cfg_ecm_ipv6_msg __attribute__((unused));
	cfgmgr_msg_cb_type_t cb;
	void *cb_data = NULL;
	uint32_t msg_type;

	cfgmgr_error("%px: Recieved dpfe to ecm msg from userspace\n", cmc);

	/*
	 * extract the message payload
	 */
	cmn = cfgmgr_base_get_msg(cmc, cmc->family, info);
	if (!cmn) {
		cfgmgr_error("%px: Unable to retrieve common message\n", cmc);
		return -EINVAL;
	}

	/*
	 * Not handling responses as of now.
	 * Add a check here if this is a response.
	 * Based on whether it is a response, you will call the callback (Lets see).
	 */
	cfgmgr_error("%px: cfgmgr_ecm_doit_handler() \n", cmn->cb);
	cb = cmn->cb;
	cb_data = cmn->cb_data;
	if (!cb) {
		cfgmgr_trace("%px: cb is NULL. Cannot raise a callback for interface %d", cmc, CFGMGR_INTERFACE_ECM);
		return 0;
	}

	/*
	 * Validate if we got the correct message type.
	 */
	msg_type = cfgmgr_base_cmn_msg_get_msg_type(cmn);
	if (msg_type >= CFGMGR_ECM_MSG_TYPE_MAX) {
		cfgmgr_error("%px: Invalid message %u received\n", cmc, msg_type);
		return -EINVAL;
	}

	/*
	 * Message validation required before accepting the configuration
	 */
	if (msg_type <= CFGMGR_ECM_MSG_TYPE_IPV4_STATS_SYNC_MANY) {
		cfgmgr_error("%px: About to call IPv4 callback\n", cmc);
		cfg_ecm_ipv4_msg = (struct cfgmgr_ecm_ipv4_msg *)cmn;
		cb((void *)cb_data, (void *)&cfg_ecm_ipv4_msg->dpfe_ipv4_msg);
	} else {
		cfg_ecm_ipv6_msg = (struct cfgmgr_ecm_ipv6_msg *)cmn;;
		cfgmgr_error("%px: About to call IPv6 callback\n", cmc);
		cb((void *)cb_data, (void *)&cfg_ecm_ipv6_msg->dpfe_ipv6_msg);
	}

	return 0;
}

/*
 * cfgmgr_ecm_register_handler
 *	Register a callback for any received ECM message.
 */
struct cfgmgr_ctx *cfgmgr_ecm_register_handler(cfgmgr_msg_cb_type_t cb, void *cb_data)
{
	struct cfgmgr_ctx *cmc = cfgmgr_base_get_ctx();
	cfgmgr_status_t status;

	status = cfgmgr_register_msg_handler(cmc, CFGMGR_INTERFACE_ECM, cb, cb_data);
	if (status != CFGMGR_STATUS_SUCCESS) {
		cfgmgr_error("%px: Unable to register message handler for wifi\n", cmc);
		return NULL;
	}

	return cmc;
}
EXPORT_SYMBOL(cfgmgr_ecm_register_handler);

/*
 * cfgmgr_ecm_dpdk_init()
 *	This function initializes the ECM sub module in the Config Manager.
 */
void cfgmgr_ecm_init(struct cfgmgr_ctx *cmc, uint32_t ifnum)
{
	cfgmgr_register_doit(cmc, ifnum, cfgmgr_ecm_doit_handler);
}
