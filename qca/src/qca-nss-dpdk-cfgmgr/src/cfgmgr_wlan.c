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

#include "cfgmgr_base.h"

/*
 * cfgmgr_wlan_doit_handler()
 *	WLAN rx message handler for all WLAN messages.
 */
static int cfgmgr_wlan_doit_handler(struct sk_buff *skb,
				struct genl_info *info)
{
	struct cfgmgr_ctx *cmc = cfgmgr_base_get_ctx();
	struct cfgmgr_cmn_msg *cmn;
	cfgmgr_msg_cb_type_t cb;
	void *cb_data = NULL;

	/*
	 * extract the message payload
	 */
	cmn = cfgmgr_base_get_msg(cmc, cmc->family, info);
	if (!cmn) {
		cfgmgr_error("%px: NULL cmn header! abort\n", cmc);
		return -EINVAL;
	}

	/*
	 * Deliver the msg to wlan driver.
	 */
	cb = cfgmgr_base_get_msg_cb(cmc, CFGMGR_INTERFACE_WLAN);
	cb_data = cfgmgr_base_get_msg_cb_data(cmc, CFGMGR_INTERFACE_WLAN);
	if (!cb) {
		cfgmgr_error("%px: NULL cb!, abortr\n", cmc);
		return 0;
	}

	/*
	* If a message needs a response, the response will be send inline
	* from the wlan driver.
	*/
	cb(cmn, (void *)cb_data);
	return 0;
}

/*
 * cfgmgr_wlan_send_msg()
 *	Send a wlan driver msg to the userspace.
 */
cfgmgr_status_t cfgmgr_wlan_send_msg(struct cfgmgr_cmn_msg *cmn,
				     uint32_t msg_len, uint32_t msg_type)
{
	struct cfgmgr_send_info send_info = {0};
	int status;

	cfgmgr_cmn_msg_init(cmn, msg_len, msg_type, NULL, NULL);

	/*
	* TODO: cfgmgr doesn't have support to send unicast resposne now, once
	* available change this flag to send unicast response.
	*/
	send_info.flags |= CFGMGR_K2U_SEND_INFO_MULTICAST;
	send_info.resp_sock_data = cmn->sock_data;
	send_info.ifnum = CFGMGR_INTERFACE_WLAN;

	status = cfgmgr_k2u_msg_send(&send_info, cmn, msg_len);
	if (status != CFGMGR_STATUS_SUCCESS)
		cfgmgr_error("Failed to send wlan msg!\n");

	return status;
}
EXPORT_SYMBOL(cfgmgr_wlan_send_msg);

/*
 * cfgmgr_wlan_unregister_msg_handler
 *	Register a callback for any received if ( message.
 */
cfgmgr_status_t cfgmgr_wlan_unregister_msg_handler(void)
{
	struct cfgmgr_ctx *cmc = cfgmgr_base_get_ctx();
	cfgmgr_status_t status;

	status = cfgmgr_unregister_msg_handler(cmc, CFGMGR_INTERFACE_WLAN);
	if (status != CFGMGR_STATUS_SUCCESS)
		cfgmgr_error("%px: Failed to unregister message handler\n", cmc);

	return status;
}
EXPORT_SYMBOL(cfgmgr_wlan_unregister_msg_handler);

/*
 * cfgmgr_wlan_register_msg_handler
 *	Register a callback for any received WLAN message.
 */
cfgmgr_status_t cfgmgr_wlan_register_msg_handler(cfgmgr_msg_cb_type_t cb,
						void *cb_data)
{
	struct cfgmgr_ctx *cmc = cfgmgr_base_get_ctx();
	cfgmgr_status_t status;

	status = cfgmgr_register_msg_handler(cmc, CFGMGR_INTERFACE_WLAN,
						cb, cb_data);
	if (status != CFGMGR_STATUS_SUCCESS)
		cfgmgr_error("%px: Failed to unregister message handler\n", cmc);

	return status;
}
EXPORT_SYMBOL(cfgmgr_wlan_register_msg_handler);

/*
 * cfgmgr_wlan_init()
 *	This function initializes the WLAN sub module in the Config Manager.
 */
void cfgmgr_wlan_init(struct cfgmgr_ctx *cmc, uint32_t ifnum)
{
	cfgmgr_register_doit(cmc, ifnum, cfgmgr_wlan_doit_handler);
}
