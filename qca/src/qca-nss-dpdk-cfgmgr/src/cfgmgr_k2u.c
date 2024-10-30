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

/*
 * cfgmgr_cmn_msg_init()
 *	Initialize common message.
 */
void cfgmgr_cmn_msg_init(struct cfgmgr_cmn_msg *ccm, uint16_t msg_len, uint32_t msg_type, void *cb, void *cb_data)
{
	ccm->version = CFGMGR_NL_MESSAGE_VERSION;
	ccm->msg_len = msg_len;
	ccm->msg_type = msg_type;

	ccm->cb = cb;
	ccm->cb_data = cb_data;
}
EXPORT_SYMBOL(cfgmgr_cmn_msg_init);

/*
 * cfgmgr_k2u_create_new_msg()
 *	Create a new Netlink message.
 */
static struct sk_buff *cfgmgr_k2u_create_new_msg(struct genl_family *family, uint32_t m_size, uint8_t cmd, uint32_t pid)
{
	struct cfgmgr_cmn_msg *cmn;
	struct sk_buff *skb;
	uint32_t buf_len;

	/*
	 * Total size of the message and allocate new message.
	 */
	buf_len = m_size + family->hdrsize;
	skb = genlmsg_new(buf_len, GFP_ATOMIC);
	if (!skb) {
		cfgmgr_error("%s: unable to allocate notifier SKB\n", family->name);
		return NULL;
	}

	/*
	 * append the generic message header
	 */
	cmn = genlmsg_put(skb, pid, 0, family, 0, cmd);
	if (!cmn) {
		cfgmgr_error("%s: no space to put generic header\n", family->name);
		nlmsg_free(skb);
		return NULL;
	}

	/*
	 * Kernel PID is 0 by default.
	 */
	cmn->pid = pid;

	return skb;
}

/*
 * cfgmgr_k2u_msg_send()
 *	Send a multicast message.
 */
int cfgmgr_k2u_msg_send(struct cfgmgr_send_info *info, struct cfgmgr_cmn_msg *cmn, uint32_t m_size)
{
	struct cfgmgr_ctx *cmc = &cmc_ctx;
	struct sk_buff *skb;
	void *msg_data = NULL;
	int ret = 0;

	if ((info->ifnum < CFGMGR_INTERFACE_CORE) || (info->ifnum >= CFGMGR_INTERFACE_MAX)) {
		cfgmgr_error("%px: Invalid ifnum %u\n", cmc, info->ifnum);
		return CFGMGR_STATUS_ERROR;
	}

	skb = cfgmgr_k2u_create_new_msg(cmc->family, m_size, info->ifnum, info->pid);
	if (!skb) {
		cfgmgr_error("%px: Unable to allocate buffer for sending from kernel to user\n", cmc);
		return CFGMGR_STATUS_ERROR;
	}

	msg_data = cfgmgr_get_data(skb);
	if (!msg_data) {
		cfgmgr_error("%px: Unable to retrieve the message data from skb\n", cmc);
		goto err;
	}

	ret = nla_put_nohdr(skb, m_size, (void *)cmn);
	if (ret < 0) {
		cfgmgr_error("%px: Not able to add the attribute or type %d to NL message\n", cmc, cmn->msg_type);
		goto err;
	}

	genlmsg_end(skb, msg_data);

	cfgmgr_trace("%px: Sending message with skb %px, length %d, pid %d, ifnum %d\n", cmc, skb, m_size, info->pid, info->ifnum);
	cfgmgr_msgdump(skb->data, GENL_HDRLEN + NLMSG_HDRLEN + m_size, false, false);

	if (info->flags & CFGMGR_K2U_SEND_INFO_RESPONSE) {
		struct net *net = (struct net *)info->resp_sock_data;
		if (!net) {
			cfgmgr_error("%px: socket data to send unicast message is NULL.\n", cmc);
			goto err;
		}

		ret = genlmsg_unicast(net, skb, info->pid);
		if (ret) {
			cfgmgr_error("%px: error %d, Unable to send Unicast message to pid %u\n", cmc, ret, info->pid);
			goto err;
		}
	} else {
		ret = genlmsg_multicast(cmc->family, skb, cmn->pid, 0, GFP_ATOMIC);
		if (ret) {
			cfgmgr_error("%px: error %d, Unable to send multicast message from pid %u.\n", cmc, ret, cmn->pid);
			goto err;
		}
	}

	return CFGMGR_STATUS_SUCCESS;

err:
	nlmsg_free(skb);
	return CFGMGR_STATUS_ERROR;
}

// /*
//  * cfgmgr_k2u_send_ack()
//  *	allocate netlink skb and send ACK to user space NULL ack means failure.
//  */
// int cfgmgr_k2u_send_ack(struct cfgmgr_cmn_msg *cm_cmn, char *ackmsg, int ack)
// {
// 	struct cfgmgr_ctx *cmc = &cmc_ctx;
// 	struct cfgmgr_cmn_msg *pcm;
// 	struct sk_buff *skb;

// 	cm_cmn->msg_type = CFGMGR_K2U_MSG_TYPE_ACK;
// 	skb = cfgmgr_k2u_create_new_msg(cmc->family, 0, CFGMGR_K2U_MSG_TYPE_ACK, cm_cmn->pid);
// 	if (!skb) {
// 		cfgmgr_error("OOM ack2usr\n");
// 		return -ENOMEM;
// 	}

// 	genlmsg_end(skb, pcm);

// 	// Should be unicast.
// 	return genlmsg_multicast(cmc->family, skb, pcm->pid, 0, GFP_ATOMIC);
// 	// return genlmsg_unicast(pcm->net, skb, pcm->pid);
// }
