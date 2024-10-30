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
#include <linux/debugfs.h>

#include "cfgmgr_base.h"
#include "cfgmgr_test.h"

uint32_t cfgmgr_send_msg = 0;

/*
 * cfgmgr_test_msg_init()
 *	Initialize a test message.
 */
void cfgmgr_test_msg_init(struct cfgmgr_test_msg *test_msg, uint32_t msg_type)
{
	cfgmgr_cmn_msg_init(&test_msg->cmn_msg, sizeof(struct cfgmgr_test_msg), msg_type, NULL, NULL);

	test_msg->rnd_id_1 = CFGMGR_RAND_ID_1;
	test_msg->rnd_id_2 = CFGMGR_RAND_ID_2;
	test_msg->rnd_id_3 = CFGMGR_RAND_ID_3;
}

/*
 * cfgmgr_send_test_msg()
 *	Send a test message
 */
cfgmgr_status_t cfgmgr_send_test_msg(struct cfgmgr_ctx *cmc, struct cfgmgr_send_info *info)
{
	struct cfgmgr_test_msg test_msg;
	int ret = 0;

	cfgmgr_test_msg_init(&test_msg, CFGMGR_TEST_MSG_TYPE_SIMPLE);

	ret = cfgmgr_k2u_msg_send(info, &test_msg.cmn_msg, sizeof(struct cfgmgr_test_msg));
	if (ret) {
		cfgmgr_error("%px: Unable to send the message.\n", cmc);
		return CFGMGR_STATUS_ERROR;
	}

	cfgmgr_trace("%px: Message of type %d sent.\n", cmc, CFGMGR_TEST_MSG_TYPE_SIMPLE);

	return CFGMGR_STATUS_SUCCESS;
}

/*
 * cfgmgr_send_test_loopback_msg()
 *	Send a test message
 */
cfgmgr_status_t cfgmgr_send_test_loopback_msg(struct cfgmgr_ctx *cmc, struct cfgmgr_send_info *info)
{
	struct cfgmgr_test_msg test_msg;
	int ret = 0;

	info->flags |= CFGMGR_K2U_SEND_INFO_MULTICAST;

	cfgmgr_test_msg_init(&test_msg, CFGMGR_TEST_MSG_TYPE_LOOPBACK);

	ret = cfgmgr_k2u_msg_send(info, &test_msg.cmn_msg, sizeof(struct cfgmgr_test_msg));
	if (ret) {
		cfgmgr_error("%px: Unable to send the message.\n", cmc);
		return CFGMGR_STATUS_ERROR;
	}

	cfgmgr_trace("%px: Message of type %d sent.\n", cmc, CFGMGR_TEST_MSG_TYPE_LOOPBACK);

	return CFGMGR_STATUS_SUCCESS;
}

/*
 * cfgmgr_test_rx_msg_handler()
 *	Test rx message handler for all test messages.
 */
static int cfgmgr_test_rx_msg_handler(struct cfgmgr_cmn_msg *cmn, void *cb_data)
{
	struct cfgmgr_ctx *cmc = &cmc_ctx;
	struct cfgmgr_test_msg *test_msg = (struct cfgmgr_test_msg *)cmn;
	struct cfgmgr_send_info send_info;

	cfgmgr_info_always("%px: Received a test message: rnd_id_1 %x, rnd_id_2 %x, rnd_id_3 %x\n",
				cmn, test_msg->rnd_id_1, test_msg->rnd_id_2, test_msg->rnd_id_3);

	/*
	 * Check which sub message type for the interface received.
	 */
	switch(cmn->msg_type) {
		case CFGMGR_TEST_MSG_TYPE_SIMPLE:
			break;

		case CFGMGR_TEST_MSG_TYPE_LOOPBACK:
			send_info.flags |= CFGMGR_K2U_SEND_INFO_RESPONSE;
			send_info.resp_sock_data = cmn->sock_data;
			send_info.pid = cmn->pid;
			send_info.ifnum = CFGMGR_INTERFACE_TEST;

			cfgmgr_send_test_msg(cmc, &send_info);
			break;

		default:
			cfgmgr_error("%px: Unknown type of msg.\n", cmn);
	}

	return 0;
}

static int cfgmgr_test_doit_handler(struct sk_buff *skb, struct genl_info *info)
{
	struct cfgmgr_ctx *cmc = &cmc_ctx;
	struct cfgmgr_cmn_msg *cmn;
	struct cfgmgr_test_msg *test_msg;
	cfgmgr_msg_cb_type_t cb;
	void *cb_data = NULL;
	uint32_t msg_type;

	/*
	 * extract the message payload
	 */
	cmn = cfgmgr_base_get_msg(cmc, cmc->family, info);
	if (!cmn) {
		cfgmgr_error("%px: Unable to retrieve common message\n", cmc);
		return -EINVAL;
	}

	msg_type = cfgmgr_base_cmn_msg_get_msg_type(cmn);
	if (msg_type < CFGMGR_TEST_MSG_TYPE_SIMPLE || msg_type >= CFGMGR_TEST_MSG_TYPE_MAX) {
		cfgmgr_error("%px: Invalid message %u received\n", cmc, msg_type);
		return -EINVAL;
	}

	/*
	 * Message validation required before accepting the configuration
	 */
	test_msg = container_of(cmn, struct cfgmgr_test_msg, cmn_msg);

	/*
	 * Not handling responses as of now.
	 * Add a check here if this is a response.
	 * Based on whether it is a response, you will call the callback (Lets see).
	 */
	cb = cfgmgr_base_get_msg_cb(cmc, CFGMGR_INTERFACE_TEST);
	cb_data = cfgmgr_base_get_msg_cb_data(cmc, CFGMGR_INTERFACE_TEST);
	if (!cb) {
		cfgmgr_trace("%px: cb is NULL. Cannot raise a callback for interface %d", cmc, CFGMGR_INTERFACE_TEST);
		return 0;
	}

	cb(&test_msg->cmn_msg, (void *)cb_data);

	return 0;
}

/*
 * cfgmgr_test_msg_callback()
 *	Send a test message to the Userspace.
 */
static int cfgmgr_test_msg_callback(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct cfgmgr_ctx *cmc = &cmc_ctx;
	struct cfgmgr_send_info info;
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!write) {
		return ret;
	}

	/*
	 * Send a cfgmgr basic message.
	 */
	if (cfgmgr_send_msg == 1) {
		cfgmgr_send_msg = 0;
		info.pid = 0;
		info.flags |= CFGMGR_K2U_SEND_INFO_MULTICAST;
		info.ifnum = CFGMGR_INTERFACE_TEST;
		cfgmgr_send_test_msg(cmc, &info);
	} else {
		cfgmgr_send_msg = 0;
	}

	return ret;
}

/*
 * cfgmgr_sub
 *	Config Manager sub directory
 */
static struct ctl_table cfgmgr_sub[] = {
	{
		.procname	=	"cfgmgr_send_msg",
		.data		=	&cfgmgr_send_msg,
		.maxlen		=	sizeof(int),
		.mode		=	0644,
		.proc_handler	=	cfgmgr_test_msg_callback,
	},
	{}
};

/*
 * cfgmgr_main
 *	Config Manager main directory
 */
static struct ctl_table cfgmgr_main[] = {
	{
		.procname	=	"cfgmgr",
		.mode		=	0555,
		.child		=	cfgmgr_sub,
	},
	{}
};

/*
 * cfgmgr_root
 *	Config Manager root directory
 */
static struct ctl_table cfgmgr_root[] = {
	{
		.procname	=	"dpdk",
		.mode		=	0555,
		.child		=	cfgmgr_main,
	},
	{}
};

/*
 * cfgmgr_ecm_test_init
 */
void cfgmgr_test_deinit(struct cfgmgr_ctx *cmc)
{
	unregister_sysctl_table(cmc->cmc_header);
}

/*
 * cfgmgr_ecm_test_init
 */
void cfgmgr_test_init(struct cfgmgr_ctx *cmc, uint32_t ifnum)
{
	cfgmgr_status_t status;

	/*
	 * Register sysctl framework for PPE DRV
	 */
	cmc->cmc_header = register_sysctl_table(cfgmgr_root);
	if (!cmc->cmc_header) {
		cfgmgr_warn("sysctl table configuration failed");
	}

	cfgmgr_register_doit(cmc, ifnum, cfgmgr_test_doit_handler);

	status = cfgmgr_register_msg_handler(cmc, ifnum, cfgmgr_test_rx_msg_handler, NULL);
	if (status != CFGMGR_STATUS_SUCCESS) {
		cfgmgr_error("%px: Unable to register message handler for test\n", cmc);
		return;
	}

	cfgmgr_info_always("%px: Initialized test interface\n", cmc);
}