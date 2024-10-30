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

/*
 * config manager kernel netlink module
 */

//#include <linux/of.h>
#include "cfgmgr_base.h"
#include "cfgmgr_test.h"

struct cfgmgr_ctx cmc_ctx;

#if (CFGMGR_DEBUG_LEVEL == 4)
/*
 * cfgmgr_msgdump
 *	Dump Config Manager Netlink message sent.
 *
 * Dump the message going per header ony by one.
 * 1. NLHDR, 2. GENLHDR, 3. Generic data after this.
 */
void cfgmgr_msgdump(void *buf, int len, int nl_hdr_print, bool enable)
{
	char *p = NULL;
	int ln;

	if (!enable) {
		return;
	}

	/*
	 * Print header wise info of the netlink message.
	 */
	printk("Print the netlink Message at buf %px, len %d\n", buf, len);
	if (nl_hdr_print) {
		struct nlmsghdr *nlh = buf;
		struct genlmsghdr *gnlh = NULL;
		printk("NL Header:\n");
		if (len >= NLMSG_HDRLEN) {
			printk("\tLen: %x\n\tType: %x\n\tFlags: %x\n\tSequence Number: %x\n\tPID: %x\n\n",
				nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);
		}

		gnlh = nlmsg_data(nlh);
		printk("GENL Header:\n");
		if (len >= GENL_HDRLEN) {
			printk("\tCmd: %x\n\tVersion: %x\n\n", gnlh->cmd, gnlh->version);
		}

	}

	ln = len >> 4;
	p = buf;
	printk("Data:\n");
	while (ln--) {
		printk("%3d: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ln,
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		p += 16;
	}

	printk("\n");
	ln = len >> 4;
	p = buf;
	while (ln--) {
		printk("%3d: %c %c %c %c %c %c %c %c %c %c %c %c %c %c %c %c\n", ln,
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		p += 16;
	}
}
#else
void cfgmgr_msgdump(void *buf, int len, int nl_hdr_print, bool enable)
{
}
#endif

/*
 * cfgmgr_base_cmn_msg_get_msg_len()
 *	Get the common message length
 */
uint16_t cfgmgr_base_cmn_msg_get_msg_len(struct cfgmgr_cmn_msg *cmn)
{
	return cmn->msg_len;
}

/*
 * cfgmgr_base_cmn_msg_get_msg_type()
 *	Get the common message type
 */
uint32_t cfgmgr_base_cmn_msg_get_msg_type(struct cfgmgr_cmn_msg *cmn)
{
	return cmn->msg_type;
}

/*
 * cfgmgr_copy_msg()
 *	copy a existing NETLINK message into a new one
 *
 * NOTE: this returns the new SKB/message
 */
struct sk_buff *cfgmgr_copy_msg(struct sk_buff *orig)
{
	struct sk_buff *copy;
	struct cfgmgr_cmn_msg *cm_cmn;

	cm_cmn = cfgmgr_get_data(orig);

	copy = skb_copy(orig, GFP_KERNEL);
	if (!copy) {
		cfgmgr_error("%px: pid %d, unable to copy incoming message of len(%d)\n", cm_cmn, cm_cmn->pid, orig->len);
		return NULL;
	}

	return copy;
}

/*
 * cfgmgr_base_ops_default()
 *	Receive a routing handling request message.
 */
static int cfgmgr_base_ops_default(struct sk_buff *skb, struct genl_info *info)
{
	cfgmgr_info_always("Invoked default message handler, buffer %px\n", skb);
	return 0;
}

/*
 * cfgmgr_unregister_msg_handler()
 *	Unregister a callback for receiving the message to an appropriate dependent interface.
 */
cfgmgr_status_t cfgmgr_unregister_msg_handler(struct cfgmgr_ctx *cmc, uint32_t ifnum)
{
	uint32_t idx = cfgmgr_base_get_idx_from_ifnum(ifnum);

	/*
	 * Validate ifnum
	 */
	if (ifnum >= CFGMGR_INTERFACE_MAX) {
		cfgmgr_error("%px: Error - Interface %d not Supported\n", cmc, ifnum);
		return CFGMGR_STATUS_ERROR;
	}

	cmc->msg_cb_list[idx].cb = NULL;

	return CFGMGR_STATUS_SUCCESS;
}

/*
 * cfgmgr_register_msg_handler()
 *	Register for receiving a message to an appropriate dependent interface.
 */
cfgmgr_status_t cfgmgr_register_msg_handler(struct cfgmgr_ctx *cmc, uint32_t ifnum, cfgmgr_msg_cb_type_t cb, void *cb_data)
{
	uint32_t idx = cfgmgr_base_get_idx_from_ifnum(ifnum);

	/*
	 * Validate ifnum
	 */
	if (ifnum >= CFGMGR_INTERFACE_MAX) {
		cfgmgr_warn("%px: Error - Interface %d not Supported\n", cmc, ifnum);
		return CFGMGR_STATUS_ERROR;
	}

	/*
	 * Check if already registered
	 */
	if (cmc->msg_cb_list[idx].cb != NULL) {
		cfgmgr_warn("%px: Error - Duplicate Interface CB Registered for interface %d\n", cmc, ifnum);
		return CFGMGR_STATUS_ERROR;
	}

	cmc->msg_cb_list[idx].cb = cb;
	cmc->msg_cb_list[idx].cb_data = cb_data;

	return CFGMGR_STATUS_SUCCESS;
}

/*
 * cfgmgr_base_get_msg()
 *      verifies and returns the message header
 */
struct cfgmgr_cmn_msg *cfgmgr_base_get_msg(struct cfgmgr_ctx *cmc, struct genl_family *family, struct genl_info *info)
{
	struct cfgmgr_cmn_msg *cmn;
	uint32_t pid;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0))
	pid =  info->snd_pid;
#else
	pid =  info->snd_portid;
#endif
	/*
	 * validate the common message header version & magic
	 */
	cmn = info->userhdr;
	if (cmn->version != CFGMGR_NL_MESSAGE_VERSION || family->version != CFGMGR_NL_FAMILY_VER) {
		cfgmgr_error("%u, %s: version mismatch %d (%d)\n", pid, family->name, family->version, cmn->version);
		return NULL;
	}

	cmn->pid = pid;
	cmn->sock_data = (dpdk_ptr_t)genl_info_net(info);

	/*
	 * Dump the common message
	 */
	cfgmgr_msgdump(cmn, cmn->msg_len, false, false);

	cfgmgr_info_always("%px: Common message: pid: %u, version %u, length %u, msg_type %d\n",
				cmc, cmn->pid, cmn->version, cmn->msg_len, cmn->msg_type);
	return cmn;
}

/*
 * multicast group for sending message status & events
 */
static const struct genl_multicast_group cfgmgr_base_nl_mcgrp[] = {
	{
		.name = CFGMGR_NL_MCAST_GRP
	},
};

/*
 * cfgmgr_nl_ops
 *	Netlink ops (cmd and callback) for different messages
 *
 * Default ops are changed later based on the subsystem.
 */
static struct genl_ops cfgmgr_base_rx_nl_ops[] = {
	{ .cmd = CFGMGR_INTERFACE_CORE, .doit = cfgmgr_base_ops_default, },
	{ .cmd = CFGMGR_INTERFACE_ECM, .doit = cfgmgr_base_ops_default, },
	{ .cmd = CFGMGR_INTERFACE_WLAN, .doit = cfgmgr_base_ops_default, },
	{ .cmd = CFGMGR_INTERFACE_TUNNEL, .doit = cfgmgr_base_ops_default, },
	{ .cmd = CFGMGR_INTERFACE_TEST, .doit = cfgmgr_base_ops_default, },

};

static struct genl_family cfgmgr_base_nl_family = {
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 9, 0))
	.id = GENL_ID_GENERATE,				/* Auto generate ID */
#endif

	.name = CFGMGR_NL_FAMILY_NAME,			/* family name string */
	.hdrsize = 0,					/* Hdr size is 0 since no common header is needed. */
	.version = CFGMGR_NL_FAMILY_VER,
	// .maxattr = CFGMGR_U2K_MSG_TYPE_MAX,		/* maximum message types supported */
	.netnsok = true,
	.pre_doit = NULL,
	.post_doit = NULL,
	.ops = cfgmgr_base_rx_nl_ops,				/* Netlink ops */
	.n_ops = ARRAY_SIZE(cfgmgr_base_rx_nl_ops),		/* Number of ops */
	.mcgrps = cfgmgr_base_nl_mcgrp,
	.n_mcgrps = ARRAY_SIZE(cfgmgr_base_nl_mcgrp)
};

/*
 * cfgmgr_unregister_doit()
 *	Unregister a callback for receiving the message to an appropriate dependent interface.
 */
cfgmgr_status_t cfgmgr_unregister_doit(struct cfgmgr_ctx *cmc, uint32_t ifnum)
{
	struct genl_family *family = cmc->family;
	uint32_t n_ops = family->n_ops;
	uint32_t idx = cfgmgr_base_get_idx_from_ifnum(ifnum);

	/*
	 * Check registration interface.
	 */
	if (idx >= n_ops) {
		cfgmgr_warn("%px: Invalid interface number received %d", cmc, ifnum);
		return CFGMGR_STATUS_ERROR;
	}

	/*
	 * Update with default do it callback.
	 */
	cfgmgr_base_rx_nl_ops[idx].doit = cfgmgr_base_ops_default;

	return CFGMGR_STATUS_SUCCESS;
}

/*
 * cfgmgr_register_doit()
 *	Register for receiving a message to an appropriate dependent interface.
 */
cfgmgr_status_t cfgmgr_register_doit(struct cfgmgr_ctx *cmc, uint32_t ifnum, cfgmgr_base_doit_type_t doit)
{
	struct genl_family *family = cmc->family;
	uint32_t n_ops = family->n_ops;
	uint32_t idx = cfgmgr_base_get_idx_from_ifnum(ifnum);

	/*
	 * Check registration interface.
	 */
	if (idx >= n_ops) {
		cfgmgr_warn("%px: Invalid interface number received %d", cmc, ifnum);
		return CFGMGR_STATUS_ERROR;
	}

	cfgmgr_base_rx_nl_ops[idx].doit = doit;
	return CFGMGR_STATUS_SUCCESS;
}

/*
 * cfgmgr_init()
 *	Config Manager module init.
 */
static int __init cfgmgr_base_init(void)
{
	int ret;
	struct cfgmgr_ctx *cmc = &cmc_ctx;

	cmc->family = &cfgmgr_base_nl_family;

	/*
	 * Register test interface.
	 */
	cfgmgr_test_init(cmc, CFGMGR_INTERFACE_TEST);

	/*
	 * Register ECM interface.
	 */
	cfgmgr_ecm_init(cmc, CFGMGR_INTERFACE_ECM);

	/*
	 * Register WIFI interface.
	 */
	cfgmgr_wlan_init(cmc, CFGMGR_INTERFACE_WLAN);

	/*
	 * Register Config interface.
	 */
	cfgmgr_core_init(cmc);

	/*
	 * Register netlink family
	 */
	ret = genl_register_family(cmc->family);
	if (ret) {
		cfgmgr_error("Unable to register DPDK family, err %d\n", ret);
		return ret;
	}

	cfgmgr_info_always("Register netlink family %s ver %d, family id %d, family hdrsize %d\n",
				cfgmgr_base_nl_family.name,
				cfgmgr_base_nl_family.version,
				cfgmgr_base_nl_family.id,
				cfgmgr_base_nl_family.hdrsize);
	cfgmgr_info_always("Config Manager module loaded\n");

	return 0;
}

/*
 * cfgmgr_exit()
 *	Config Manager module exit.
 */
static void __exit cfgmgr_base_exit(void)
{
	int ret;
	struct cfgmgr_ctx *cmc = &cmc_ctx;

	cfgmgr_test_deinit(cmc);

	/*
	 * Unregister the netlink family
	 */
	ret = genl_unregister_family(cmc->family);
	if (ret) {
		cfgmgr_info_always("Unable to unregister DPDK NETLINK family\n");
	}

#ifdef CM_POST_RT
	pp_dpdk_post_rt_exit(&init_net);
#endif

	cfgmgr_info_always("%px: Netlink family unregister %s ver %d\n",
				cmc, cfgmgr_base_nl_family.name, cfgmgr_base_nl_family.version);
	cfgmgr_info_always("Config manager module unloaded\n");
}

module_init(cfgmgr_base_init);
module_exit(cfgmgr_base_exit);

MODULE_DESCRIPTION("DPDK Config Manager");
MODULE_LICENSE("Dual BSD/GPL");