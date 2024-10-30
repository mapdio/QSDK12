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

#include <linux/netlink.h>
#include <linux/types.h>
#include <linux/version.h>
#include <net/genetlink.h>
#include <linux/if.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <linux/rcupdate.h>

#include <net/netfilter/nf_conntrack.h>

#include <cfgmgr_api_if.h>
#include "cfgmgr_k2u.h"

/*
 * 1. Priority for messages.
 * 2. Scatter Gather messages.
 */

extern struct cfgmgr_ctx cmc_ctx;

#define CFGMGR_FLAG_DPFE_ACTIVE			0x00000001
#define CFGMGR_FLAG_POST_ROUTE_ENABLED		0x00000002

/*
 * If dynamic debug is enabled, use pr_debug.
 */
#if defined(CONFIG_DYNAMIC_DEBUG)
#define cfgmgr_error(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define cfgmgr_warn(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define cfgmgr_info(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define cfgmgr_trace(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else

#if (CFGMGR_DEBUG_LEVEL < 1)
#define cfgmgr_error(s, ...)
#else
#define cfgmgr_error(s, ...) pr_error("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

/*
 * Statically compile messages at different levels, when dynamic debug is disabled.
 */
#if (CFGMGR_DEBUG_LEVEL < 2)
#define cfgmgr_warn(s, ...)
#else
#define cfgmgr_warn(s, ...) pr_warn("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#if (CFGMGR_DEBUG_LEVEL < 3)
#define cfgmgr_info(s, ...)
#else
#define cfgmgr_info(s, ...) pr_notice("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#if (CFGMGR_DEBUG_LEVEL < 4)
#define cfgmgr_trace(s, ...)
#define cfgmgr_assert(c, s, ...)
#else
#define cfgmgr_trace(s, ...) pr_info("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define cfgmgr_assert(c, s, ...) if (!(c)) { printk(KERN_CRIT "%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__); BUG_ON(!(c)); }
#endif
#endif

#define cfgmgr_info_always(s, ...) pr_info("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define	CFGMGR_NL_MESSAGE_VERSION	1
#define CFGMGR_NL_FAMILY_VER		7281991
#define CFGMGR_NL_MCAST_GRP		"cfgmgr_mcast"
#define CFGMGR_NL_FAMILY_NAME		"cfgmgr_dpdk"

/*
 * cfgmgr_interface
 *	Interface is used to receive messages from the socket registered directly
 */
enum cfgmgr_interface {
	CFGMGR_INTERFACE_CORE = 17,		/* Messages destined for local interface */
	CFGMGR_INTERFACE_ECM,			/* ECM module hooking into the cfgmgr interface */
	CFGMGR_INTERFACE_WLAN,			/* WIFI module hooking into the cfgmgr interface */
	CFGMGR_INTERFACE_TUNNEL,
	CFGMGR_INTERFACE_TEST,			/* Test interface to verify test messages */
	CFGMGR_INTERFACE_MAX,
};

/*
 * cfgmgr_base_doit_type_t
 *	Doit handler type
 */
typedef int (*cfgmgr_base_doit_type_t)(struct sk_buff *skb, struct genl_info *info);

/*
 * cfgmgr_msg_cb_list
 *	List of the callbacks registered in the config manager.
 */
struct cfgmgr_msg_cb_list {
	cfgmgr_msg_cb_type_t cb;		/* Callback to return back the data. */
	void *cb_data;				/* Callback's registered data */
};

#define CFGMGR_PORT_CNT	6

/*
 * cfgmgr_interface_data
 *	Interface data in cfgmgr coming from DPFE client.
 */
struct cfgmgr_interface_data {
	uint8_t port;
	uint8_t interface_num;
	struct net_device *netdev;
};

/*
 * cfgmgr_ctx
 *	Main structure for config manager
 */
struct cfgmgr_ctx {
	struct genl_family *family;		/* May be different families */
	struct ctl_table_header *cmc_header;	/* Sysctl */
	struct net *net;			/* socket info, used by kernel */
	uint32_t flags;				/* Config Manager flags */

	struct cfgmgr_msg_cb_list msg_cb_list[CFGMGR_INTERFACE_MAX - CFGMGR_INTERFACE_CORE];

	struct cfgmgr_interface_data intf_data[CFGMGR_PORT_CNT];	/* Mapping of the netdevice and the DPFE interface numbers */
};

/*
 * cfgmgr_base_get_idx_from_ifnum()
 */
static uint32_t cfgmgr_base_get_idx_from_ifnum(uint32_t ifnum)
{
	return (ifnum - CFGMGR_INTERFACE_CORE);
}

/*
 * cfgmgr_base_get_msg_cb()
 *	Get the message callback.
 */
static inline cfgmgr_msg_cb_type_t cfgmgr_base_get_msg_cb(struct cfgmgr_ctx *cmc, uint32_t ifnum)
{
	return cmc->msg_cb_list[cfgmgr_base_get_idx_from_ifnum(ifnum)].cb;
}

/*
 * cfgmgr_base_get_msg_cb_data()
 *	Get the callback data.
 */
static inline cfgmgr_msg_cb_type_t cfgmgr_base_get_msg_cb_data(struct cfgmgr_ctx *cmc, uint32_t ifnum)
{
	return cmc->msg_cb_list[cfgmgr_base_get_idx_from_ifnum(ifnum)].cb_data;
}

/*
 * cfgmgr_base_get_ctx()
 *	Get Config manager context.
 */
static inline struct cfgmgr_ctx *cfgmgr_base_get_ctx(void)
{
	return &cmc_ctx;
}

/*
 * cfgmgr_get_data()
 *	Returns start of payload data
 */
static inline void *cfgmgr_get_data(struct sk_buff *skb)
{
	return genlmsg_data(NLMSG_DATA(skb->data));
}

/*
 * cfgmgr_set_dpfe_active()
 *	Set DPFE status as active.
 */
static inline void cfgmgr_set_dpfe_active(struct cfgmgr_ctx *cmc)
{
	cmc->flags |= CFGMGR_FLAG_DPFE_ACTIVE;
}

/*
 * cfgmgr_is_dpfe_active()
 *	Get DPFE active status.
 */
static inline bool cfgmgr_is_dpfe_active(struct cfgmgr_ctx *cmc)
{
	return (cmc->flags & CFGMGR_FLAG_DPFE_ACTIVE);
}

/*
 * cfgmgr_post_route_set_inactive()
 *	Set post route functionality as active.
 */
static inline void cfgmgr_post_route_set_inactive(struct cfgmgr_ctx *cmc)
{
	cmc->flags &= ~CFGMGR_FLAG_POST_ROUTE_ENABLED;
}

/*
 * cfgmgr_post_route_set_active()
 *	Set post route functionality as active.
 */
static inline void cfgmgr_post_route_set_active(struct cfgmgr_ctx *cmc)
{
	cmc->flags |= CFGMGR_FLAG_POST_ROUTE_ENABLED;
}

/*
 * cfgmgr_post_route_is_active()
 *	Get post route enabled status.
 */
static inline bool cfgmgr_post_route_is_active(struct cfgmgr_ctx *cmc)
{
	return (cmc->flags & CFGMGR_FLAG_POST_ROUTE_ENABLED);
}

extern uint16_t cfgmgr_base_cmn_msg_get_msg_len(struct cfgmgr_cmn_msg *cmn);
extern uint32_t cfgmgr_base_cmn_msg_get_msg_type(struct cfgmgr_cmn_msg *cmn);

extern cfgmgr_status_t cfgmgr_unregister_doit(struct cfgmgr_ctx *cmc, uint32_t ifnum);
extern cfgmgr_status_t cfgmgr_register_doit(struct cfgmgr_ctx *cmc, uint32_t ifnum, cfgmgr_base_doit_type_t doit);

extern cfgmgr_status_t cfgmgr_unregister_msg_handler(struct cfgmgr_ctx *cmc, uint32_t ifnum);
extern cfgmgr_status_t cfgmgr_register_msg_handler(struct cfgmgr_ctx *cmc, uint32_t ifnum, cfgmgr_msg_cb_type_t cb, void *cb_data);

/*
 * Individual interface initializers
 */
extern void cfgmgr_test_deinit(struct cfgmgr_ctx *cmc);
extern void cfgmgr_test_init(struct cfgmgr_ctx *cmc, uint32_t ifnum);

extern void cfgmgr_ecm_deinit(struct cfgmgr_ctx *cmc);
extern void cfgmgr_ecm_init(struct cfgmgr_ctx *cmc, uint32_t ifnum);

extern void cfgmgr_wlan_deinit(struct cfgmgr_ctx *cmc);
extern void cfgmgr_wlan_init(struct cfgmgr_ctx *cmc, uint32_t ifnum);

extern void cfgmgr_core_deinit(struct cfgmgr_ctx *cmc);
extern void cfgmgr_core_init(struct cfgmgr_ctx *cmc);

extern struct cfgmgr_cmn_msg *cfgmgr_base_get_msg(struct cfgmgr_ctx *cmc, struct genl_family *family, struct genl_info *info);
extern void cfgmgr_msgdump(void *buf, int len, int nl_hdr_print, bool enable);
