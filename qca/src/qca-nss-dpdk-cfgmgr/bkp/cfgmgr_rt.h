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
 * config manager for setting up netlink channle, gettting routing info, and
 * configuring / managing routing tables.
 *
 * This file is shared between kenel and user space.
 */

#ifndef	__KERNEL__
#include <pthread.h>
#endif

/*
 * DPDK Netlink configuration parameter for IPC between kernel and user space
 */

/*
 * Notice: general netlink message
 */

/*
 * msg_id for pp_dpdk_xx_msg (sub commands)
 */
/**
 * @brief netlink channel setup
 */
enum cm_nl_setup {
	CM_NL_ERR = -1,
	CM_NL_NOACT,	/**< nothing to be done */
	CM_NL_SET,	/**< setup netlink chanel for PP_KNL_FAMILY */
	CM_NL_UNSET,	/**< unset netlink chanel for PP_KNL_FAMILY */
};

#ifdef	__KERNEL__

extern int __net_init pp_dpdk_post_rt_init(struct net *net);
extern void __net_exit pp_dpdk_post_rt_exit(struct net *net);
extern struct cfgmgr_cmn_msg *pp_get_userinfo(void);

#else

/**
 * @brief DPDK netlink context header for both kernel and user space
 */
struct pp_dpdk_nl_ctx {
	struct cfgmgr_rtmsg *pdlm;	/**< common msg for IPC */
	const char *family_name; /**< set to genl_family.name */
	const char *group_name;	/**< for group IPC */
	void *msg;		/**< message pointer */

	uint32_t family_id;	/**< derived from genl_family.name */
	int32_t gid;		/**< group ID: pid is in ccm */
	uint32_t version;	/**< DPDK NL ID */

	/**<
	 * This is generic structure for all
	 * because kernel and user space have different struct content,
	 * each party convert to their own structure pointers.
	 */
	int s_fd;		/**< socket descriptor */
	pthread_t thr;		/**< for nl_cb */
	void *nl_sock;		/**< struct nl_sock */
	void *nl_cb;		/**< nl call back function allocated for nl_sock */
	void *arg;		/**< call back function argument */
	void *user;		/**< user speficic data if any */
};

#endif
