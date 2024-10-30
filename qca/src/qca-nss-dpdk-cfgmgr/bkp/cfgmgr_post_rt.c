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

#ifndef	CM_POST_RT
#define	CM_POST_RT
#include <linux/module.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include <linux/inetdevice.h>

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <linux/rcupdate.h>

#include <net/netfilter/nf_conntrack.h>

#include "cfgmgr_base.h"

static void pp_dpdk_nl_recv_msg(struct sk_buff *skb) {
	struct nlmsghdr *nlh;
	struct dst_entry *de;
	struct sk_buff *skb_out;
	struct cfgmgr_rtmsg *pdrm;
	struct cfgmgr_cmn_msg *pn;
	int pid, ret;
	struct cfgmgr_ctx *cm = &cm_ctx;

	cfgmgr_trace("Entering %s: %px sk %px %px nf %px %px\n", __FUNCTION__, skb,
		init_net.rtnl, init_net.genl_sock, init_net.nfnl, init_net.nfnl_stash);

	nlh = (struct nlmsghdr*)skb->data;
	pid = nlh->nlmsg_pid; /*pid of sending process */

	pdrm = genlmsg_data(nlmsg_data(nlh));
	pn = pp_get_userinfo();

	if (nlh->nlmsg_len > 2 * sizeof(*pdrm)) {
		if (nlh->nlmsg_len < 263938)
		cfgmgr_warn("%d bad msg %d %d opid %x\n", nlh->nlmsg_len,
			pdrm->msg_id, pdrm->ccm.msg_type, pn->pid);
		return;
	}
	if (pdrm->ccm.version != CFGMGR_NL_MESSAGE_VERSION) {
		cfgmgr_warn("0x%x not DPD RT msg %d %d opid 0x%x pid 0x%x\n", pdrm->ccm.version,
			pdrm->msg_id, pdrm->ccm.msg_type, pn->pid, pdrm->ccm.pid);
		return;
	}
	cfgmgr_info("%x %x Netlink received msg len: %d\n", pid, pn->pid, nlh->nlmsg_len);

	skb_out = pp_nl_create_new_msg(cm->u2k_family, KNL_MSG_ACK, pn->pid);
	if (!skb_out) {
		DEBUG_ERROR("Failed to allocate new skb\n");
		return;
	}
	cfgmgr_trace("skb out data %px head %px tail %u\n", skb_out->data, skb_out->head, skb_out->tail);

	nlh = (struct nlmsghdr *)skb_tail_pointer(skb_out);
	pdrm = genlmsg_data(nlmsg_data(nlh));

	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

	de = skb_dst(skb);
	if (de) {
		cfgmgr_trace("de %px dev %px %s\n", de, de->dev, de->dev->name);
		if (de->dev->name)
			strlcpy(pdrm->devname, de->dev->name, sizeof(pdrm->devname));
	} else {
		strlcpy(pdrm->devname, "no PDST", sizeof(pdrm->devname));
	}
	genlmsg_end(skb_out, pdrm);

	ret = nlmsg_unicast(init_net.genl_sock, skb_out, pn->pid);
	if (ret < 0) {
		DEBUG_ERROR("Error %d while sending to user %px %d (%d)\n", ret,
				init_net.genl_sock, pn->pid, pid);
	}
}

/*
 * dpdk_ipv4_ip_process()
 *	Process IP datagram skb
 */
static unsigned int dpdk_ipv4_ip_process(struct net_device *out_dev, struct net_device *in_dev,
				 struct sk_buff *skb, bool is_routed, bool is_l2_encap)
{
	struct in_ifaddr *ifa;
	struct cfgmgr_rtmsg	pdrm, *pdrmp;
	struct tcphdr *th;
	struct udphdr *uh;
	char hdrbuf[128];
	int hdr_len;
	struct cfgmgr_ctx *cm = &cm_ctx;

#ifdef NEED_NF_CT
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

#endif
	struct iphdr *v4_hdr = skb_header_pointer(skb, 0, sizeof(*v4_hdr), hdrbuf);
	if (!v4_hdr || v4_hdr->version != 4) {
		cfgmgr_trace("%px %px: skb: %px is NOT ipv4\n", v4_hdr, &hdrbuf, skb);
		return NF_ACCEPT;
	}
#ifdef	NEED_NF_CT
	ct = nf_ct_get(skb, &ctinfo);
	if (ct) {
		cfgmgr_trace("ct %px\n", ct);
	}
#endif
	pdrm.ccm = *pp_get_userinfo();
	pdrm.ccm.msg_type = KNL_K2U_ROUTING_INFO;

	rcu_read_lock();
	ifa = rcu_dereference(out_dev->ip_ptr->ifa_list);
	pdrm.mask = ifa->ifa_mask;
	cfgmgr_info("address: (%pI4) %pI4, mask: %pI4\n", &v4_hdr->daddr, &ifa->ifa_address, &pdrm.mask);
	rcu_read_unlock();

	pdrm.msg_id = KNL_K2U_ROUTING_INFO;
	pdrm.ack = 0;
	pdrm.dip = v4_hdr->daddr;
	pdrm.sip = v4_hdr->saddr;
	pdrm.tos = v4_hdr->tos;
	hdr_len = v4_hdr->ihl << 2;
	switch ((pdrm.proto = v4_hdr->protocol)) {
	case IPPROTO_IP:
	case IPPROTO_ICMP:
		cfgmgr_info("raw IP protocol %d\n", pdrm.proto);
		pdrm.sport = 0;
		pdrm.dport = 0;
		break;
	case IPPROTO_TCP:
		th = skb_header_pointer(skb, hdr_len, sizeof(*th), hdrbuf);
		pdrm.sport = th->source;
		pdrm.dport = th->dest;
		break;
	case IPPROTO_UDP:
		uh = skb_header_pointer(skb, hdr_len, sizeof(*uh), hdrbuf);
		pdrm.sport = uh->source;
		pdrm.dport = uh->dest;
		break;
	default:
		cfgmgr_warn("non IP protocol %d\n", pdrm.proto);
		cfgmgr_msgdump(v4_hdr, 80, 0);
	}
	strlcpy(pdrm.devname, out_dev->name, sizeof(pdrm.devname));
	cfgmgr_msgdump(&pdrm, sizeof(pdrm), 0);

	hdr_len = pp_nl_msg_to_user(cm->family, &pdrm.ccm, NULL);
	if (hdr_len < 0) {
		DEBUG_ERROR("Error %d sending rt to user %px %d\n", hdr_len,
			init_net.genl_sock, pdrmp->ccm.pid);
	} else {
		cfgmgr_info("send message to user space %px %px mid 0x%x cmd 0x%x proto %d\n",
			out_dev, in_dev, pdrm.msg_id, pdrm.ccm.msg_type, pdrm.proto);
	}
	return NF_ACCEPT;
}

/*
 * dpdk_ipv4_post_routing_hook()
 *	Called for IP packets that are going out to interfaces after IP routing stage.
 */
static unsigned int dpdk_ipv4_post_routing_hook(void *priv, struct sk_buff *skb,
						const struct nf_hook_state *nhs)
{
	struct net_device *out = nhs->out;
	struct net_device *in;
	unsigned int ret;

	struct dst_entry *de = skb_dst(skb);
	if (de) {
		cfgmgr_trace("De %px Dev %px %s\n", de, de->dev, de->dev->name);
	}
	cfgmgr_trace("%px: IPv4 CMN Routing: %s\n", out, out->name);

	/*
	 * Don't process broadcast or multicast
	 */
	if (skb->pkt_type == PACKET_BROADCAST) {
		cfgmgr_trace("Broadcast, ignoring: %px\n", skb);
		return NF_ACCEPT;
	}

#ifdef	DPDK_HANDLE_TUNNELS
#ifndef DPDK_INTERFACE_PPTP_ENABLE
	/*
	 * skip pptp because we don't accelerate them
	 */
	if (dpdk_interface_is_pptp(skb, out)) {
		return NF_ACCEPT;
	}
#endif

#ifndef DPDK_INTERFACE_L2TPV2_ENABLE
	/*
	 * skip l2tpv2 because we don't accelerate them
	 */
	if (dpdk_interface_is_l2tp_packet_by_version(skb, out, 2)) {
		return NF_ACCEPT;
	}
#endif

	/*
	 * skip l2tpv3 because we don't accelerate them
	 */
	if (dpdk_interface_is_l2tp_packet_by_version(skb, out, 3)) {
		return NF_ACCEPT;
	}
#endif

	/*
	 * Identify interface from where this packet came
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if (unlikely(!in)) {
		cfgmgr_trace("Locally sourced packets are not processed in DPDK.\n");
		return NF_ACCEPT;
	}

	cfgmgr_trace("CMN Post routing process skb %px, out: %px (%s), in: %px (%s)\n",
			skb, out, out->name, in, in->name);
	ret = dpdk_ipv4_ip_process((struct net_device *)out, in, skb, true, false);
	dev_put(in);
	return ret;
}

/*
 * dpdk_interface_get_and_hold_dev_master()
 *	Returns the master device of a net device if any.
 */
struct net_device *dpdk_interface_get_and_hold_dev_master(struct net_device *dev)
{
	struct net_device *master;

#ifdef DPDK_INTERFACE_OVS_BRIDGE_ENABLE
	if (dpdk_interface_is_ovs_bridge_port(dev)) {
		master = ovsmgr_dev_get_master(dev);
		if (!master) {
			return NULL;
		}

		dev_hold(master);
		return master;
	}
#endif
	rcu_read_lock();
	master = netdev_master_upper_dev_get_rcu(dev);
	if (!master) {
		rcu_read_unlock();
		return NULL;
	}
	dev_hold(master);
	rcu_read_unlock();

	return master;
}
EXPORT_SYMBOL(dpdk_interface_get_and_hold_dev_master);

/*
 * dpdk_ipv4_bridge_post_routing_hook()
 *	Called for packets that are going out to one of the bridge physical interfaces.
 *
 * These may have come from another bridged interface or from a non-bridged interface.
 * Conntrack information may be available or not if this skb is bridged.
 */
static unsigned int dpdk_ipv4_bridge_post_routing_hook(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *nhs)
{
	struct net_device *out = nhs->out;
	struct ethhdr *skb_eth_hdr;
	uint16_t eth_type;
	struct net_device *bridge;
	struct net_device *in;
	unsigned int ret = NF_ACCEPT;

	cfgmgr_trace("%px: IPv4 CMN Bridge: %s\n", out, out->name);

	/*
	 * Check packet is an IP Ethernet packet
	 */
	skb_eth_hdr = eth_hdr(skb);
	if (!skb_eth_hdr) {
		cfgmgr_trace("%px: Not Eth\n", skb);
		return NF_ACCEPT;
	}
	eth_type = ntohs(skb_eth_hdr->h_proto);
	if (unlikely((eth_type != 0x0800) && (eth_type != ETH_P_PPP_SES))) {
		pp_dpdk_nl_recv_msg(skb);	// testing
		cfgmgr_trace("%px: Not IP/PPPoE session: %d\n", skb, eth_type);
		return NF_ACCEPT;
	}

	/*
	 * Identify interface from where this packet came.
	 * There are three scenarios to consider here:
	 * 1. Packet came from a local source.
	 *	Ignore - local is not handled.
	 * 2. Packet came from a routed path.
	 *	Ignore - it was handled in INET post routing.
	 * 3. Packet is bridged from another port.
	 *	Process.
	 *
	 * Begin by identifying case 1.
	 * NOTE: We are given 'out' (which we implicitly know is a bridge port) so out interface's master is the 'bridge'.
	 */
	bridge = dpdk_interface_get_and_hold_dev_master((struct net_device *)out);
	if (!bridge) {
		DEBUG_ERROR("Expected bridge\n");
		return NF_ACCEPT;
	}
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if  (!in) {
		/*
		 * Case 1.
		 */
		cfgmgr_trace("Local traffic: %px, ignoring traffic to bridge: %px (%s) \n", skb, bridge, bridge->name);
		dev_put(bridge);
		return NF_ACCEPT;
	}
	dev_put(in);

	/*
	 * Case 2:
	 *	For routed packets the skb will have the src mac matching the bridge mac.
	 * Case 3:
	 *	If the packet was not local (case 1) or routed (case 2) then
	 *	we process. There is an exception to case 2: when hairpin mode
	 *	is enabled, we process.
	 */

	/*
	 * Pass in NULL (for skb) and 0 for cookie since doing FDB lookup only
	 */
	in = br_port_dev_get(bridge, skb_eth_hdr->h_source, NULL, 0);
	if (!in) {
		cfgmgr_trace("skb: %px, no in device for bridge: %px (%s)\n", skb, bridge, bridge->name);
		dev_put(bridge);
		return NF_ACCEPT;
	}

	/*
	 * This flag needs to be checked in slave port(eth0/ath0)
	 * and not on master interface(br-lan). Hairpin flag can be
	 * enabled/disabled for ports individually.
	 */
	if (in == out) {
		if (!br_is_hairpin_enabled(in)) {
			cfgmgr_trace("skb: %px, bridge: %px (%s), ignoring"
					"the packet, hairpin not enabled"
					"on port %px (%s)\n", skb, bridge,
					bridge->name, out, out->name);
			goto skip_ipv4_bridge_flow;
		}
		cfgmgr_trace("skb: %px, bridge: %px (%s), hairpin enabled on port"
				"%px (%s)\n", skb, bridge, bridge->name, out, out->name);
	}

	ret = dpdk_ipv4_ip_process((struct net_device *)out, in,
//				skb_eth_hdr->h_source, skb_eth_hdr->h_dest,
				skb, false, false);
skip_ipv4_bridge_flow:
	dev_put(in);
	dev_put(bridge);
	return ret;
}

/*
 * struct nf_hook_ops dpdk_ipv4_netfilter_routing_hooks[]
 *	Hooks into netfilter routing packet monitoring points.
 */
static struct nf_hook_ops dpdk_ipv4_netfilter_routing_hooks[] __read_mostly = {
	/*
	 * Post routing hook is used to monitor packets going to interfaces
	 * that are NOT bridged in some way, e.g. packets to the WAN.
	 */
	{
		.hook		= dpdk_ipv4_post_routing_hook,
		.pf		= PF_INET,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_NAT_SRC + 1,
	},
};

/*
 * struct nf_hook_ops dpdk_ipv4_netfilter_bridge_hooks[]
 *      Hooks into netfilter bridge packet monitoring points.
 */
static struct nf_hook_ops dpdk_ipv4_netfilter_bridge_hooks[] __read_mostly = {
	/*
	 * The bridge post routing hook monitors packets going to interfaces
	 * that are part of a bridge arrangement.
	 * For example Wireles LAN (WLAN) and Wired LAN (LAN).
	 */
	{
		.hook		= dpdk_ipv4_bridge_post_routing_hook,
		.pf		= PF_BRIDGE,
		.hooknum	= NF_BR_POST_ROUTING,
		.priority	= NF_BR_PRI_FILTER_OTHER,
	},
};

static int ipv4_hooked;

int __net_init pp_dpdk_post_rt_init(struct net *net) {
	int rc;

	cfgmgr_info("Entering: %s ipv4-hook %d\n",__FUNCTION__, ipv4_hooked);
	if (ipv4_hooked++)
		return -EBUSY;

	rc = nf_register_net_hooks(&init_net, dpdk_ipv4_netfilter_routing_hooks,
				ARRAY_SIZE(dpdk_ipv4_netfilter_routing_hooks));
	if (rc < 0) {
		DEBUG_ERROR("Can't register Gatway netfilter hook.\n");
		return rc;
	}

	rc = nf_register_net_hooks(&init_net, dpdk_ipv4_netfilter_bridge_hooks,
				ARRAY_SIZE(dpdk_ipv4_netfilter_bridge_hooks));
	if (rc < 0) {
		DEBUG_ERROR("Can't register netfilter bridge hook.\n");
		return rc;
	}

	return ipv4_hooked;
}

void __net_exit pp_dpdk_post_rt_exit(struct net *net) {

	cfgmgr_info("exiting pp_dpdk module %d\n", ipv4_hooked);

	if (ipv4_hooked) {
		nf_unregister_net_hooks(net, dpdk_ipv4_netfilter_routing_hooks,
				ARRAY_SIZE(dpdk_ipv4_netfilter_routing_hooks));
		nf_unregister_net_hooks(net, dpdk_ipv4_netfilter_bridge_hooks,
				ARRAY_SIZE(dpdk_ipv4_netfilter_bridge_hooks));
	}
}

//MODULE_LICENSE("Dual BSD/GPL");
#endif //CM_POST_RT
