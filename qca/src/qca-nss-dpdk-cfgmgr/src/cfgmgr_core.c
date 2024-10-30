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
#include "dpdk_core_msg_types.h"

/*
 * cfgmgr_core_interface_add()
 *	Add new interface in
 */
static inline void cfgmgr_core_interface_add(uint8_t port_num, uint32_t ifnum, const char *if_name)
{
	struct cfgmgr_ctx *cmc = cfgmgr_base_get_ctx();
	struct cfgmgr_interface_data *intf_data;
	struct net_device *netdev;

	/*
	 * Get the netdevice from the netdevice registration from the port number
	 */
	netdev = dev_get_by_name(&init_net, if_name);
	if (!netdev) {
		cfgmgr_error("%px: No netdevice for the port %d", cmc, port_num);
		return;
	}

	intf_data = &cmc->intf_data[port_num];
	intf_data->port = port_num;
	intf_data->interface_num = ifnum;
	intf_data->netdev = netdev;

	cfgmgr_info("%px: Adding interface map for interface %u, netdev %px", cmc, intf_data->interface_num, intf_data->netdev);
}

/*
 * cfgmgr_core_get_ifnum_by_netdev()
 *	Get interface number for a netdevice
 */
int32_t cfgmgr_core_get_ifnum_by_netdev(struct net_device *netdev)
{
	struct cfgmgr_ctx *cmc = cfgmgr_base_get_ctx();
	struct cfgmgr_interface_data *intf_data;
	int i;

	for (i = 0; i < CFGMGR_PORT_CNT; i++) {
		intf_data = &cmc->intf_data[i];
		if (intf_data->netdev == netdev) {
			return intf_data->interface_num;
		}
	}

	return -1;
}
EXPORT_SYMBOL(cfgmgr_core_get_ifnum_by_netdev);

/*
 * cfgmgr_core_send_msg()
 *	Send a core driver msg to the userspace.
 */
cfgmgr_status_t cfgmgr_core_send_msg(struct cfgmgr_cmn_msg *cmn, uint32_t msg_len, uint32_t msg_type)
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
	send_info.ifnum = CFGMGR_INTERFACE_CORE;

	status = cfgmgr_k2u_msg_send(&send_info, cmn, msg_len);
	if (status != CFGMGR_STATUS_SUCCESS)
		cfgmgr_error("Failed to send wlan msg!\n");

	return status;
}
EXPORT_SYMBOL(cfgmgr_wlan_send_msg);

/*
 * cfgmgr_core_ipv4_ip_process()
 *	Process IP datagram skb
 */
static unsigned int cfgmgr_core_ipv4_ip_process(struct cfgmgr_ctx *cmc, struct net_device *out_dev,
				struct net_device *in_dev, struct sk_buff *skb, bool is_routed)
{
	struct dpdk_core_msg dcm;
	struct iphdr *v4_hdr;
	struct iphdr v4_header;
	struct tcphdr tcp_header;
	struct tcphdr *th;
	struct udphdr udp_header;
	struct udphdr *uh;
	int protocol;
	uint8_t ttl;
	uint32_t iphdr_len, total_len;
	struct in_ifaddr *ifa;
	cfgmgr_status_t status;

#ifdef	NEED_NF_CT
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

#endif

	/*
	 * Read and check the IPv4 header.
	 */
	v4_hdr = skb_header_pointer(skb, 0, sizeof(struct iphdr), &v4_header);
	if (!v4_hdr || v4_hdr->version != 4) {
		cfgmgr_trace("%px: skb %px, %px is NOT ipv4\n", cmc, skb, v4_hdr);
		return NF_ACCEPT;
	}

	iphdr_len = ntohs(v4_hdr->ihl);
	iphdr_len <<= 2;
	if (iphdr_len < 20) {
		cfgmgr_warn("%px: skb %px, v4 invalid ip hdr len %d\n", cmc, skb, iphdr_len);
		return NF_ACCEPT;
	}

	total_len = ntohs(v4_hdr->tot_len);
	if (skb->len < total_len) {
		cfgmgr_warn("%px: skb %px, v4 invalid total len: %u skb len: %u\n", cmc, skb, total_len, skb->len);
		return NF_ACCEPT;
	}

	/*
	 * Ignore fragmented packets for now
	 * TODO: Support fragmented packets.
	 */
	if ((ntohs(v4_hdr->frag_off) & 0x3fff)) {
		cfgmgr_warn("%px: skb %px, fragmented packets not supported yet\n", cmc, skb);
		return NF_ACCEPT;
	}

	ttl = v4_hdr->ttl;
	protocol = v4_hdr->protocol;
	dcm.msg.dcdr_msg.tos = v4_hdr->tos;
	dcm.msg.dcdr_msg.src_ip = v4_hdr->saddr;
	dcm.msg.dcdr_msg.dest_ip = v4_hdr->daddr;

#ifdef NEED_NF_CT
	ct = nf_ct_get(skb, &ctinfo);
	if (ct) {
		DEBUG_TRACE("ct %px\n", ct);
	}
#endif

	rcu_read_lock();
	ifa = rcu_dereference(out_dev->ip_ptr->ifa_list);
	dcm.msg.dcdr_msg.mask = ifa->ifa_mask;
	rcu_read_unlock();

	cfgmgr_info("%px: Sending msg for address (%pI4) %pI4, mask %pI4, protocol %d\n",
			cmc, &v4_hdr->daddr, &ifa->ifa_address, &dcm.msg.dcdr_msg.mask, protocol);
	// DEBUG_INFO("address: (%pI4) %pI4, mask: %pI4\n", &v4_hdr->daddr, &ifa->ifa_address, &pdrm.mask);

	switch (protocol) {
		case IPPROTO_IP:
		{
			break;
		}

		case IPPROTO_ICMP:
		{
			dcm.msg.dcdr_msg.src_port = 0;
			dcm.msg.dcdr_msg.dest_port = 0;
			break;
		}

		case IPPROTO_TCP:
		{
			th = skb_header_pointer(skb, iphdr_len, sizeof(*th), &tcp_header);
			dcm.msg.dcdr_msg.src_port = th->source;
			dcm.msg.dcdr_msg.dest_port = th->dest;
			break;
		}
		case IPPROTO_UDP:
		{
			uh = skb_header_pointer(skb, iphdr_len, sizeof(*uh), &udp_header);
			dcm.msg.dcdr_msg.src_port = uh->source;
			dcm.msg.dcdr_msg.dest_port = uh->dest;
			break;
		}
		default:
			cfgmgr_warn("%px: non ip protocol %d", cmc, protocol);
	}

	// strlcpy(pdrm.devname, out_dev->name, sizeof(pdrm.devname));

	/*
	 * Send the routing message to the DPFE client
	 */
	status = cfgmgr_core_send_msg(&dcm.cmn, sizeof(struct dpdk_core_dpfe_route), DPDK_CORE_MSG_TYPE_ROUTE_REG);
	if (status != CFGMGR_STATUS_SUCCESS) {
		cfgmgr_error("%px: Error sending routing info message, status %d", cmc, status);
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}

/*
 * cfgmgr_core_ipv4_post_routing_hook()
 *	Called for IP packets that are going out to interfaces after IP routing stage.
 */
static unsigned int cfgmgr_core_ipv4_post_routing_hook(void *priv, struct sk_buff *skb,
						const struct nf_hook_state *nhs)
{
	struct cfgmgr_ctx *cmc = cfgmgr_base_get_ctx();
	struct net_device *out = nhs->out;
	struct net_device *in;
	unsigned int ret;

	struct dst_entry *dst = skb_dst(skb);
	if (dst) {
		cfgmgr_trace("%px: dst entry %px Dev %px %s\n", cmc, dst, dst->dev, dst->dev->name);
	}

	cfgmgr_trace("%px: IPv4 CMN Routing: %s\n", out, out->name);

	/*
	 * Don't process broadcast or multicast
	 */
	if (skb->pkt_type == PACKET_BROADCAST) {
		cfgmgr_trace("%px: ignoring brodcast: %px\n", cmc, skb);
		return NF_ACCEPT;
	}

	/*
	 * List all tunnels or protocols that you do not support.
	 * PPTP, L2TPV2
	 * Check ECM once again to check the post routing hook.
	 */

	/*
	 * Identify interface from where this packet came
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if (unlikely(!in)) {
		cfgmgr_trace("%px: packet is from local source. they did not arrive from dpfe", cmc);
		return NF_ACCEPT;
	}

	cfgmgr_trace("%px: Post routing process: skb %px, out %px (%s), in %px (%s)",
			cmc, skb, out, out->name, in, in->name);
	ret = cfgmgr_core_ipv4_ip_process(cmc, (struct net_device *)out, in, skb, true);
	if (!ret) {
		return ret;
	}

	dev_put(in);
	return ret;
}

/*
 * cfgmgr_core_interface_get_and_hold_dev_master()
 *	Returns the master device of a net device if any.
 */
static inline struct net_device *cfgmgr_core_interface_get_and_hold_dev_master(struct net_device *dev)
{
	struct net_device *master;

	/*
	 * TODO: Fix to identify other interfaces.
	 */
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

/*
 * cfgmgr_core_ipv4_bridge_post_routing_hook()
 *	Called for packets that are going out to one of the bridge physical interfaces.
 */
static unsigned int cfgmgr_core_ipv4_bridge_post_routing_hook(void *priv, struct sk_buff *skb,
								const struct nf_hook_state *nhs)
{
	struct cfgmgr_ctx *cmc = cfgmgr_base_get_ctx();
	struct net_device *out = nhs->out, *bridge, *in;
	struct ethhdr *eth_header;
	uint16_t eth_type;
	uint32_t ret;

	/*
	 * Check packet is an IP Ethernet packet
	 */
	eth_header = eth_hdr(skb);
	if (!eth_header) {
		cfgmgr_trace("%px: skb %px header is not ethernet\n", cmc, skb);
		return NF_ACCEPT;
	}

	eth_type = ntohs(eth_header->h_proto);
	if (unlikely((eth_type != 0x0800) && (eth_type != ETH_P_PPP_SES))) {
		cfgmgr_trace("%px: skb %px packet is not IP/PPPoE session: %d\n", cmc, skb, eth_type);
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
	 *	PROCESS.
	 *
	 * Begin by identifying case 1.
	 * NOTE: We are given 'out' (which we implicitly know is a bridge port)
	 * so out interface's master is the 'bridge'.
	 */
	bridge = cfgmgr_core_interface_get_and_hold_dev_master((struct net_device *)out);
	if (!bridge) {
		cfgmgr_error("%px: expected bridge\n", cmc);
		return NF_ACCEPT;
	}

	/*
	 * Case 1.
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if  (!in) {
		cfgmgr_trace("%px: skb %px, local traffic, ignoring traffic to bridge: %px (%s) \n",
				cmc, skb, bridge, bridge->name);
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
	in = br_port_dev_get(bridge, eth_header->h_source, NULL, 0);
	if (!in) {
		cfgmgr_trace("%px: skb: %px, no in device for bridge: %px (%s)\n", cmc, skb, bridge, bridge->name);
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
			cfgmgr_trace("%px: skb: %px, bridge: %px (%s), ignoring the packet, hairpin not enabled"
					"on port %px (%s)\n", cmc, skb, bridge, bridge->name, out, out->name);
			goto skip_ipv4_bridge_flow;
		}

		cfgmgr_trace("skb: %px, bridge: %px (%s), hairpin enabled on port"
				"%px (%s)\n", skb, bridge, bridge->name, out, out->name);
	}

	ret = cfgmgr_core_ipv4_ip_process(cmc, (struct net_device *)out, in, skb, false);
	if (!ret) {
		return ret;
	}

skip_ipv4_bridge_flow:
	dev_put(in);
	dev_put(bridge);
	return ret;
}

/*
 * struct nf_hook_ops cfgmgr_core_ipv4_netfilter_routing_hooks[]
 *	Hooks into netfilter routing packet monitoring points.
 */
static struct nf_hook_ops cfgmgr_core_ipv4_netfilter_routing_hooks[] __read_mostly = {
	/*
	 * Post routing hook is used to monitor packets going to interfaces
	 * that are NOT bridged in some way, e.g. packets to the WAN.
	 */
	{
		.hook		= cfgmgr_core_ipv4_post_routing_hook,
		.pf		= PF_INET,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_NAT_SRC + 1,
	},
};

/*
 * struct nf_hook_ops cfgmgr_core_ipv4_netfilter_bridge_hooks[]
 *      Hooks into netfilter bridge packet monitoring points.
 */
static struct nf_hook_ops cfgmgr_core_ipv4_netfilter_bridge_hooks[] __read_mostly = {
	/*
	 * The bridge post routing hook monitors packets going to interfaces
	 * that are part of a bridge arrangement.
	 * For example Wireles LAN (WLAN) and Wired LAN (LAN).
	 */
	{
		.hook		= cfgmgr_core_ipv4_bridge_post_routing_hook,
		.pf		= PF_BRIDGE,
		.hooknum	= NF_BR_POST_ROUTING,
		.priority	= NF_BR_PRI_FILTER_OTHER,
	},
};

/*
 * cfgmgr_core_post_route_init()
 *	Initialize the post routing hook.
 */
bool cfgmgr_core_post_route_init(struct cfgmgr_ctx *cmc)
{
	int result;

	if (cfgmgr_post_route_is_active(cmc)) {
		cfgmgr_trace("%px: Post routing hook is already enabled, ignoring message", cmc);
		return false;
	}

	result = nf_register_net_hooks(&init_net, cfgmgr_core_ipv4_netfilter_routing_hooks,
			ARRAY_SIZE(cfgmgr_core_ipv4_netfilter_routing_hooks));
	if (result) {
		cfgmgr_error("%px: Unable to register netfilter hook", cmc);
		return CFGMGR_STATUS_ERROR;
	}

	result = nf_register_net_hooks(&init_net, cfgmgr_core_ipv4_netfilter_bridge_hooks,
			ARRAY_SIZE(cfgmgr_core_ipv4_netfilter_bridge_hooks));
	if (result) {
		cfgmgr_error("%px: Unable to register netfilter bridge hook", cmc);
		return CFGMGR_STATUS_ERROR;
	}

	/*
	 * Set the post routing feature as active.
	 */
	cfgmgr_post_route_set_active(cmc);
	return true;
}

/*
 * cfgmgr_core_post_route_deinit()
 *	Deinitialize the post routing hook.
 */
bool cfgmgr_core_post_route_deinit(struct cfgmgr_ctx *cmc)
{
	if (!cfgmgr_post_route_is_active(cmc)) {
		cfgmgr_trace("%px: Post routing hook is already disabled", cmc);
		return false;
	}

	nf_unregister_net_hooks(&init_net, cfgmgr_core_ipv4_netfilter_routing_hooks,
			ARRAY_SIZE(cfgmgr_core_ipv4_netfilter_routing_hooks));
	nf_unregister_net_hooks(&init_net, cfgmgr_core_ipv4_netfilter_bridge_hooks,
			ARRAY_SIZE(cfgmgr_core_ipv4_netfilter_bridge_hooks));

	cfgmgr_post_route_set_inactive(cmc);
	return true;
}

/*
 * cfgmgr_core_doit_handler()
 *	Route rx message handler for all WLAN messages.
 */
static int cfgmgr_core_doit_handler(struct sk_buff *skb,
				struct genl_info *info)
{
	struct cfgmgr_ctx *cmc = cfgmgr_base_get_ctx();
	struct cfgmgr_cmn_msg *cmn;
	cfgmgr_msg_cb_type_t cb;
	struct dpdk_core_msg *core_msg;
	void *cb_data = NULL;

	/*
	 * extract the message payload
	 */
	cmn = cfgmgr_base_get_msg(cmc, cmc->family, info);
	if (!cmn) {
		cfgmgr_error("%px: NULL cmn header! abort\n", cmc);
		return -EINVAL;
	}

	cfgmgr_info("%px: Received a DPDK core message, type %u\n", cmc, cmn->msg_type);

	/*
	 * Perform all the configuration operations here.
	 */
	switch (cmn->msg_type) {
		/*
		 * Store the received net for future unicast messages.
		 */
		case DPDK_CORE_MSG_TYPE_SETUP:
		{
			if (cfgmgr_is_dpfe_active(cmc)) {
				cfgmgr_warn("%px: DPFE is already active\n", cmc);
			}

			cfgmgr_set_dpfe_active(cmc);
			cfgmgr_info("%px: DPFE is enabled and activated.\n", cmc);
			cmc->net = (struct net *)cmn->sock_data;
			break;
		}

		case DPDK_CORE_MSG_TYPE_INTERFACE_INIT:
		{
			core_msg = (struct dpdk_core_msg *)cmn;
			cfgmgr_core_interface_add(core_msg->msg.intf_msg.port, core_msg->msg.intf_msg.ifnum, core_msg->msg.intf_msg.if_name);
			break;
		}

		case DPDK_CORE_MSG_TYPE_ROUTE_REG:
		{
			cfgmgr_core_post_route_init(cmc);
			break;
		}

		case DPDK_CORE_MSG_TYPE_ROUTE_UNREG:
		{
			cfgmgr_core_post_route_deinit(cmc);
			break;
		}

		default:
		{
			cfgmgr_warn("%px: Unknown message type %u received.\n", cmc, cmn->msg_type);
		}
	}

	/*
	 * Deliver the msg to core driver.
	 */
	cb = cfgmgr_base_get_msg_cb(cmc, CFGMGR_INTERFACE_CORE);
	cb_data = cfgmgr_base_get_msg_cb_data(cmc, CFGMGR_INTERFACE_CORE);
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
 * cfgmgr_core_deinit()
 *	DPDK Config deinit.
 */
void cfgmgr_core_deinit(struct cfgmgr_ctx *cmc)
{
	cfgmgr_status_t status;
	cfgmgr_unregister_doit(cmc, CFGMGR_INTERFACE_CORE);

	status = cfgmgr_unregister_msg_handler(cmc, CFGMGR_INTERFACE_CORE);
	if (status != CFGMGR_STATUS_SUCCESS) {
		cfgmgr_error("%px: Failed to unregister message handler\n", cmc);
		return;
	}
}

/*
 * cfgmgr_core_init()
 *	This function initializes the config sub-module in the Config Manager.
 */
void cfgmgr_core_init(struct cfgmgr_ctx *cmc)
{
	cfgmgr_status_t status;
	cfgmgr_register_doit(cmc, CFGMGR_INTERFACE_CORE, cfgmgr_core_doit_handler);

	status = cfgmgr_register_msg_handler(cmc, CFGMGR_INTERFACE_CORE, NULL, NULL);
	if (status != CFGMGR_STATUS_SUCCESS) {
		cfgmgr_error("%px: Failed to unregister message handler\n", cmc);
		return;
	}
}
