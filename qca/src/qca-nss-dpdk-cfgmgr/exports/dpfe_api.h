/*
 **************************************************************************
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

/**
 * @file qca_nss_dpfe_client.h
 *	NSS DPDK CLIENT interface definitions.
 */

#ifndef __DPFE_API_H
#define __DPFE_API_H

/**
 * @addtogroup nss_dpfe_client_subsystem
 * @{
 */

#define DPFE_MAX_VLAN_DEPTH 2			/**< Maximum VLAN depth. */
#define DPFE_VLAN_ID_NOT_CONFIGURED 0xfff	/**< VLAN ID not configured. */

/*
 * Rule creation and rule update flags.
 */
#define DPFE_RULE_CREATE_FLAG_IPV4 (1<<0)				/**< Rule is for IPv4. */
#define DPFE_RULE_CREATE_FLAG_IPV6 (1<<1)				/**< Rule is for IPv6. */
#define DPFE_RULE_CREATE_FLAG_BRIDGE_FLOW  (1<<2)		/**< Rule is for a pure bridge forwarding flow. */
#define DPFE_RULE_CREATE_FLAG_ROUTED       (1<<3)		/**< Rule is for a routed connection. */
#define DPFE_RULE_CREATE_FLAG_L2_ENCAP     (1<<4)		/**< Consists of an encapsulating protocol that carries an IPv4 payload within it. */
#define DPFE_RULE_CREATE_FLAG_USE_FLOW_BOTTOM_INTERFACE (1<<5)	/**< Use flow interface number instead of top interface. */
#define DPFE_RULE_CREATE_FLAG_USE_RETURN_BOTTOM_INTERFACE (1<<6) /**< Use return interface number instead of top interface. */
#define DPFE_RULE_CREATE_FLAG_FLOW_SRC_INTERFACE_CHECK  (1<<7)  /**< Check source interface on the flow direction. */
#define DPFE_RULE_CREATE_FLAG_RETURN_SRC_INTERFACE_CHECK  (1<<8)
								/**< Check source interface on the return direction. */
#define DPFE_RULE_CREATE_FLAG_FLOW_SRC_INTERFACE_CHECK_NO_FLUSH  (1<<9)
								/**< Check source interface on the flow direction but do not flush the connection. */
#define DPFE_RULE_CREATE_FLAG_RETURN_SRC_INTERFACE_CHECK_NO_FLUSH  (1<<10)
								/**< Check source interface on the return direction but do not flush the connection. */
#define DPFE_RULE_CREATE_FLAG_NO_SEQ_CHECK (1<<11)			/**< Do not perform TCP sequence number checks. */

/*
 * Rule creation validity flags.
 */
#define DPFE_RULE_CREATE_CONN_VALID         (1<<0)	/**< IPv4 connection is valid. */
#define DPFE_RULE_CREATE_TCP_VALID          (1<<1)	/**< TCP protocol fields are valid. */
#define DPFE_RULE_CREATE_VLAN_VALID         (1<<2)	/**< VLAN fields are valid. */
#define DPFE_RULE_CREATE_SRC_MAC_VALID      (1<<3)	/**< Source MAC address is valid. */


/*
 * Source MAC address validity flags; used with the mac_valid_flags field in the dpfe_ipv4_src_mac_rule structure.
 */
#define DPFE_SRC_MAC_FLOW_VALID 0x01
		/**< MAC address for the flow interface is valid. */
#define DPFE_SRC_MAC_RETURN_VALID 0x02
		/**< MAC address for the return interface is valid. */

/**
 * @addtogroup dpfe_datatypes
 * @{
 */

/**
* Synchronize reason enum.
*/
typedef enum dpfe_stats_sync_reason {
	DPFE_RULE_SYNC_REASON_STATS,	/**< Synchronize statistics. */
	DPFE_RULE_SYNC_REASON_FLUSH,	/**< Synchronize to flush an entry. */
	DPFE_RULE_SYNC_REASON_EVICT,	/**< Synchronize to evict an entry. */
	DPFE_RULE_SYNC_REASON_DESTROY	/**< Synchronize to destroy an entry (requested by the connection manager). */
} dpfe_stats_sync_reason_t;

/**
 * Common response types.
 */
enum dpfe_cmn_response {
	DPFE_CMN_RESPONSE_ACK,		/**< Message acknowledged. */
	DPFE_CMN_RESPONSE_EVERSION,	/**< Version error. */
	DPFE_CMN_RESPONSE_EINTERFACE,	/**< Interface error. */
	DPFE_CMN_RESPONSE_ELENGTH,	/**< Length error. */
	DPFE_CMN_RESPONSE_EMSG,		/**< Message error. */
	DPFE_CMM_RESPONSE_NOTIFY,	/**< Message independant of request. */
	DPFE_CMN_RESPONSE_LAST		/**< Indicates the last item. */
};

/**
 * DPDK return status
 */
typedef enum dpfe_ret {
	DPFE_RET_SUCCESS = 0,			/**< Success */
	DPFE_RET_IFACE_INVALID,			/**< Failure due to Invalid DPFE interface */
	DPFE_RET_FAILURE_NOT_SUPPORTED,		/**< Failure due to unsupported feature */
	DPFE_RET_FAILURE_NO_RESOURCE,		/**< Failure due to out of resource */
	DPFE_RET_FAILURE_INVALID_PARAM,		/**< Failure due to invalid parameter */
	DPFE_RET_PORT_NOT_FOUND,		/**< Port not found */
	DPFE_RET_PORT_ALLOC_FAIL,		/**< Port allocation fails */
	DPFE_RET_MTU_CFG_FAIL,			/**< MTU configuration fails */
	DPFE_RET_INGRESS_VLAN_FAIL,		/**< Ingress vlan configuration failed */
	DPFE_RET_EGRESS_VLAN_FAIL,		/**< Egress vlan configuration failed */
	DPFE_RET_VLAN_INGRESS_DEL_FAIL,		/**< Ingress vlan deletion configuration failed */
	DPFE_RET_VLAN_EGRESS_DEL_FAIL,		/**< Egress vlan deletion configuration failed */
	DPFE_RET_FAILURE_CREATE_COLLISSION,	/**< Failure due to create collision */
	DPFE_RET_FAILURE_CREATE_OOM,		/**< Failure due to memory allocation failed */
	DPFE_RET_FAILURE_FLOW_ADD_FAIL,		/**< Failure due to flow addition failed in DPFE */
	DPFE_RET_FAILURE_DESTROY_NO_CONN,	/**< Failure due to connection not found in DPFE */
	DPFE_RET_FAILURE_DESTROY_FAIL,		/**< Failure due to connection not found in DPFE */
	DPFE_RET_FAILURE_FLUSH_FAIL,		/**< Flush failure */
	DPFE_RET_FAILURE_BRIDGE_NAT,		/**< Failure due to Bridge + NAT flows */
	DPFE_RET_QUEUE_CFG_FAIL,		/**< Failure in queue configuration */
	DPFE_RET_FAILURE_TUN_CE_ADD_FAILURE,	/**< Failure in adding tunnel connection entry */
	DPFE_RET_FAILURE_TUN_CE_DEL_FAILURE,	/**< Failure in removing tunnel connection entry */
	DPFE_RET_TUN_ADD_CE_NULL,		/**< Add connection entry callback is NULL */
	DPFE_RET_PORT_NO_OFFLOAD,		/**< Offload is disabled on the DPFE port */
} dpfe_ret_t;

/**
 * IPv4 bridge/route rule messages.
 */
enum dpfe_message_types {
	DPFE_IPV4_CREATE_RULE_MSG,		/**< IPv4/IPv6 create rule message. */
	DPFE_IPV4_DESTROY_RULE_MSG,		/**< IPv4/IPv6 destroy rule message. */
	DPFE_IPV4_CONN_STATS_SYNC_MSG,		/**< IPv4/IPv6 connection statistics synchronize message. */
	DPFE_IPV4_CONN_STATS_SYNC_MANY_MSG,	/**< IPv4/IPv6 connection statistics synchronize many message. */
	DPFE_IPV6_CREATE_RULE_MSG,		/**< IPv4/IPv6 create rule message. */
	DPFE_IPV6_DESTROY_RULE_MSG,		/**< IPv4/IPv6 destroy rule message. */
	DPFE_IPV6_CONN_STATS_SYNC_MSG,		/**< IPv4/IPv6 connection statistics synchronize message. */
	DPFE_IPV6_CONN_STATS_SYNC_MANY_MSG,	/**< IPv4/IPv6 connection statistics synchronize many message. */
	DPFE_MAX_MSG_TYPES,			/**< IPv4/IPv6 message max type number. */
};

/*
 * Connection mark types.
 */
enum dpfe_connection_mark_type {
	DPFE_CONNECTION_MARK_TYPE_CONNMARK,      /**< Conntrack mark. */
	DPFE_CONNECTION_MARK_TYPE_MAX            /**< Indicates the last item. */
};

/**
 * Connection mark structure.
 */
struct dpfe_connection_mark {
	uint8_t protocol;			/**< Protocol number. */
	__be32 src_ip[4];			/**< Source IP address. */
	__be32 dest_ip[4];			/**< Destination IP address. */
	__be16 src_port;			/**< Source port number. */
	__be16 dest_port;			/**< Destination port number. */
	uint32_t flow_mark;			/**< Mark to be updated for the flow direction. */
	uint32_t return_mark;			/**< Mark to be updated for the return direction. */
	uint32_t flags;				/**< State of marks. */
	enum dpfe_connection_mark_type type;	/**< Type of the marking. */
};

/**
 * Common message structure.
 */
struct dpfe_cmn_msg {
	enum dpfe_cmn_response response;/**< Primary response. */
	uint32_t type;			/**< Decentralized request ID used to match response ID. */
	uint32_t len;			/**< Length of the message excluding this header. */
};

/**
 * Common 5-tuple structure.
 */
struct dpfe_ipv4_5tuple {
	__be32 flow_ip;		/**< Flow IP address. */
	__be32 return_ip;	/**< Return IP address. */
	__be16 flow_ident;	/**< Flow identifier, e.g., TCP/UDP port. */
	__be16 return_ident;	/**< Return identifier, e.g., TCP/UDP port. */
	uint8_t protocol;	/**< Protocol number. */
	uint8_t reserved[3];	/**< Reserved; padding for alignment. */
};

/**
 * IPv4 connection rule structure.
 */
struct dpfe_ipv4_connection_rule {
	uint8_t flow_mac[6];			/**< Flow MAC address. */
	uint8_t return_mac[6];			/**< Return MAC address. */
	int32_t flow_interface_num;		/**< Flow interface number. */
	int32_t return_interface_num;		/**< Return interface number. */
	int32_t flow_top_interface_num;		/**< Top flow interface number. */
	int32_t return_top_interface_num;	/**< Top return interface number. */
	uint32_t flow_mtu;			/**< Flow interface`s MTU. */
	uint32_t return_mtu;			/**< Return interface`s MTU. */
	__be32 flow_ip_xlate;			/**< Translated flow IP address. */
	__be32 return_ip_xlate;			/**< Translated return IP address. */
	__be16 flow_ident_xlate;		/**< Translated flow identifier, e.g., port. */
	__be16 return_ident_xlate;		/**< Translated return identifier, e.g., port. */
};

/**
 * TCP connection rule structure.
 */
struct dpfe_protocol_tcp_rule {
	uint32_t flow_max_window;	/**< Flow direction's largest seen window. */
	uint32_t return_max_window;	/**< Return direction's largest seen window. */
	uint32_t flow_end;		/**< Flow direction's largest seen sequence + segment length. */
	uint32_t return_end;		/**< Return direction's largest seen sequence + segment length. */
	uint32_t flow_max_end;		/**< Flow direction's largest seen ack + max(1, win). */
	uint32_t return_max_end;	/**< Return direction's largest seen ack + max(1, win). */
	uint8_t flow_window_scale;	/**< Flow direction's window scaling factor. */
	uint8_t return_window_scale;	/**< Return direction's window scaling factor. */
	uint16_t reserved;		/**< Reserved; padding for alignment. */
};

/**
 * Information for source MAC address rules.
 */
struct dpfe_src_mac_rule {
	uint32_t mac_valid_flags;	/**< MAC address validity flags. */
	uint16_t flow_src_mac[3];	/**< Source MAC address for the flow direction. */
	uint16_t return_src_mac[3];	/**< Source MAC address for the return direction. */
};

/**
* Mark rule structure.
*/
struct dpfe_mark_rule {
	uint32_t flow_mark;		/**< SKB mark associated with this rule for flow direction. */
	uint32_t return_mark;		/**< SKB mark associated with this rule for return direction. */
};

/**
 * DSCP connection rule structure.
 */
struct dpfe_dscp_rule {
	uint8_t flow_dscp;		/**< Egress DSCP value for flow direction. */
	uint8_t return_dscp;		/**< Egress DSCP value for return direction. */
	uint8_t reserved[2];		/**< Reserved; padding for alignment. */
};

/**
 * VLAN connection rule structure.
 */
struct dpfe_vlan_rule {
	uint32_t ingress_vlan_tag;	/**< VLAN tag for ingress packets. */
	uint32_t egress_vlan_tag;	/**< VLAN tag for egress packets. */
};

/**
 * Acceleration direction rule structure.
 * Sometimes it is useful to accelerate traffic in one direction and not in another.
 */
struct dpfe_acceleration_direction_rule {
	uint8_t flow_accel;		/**< Accelerate in flow direction. */
	uint8_t return_accel;		/**< Accelerate in return direction. */
	uint8_t reserved[2];		/**< Reserved; padding for alignment. */
};

/**
 * IPv4 rule create submessage structure.
 */
struct dpfe_ipv4_rule_create_msg {
	/* Request */
	uint32_t valid_flags;				/**< Bit flags associated with paramater validity. */
	uint32_t rule_flags;				/**< Bit flags associated with the rule. */

	struct dpfe_ipv4_5tuple tuple;			/**< Holds values of 5-tuple. */

	struct dpfe_ipv4_connection_rule conn_rule;	/**< Basic connection-specific data. */
	struct dpfe_protocol_tcp_rule tcp_rule;		/**< TCP-related acceleration parameters. */
	struct dpfe_src_mac_rule src_mac_rule;		/**< Source MAC address rule. */
	struct dpfe_vlan_rule vlan_primary_rule;	/**< Primary VLAN-related acceleration parameters. */
	struct dpfe_vlan_rule vlan_secondary_rule;	/**< Secondary VLAN-related acceleration parameters. */

	/* Response */
	uint32_t index;					/**< Slot ID for cache statistics to host OS. */
};

/**
 * IPv4 rule destroy submessage structure.
 */
struct dpfe_ipv4_rule_destroy_msg {
	struct dpfe_ipv4_5tuple tuple;	/**< Holds values of 5-tuple. */
};

/**
 * The DPFE IPv4 rule sync structure.
 */
struct dpfe_ipv4_conn_sync {
	uint32_t index;				/**< Slot ID for cache statistics to host OS. */
	uint8_t protocol;			/**< Protocol number. */
	__be32 flow_ip;				/**< Flow IP address. */
	__be32 flow_ip_xlate;			/**< Translated flow IP address. */
	__be16 flow_ident;			/**< Flow identifier, e.g., port. */
	__be16 flow_ident_xlate;		/**< Translated flow identifier, e.g., port. */
	uint32_t flow_max_window;		/**< Flow direction's largest seen window. */
	uint32_t flow_end;			/**< Flow direction's largest seen sequence + segment length. */
	uint32_t flow_max_end;			/**< Flow direction's largest seen ack + max(1, win). */
	uint32_t flow_rx_packet_count;		/**< Flow interface's Rx packet count. */
	uint32_t flow_rx_byte_count;		/**< Flow interface's Rx byte count. */
	uint32_t flow_tx_packet_count;		/**< Flow interface's Tx packet count. */
	uint32_t flow_tx_byte_count;		/**< Flow interface's Tx byte count. */
	__be32 return_ip;			/**< Return IP address. */
	__be32 return_ip_xlate;			/**< Translated return IP address */
	__be16 return_ident;			/**< Return identifier, e.g., port. */
	__be16 return_ident_xlate;		/**< Translated return identifier, e.g., port. */
	uint32_t return_max_window;		/**< Return direction's largest seen window. */
	uint32_t return_end;			/**< Return direction's largest seen sequence + segment length. */
	uint32_t return_max_end;		/**< Return direction's largest seen ack + max(1, win). */
	uint32_t return_rx_packet_count;	/**< Return interface's Rx packet count. */
	uint32_t return_rx_byte_count;		/**< Return interface's Rx byte count. */
	uint32_t return_tx_packet_count;	/**< Return interface's Tx packet count. */
	uint32_t return_tx_byte_count;		/**< Return interface's Tx byte count. */
	uint32_t inc_ticks;			/**< Number of ticks since the last sync. */
	dpfe_stats_sync_reason_t reason;	/**< Syncrhonization reason. */

	uint8_t flags;				/**< Bit flags associated with the rule. */
	uint32_t cause;				/**< Flush cause. */
};

/**
 * Information for a multiple IPv4 connection statistics synchronization message.
 */
struct dpfe_ipv4_conn_sync_many_msg {
	/*
	 * Request
	 */
	uint16_t index;		/**< Request connection statistics from the index. */
	uint16_t size;		/**< Buffer size of this message. */

	/*
	 * Response
	 */
	uint16_t next;		/**< Firmware response for the next connection to be requested. */
	uint16_t count;		/**< Number of synchronized connections included in this message. */
	struct dpfe_ipv4_conn_sync conn_sync[];	/**< Array for the statistics. */
};

/**
 * Message structure to send/receive IPv4 bridge/route commands
 */
struct dpfe_ipv4_msg {
	struct dpfe_cmn_msg cm;					/**< Message header. */
	union {
		struct dpfe_ipv4_rule_create_msg rule_create;	/**< Rule create message. */
		struct dpfe_ipv4_rule_destroy_msg rule_destroy;	/**< Rule destroy message. */
		struct dpfe_ipv4_conn_sync conn_stats;		/**< Connection statistics synchronization message. */
		struct dpfe_ipv4_conn_sync_many_msg conn_stats_many;
					/**< Many connections' statistics synchronization message. */
	} msg;							/**< IPv4 message. */
};


/**
 * @addtogroup dpfe_datatypes
 * @{
 */

/**
 * IPv6 5-tuple structure.
 */
struct dpfe_ipv6_5tuple {
	__be32 flow_ip[4];	/**< Flow IP address. */
	__be32 return_ip[4];	/**< Return IP address. */
	__be16 flow_ident;	/**< Flow identifier, e.g.,TCP/UDP port. */
	__be16 return_ident;	/**< Return identifier, e.g., TCP/UDP port. */
	uint8_t  protocol;		/**< Protocol number. */
	uint8_t  reserved[3];	/**< Reserved; padding for alignment. */
};

/**
 * IPv6 connection rule structure.
 */
struct dpfe_ipv6_connection_rule {
	uint8_t flow_mac[6];			/**< Flow MAC address. */
	uint8_t return_mac[6];			/**< Return MAC address. */
	int32_t flow_interface_num;		/**< Flow interface number. */
	int32_t return_interface_num;		/**< Return interface number. */
	int32_t flow_top_interface_num;		/**< Top flow interface number. */
	int32_t return_top_interface_num;	/**< Top return interface number. */
	uint32_t flow_mtu;			/**< Flow interface's MTU. */
	uint32_t return_mtu;			/**< Return interface's MTU. */
	__be32 flow_ip_xlate[4];		/**< Translated flow IP address. */
	__be32 return_ip_xlate[4];		/**< Translated return IP address. */
	__be16 flow_ident_xlate;		/**< Translated flow identifier, e.g., port. */
	__be16 return_ident_xlate;		/**< Translated return identifier, e.g., port. */
};

/**
 * IPv6 rule create submessage structure.
 */
struct dpfe_ipv6_rule_create_msg {
	/*
	 * Request
	 */
	uint32_t valid_flags;				/**< Bit flags associated with parameter validity. */
	uint32_t rule_flags;				/**< Bit flags associated with the rule. */
	struct dpfe_ipv6_5tuple tuple;			/**< Holds values of the dpfe_ipv6_5tuple tuple. */
	struct dpfe_ipv6_connection_rule conn_rule;	/**< Basic connection-specific data. */
	struct dpfe_protocol_tcp_rule tcp_rule;		/**< Protocol-related acceleration parameters. */
	struct dpfe_src_mac_rule src_mac_rule;		/**< Source MAC address rule. */
	struct dpfe_mark_rule mark_rule;		/**< SKB mark-related acceleration parameters. */
	struct dpfe_vlan_rule vlan_primary_rule;	/**< VLAN-related acceleration parameters. */
	struct dpfe_vlan_rule vlan_secondary_rule;	/**< VLAN-related acceleration parameters. */

	/*
	 * Response
	 */
	uint32_t index;					/**< Slot ID for cache statistics to host OS. */
};

/**
 * IPv6 rule destroy submessage structure.
 */
struct dpfe_ipv6_rule_destroy_msg {
	struct dpfe_ipv6_5tuple tuple;	/**< Holds values of the dpfe_ipv6_5tuple tuple */
};

/**
 * DPFE IPv6 rule sync structure.
 */
struct dpfe_ipv6_conn_sync {
	uint32_t index;				/**< Slot ID for cache statistics to host OS. */
	uint8_t protocol;			/**< Protocol number. */
	__be32 flow_ip[4];			/**< Flow IP address. */
	__be32 flow_ip_xlate[4];		/**< Translated flow IP address. */
	__be16 flow_ident;			/**< Flow identifier, e.g., port. */
	__be16 flow_ident_xlate;		/**< Translated flow identifier, e.g., port. */
	uint32_t flow_max_window;		/**< Flow direction's largest seen window. */
	uint32_t flow_end;			/**< Flow direction's largest seen sequence + segment length. */
	uint32_t flow_max_end;			/**< Flow direction's largest seen ack + max(1, win). */
	uint32_t flow_rx_packet_count;		/**< Flow interface's Rx packet count. */
	uint32_t flow_rx_byte_count;		/**< Flow interface's Rx byte count. */
	uint32_t flow_tx_packet_count;		/**< Flow interface's Tx packet count. */
	uint32_t flow_tx_byte_count;		/**< Flow interface's Tx byte count. */
	__be32 return_ip[4];			/**< Return IP address. */
	__be32 return_ip_xlate[4];		/**< Translated return IP address. */
	__be16 return_ident;			/**< Return identifer, e.g., port. */
	__be16 return_ident_xlate;		/**< Translated return identifier, e.g., port. */
	uint32_t return_max_window;		/**< Return direction's largest seen window. */
	uint32_t return_end;			/**< Return direction's largest seen sequence + segment length. */
	uint32_t return_max_end;		/**< Return direction's largest seen ack + max(1, win). */
	uint32_t return_rx_packet_count;	/**< Return interface's Rx packet count. */
	uint32_t return_rx_byte_count;		/**< Return interface's Rx byte count. */
	uint32_t return_tx_packet_count;	/**< Return interface's Tx packet count. */
	uint32_t return_tx_byte_count;		/**< Return interface's Tx byte count. */
	uint32_t inc_ticks;			/**< Number of ticks since the last sync. */
	dpfe_stats_sync_reason_t reason;	/**< Syncrhonization reason. */
	uint8_t flags;				/**< Bit flags associated with the rule. */
	uint32_t cause;				/**< Flush cause associated with the rule. */
};

/**
 * Information for a multiple IPv6 connection statistics synchronization message.
 */
struct dpfe_ipv6_conn_sync_many_msg {
	/*
	 * Request:
	 */
	uint16_t index;		/**< Request connection statistics from the index. */
	uint16_t size;		/**< Buffer size of this message. */

	/*
	 * Response:
	 */
	uint16_t next;		/**< Firmware response for the next connection to be requested. */
	uint16_t count;		/**< Number of synchronized connections included in this message. */
	struct dpfe_ipv6_conn_sync conn_sync[];	/**< Array for the statistics. */
};

/**
 * Message structure to send/receive IPv6 bridge/route commands.
 */
struct dpfe_ipv6_msg {
	struct dpfe_cmn_msg cm;		/**< Message header. */
	union {
		struct dpfe_ipv6_rule_create_msg rule_create;
					/**< Rule create message. */
		struct dpfe_ipv6_rule_destroy_msg rule_destroy;
					/**< Rule destroy message. */
		struct dpfe_ipv6_conn_sync conn_stats;
					/**< Statistics synchronization message. */
		struct dpfe_ipv6_conn_sync_many_msg conn_stats_many;
					/**< Many Connections' statistics synchronizaion message. */
	} msg;				/**< IPv6 message. */
};

#endif /* __DPFE_API_H */
