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

/**
 * @file dpdk_wlan_msg_types.h
 *	Wlan cmd and event defination for dpdk
 */

#ifndef _DPDK_WLAN_MSG_TYPES_H_
#define _DPDK_WLAN_MSG_TYPES_H_

#include "cfgmgr_def.h"

#define DPDK_MAX_REO_DEST_RINGS 8
#define DPDK_MAX_TCL_DATA_RINGS 5

/*
 * enum dpdk_wlan_cmd_types: Commands sent from wlan pmd to wlan driver
 * @DPDK_WLAN_CMD_TYPE_INVALID: Invalid command type
 * @DPDK_WLAN_CMD_TYPE_SOC_INFO: Command to get soc info
 * @DPDK_WLAN_CMD_TYPE_VDEV_INFO: Command to get vdev info
 * @DPDK_WLAN_CMD_TYPE_PEER_INFO: Command to get peer info
 * @DPDK_WLAN_CMD_TYPE_MAX: Max command type
 */
enum dpdk_wlan_cmd_types {
	DPDK_WLAN_CMD_TYPE_INVALID,
	DPDK_WLAN_CMD_TYPE_SOC_INFO,
	DPDK_WLAN_CMD_TYPE_VDEV_INFO,
	DPDK_WLAN_CMD_TYPE_PEER_INFO,

	/* Add new commands before this */
	DPDK_WLAN_CMD_TYPE_MAX
};

/*
 * enum dpdk_wlan_event_types: Events sent from wlan driver to wlan pmd
 * @DPDK_WLAN_EVT_TYPE_INVALID: Invalid event type
 * @DPDK_WLAN_EVT_TYPE_SOC_INFO: Event to send soc info
 * @DPDK_WLAN_EVT_TYPE_VDEV_INFO: Event to send vdev info
 * @DPDK_WLAN_EVT_TYPE_PEER_INFO: Event to sent peer info
 * @DPDK_WLAN_EVT_TYPE_VDEV_CREATE: Event to send vdev info on vdev create
 * @DPDK_WLAN_EVT_TYPE_VDEV_DELETE: Event to send vdev info vdev delete
 * @DPDK_WLAN_EVT_TYPE_VDEV_UP: Event to send vdev up notification
 * @DPDK_WLAN_EVT_TYPE_VDEV_DOWN: Event to send vdev down notification
 * @DPDK_WLAN_EVT_TYPE_PEER_CREATE: Event to send peer info on peer create
 * @DPDK_WLAN_EVT_TYPE_PEER_DELETE: Event to send peer info on peer delete
 * @DPDK_WLAN_EVT_TYPE_MAX: Max event type
 */
enum dpdk_wlan_event_types {
	DPDK_WLAN_EVT_TYPE_INVALID,
	DPDK_WLAN_EVT_TYPE_SOC_INFO,
	DPDK_WLAN_EVT_TYPE_VDEV_INFO,
	DPDK_WLAN_EVT_TYPE_PEER_INFO,
	DPDK_WLAN_EVT_TYPE_VDEV_CREATE,
	DPDK_WLAN_EVT_TYPE_VDEV_DELETE,
	DPDK_WLAN_EVT_TYPE_VDEV_UP,
	DPDK_WLAN_EVT_TYPE_VDEV_DOWN,
	DPDK_WLAN_EVT_TYPE_PEER_CREATE,
	DPDK_WLAN_EVT_TYPE_PEER_DELETE,

	/* Add new events before this */
	DPDK_WLAN_EVT_TYPE_MAX
};

/*
 * enum dpdk_wlan_op_mode: Wlan opmodes
 * @dpdk_wlan_op_mode_unknown: Opmode unknown
 * @dpdk_wlan_op_mode_ap: Opmode AP
 * @dpdk_wlan_op_mode_ibss: Opmode IBSS
 * @dpdk_wlan_op_mode_sta: Opmode STA
 * @dpdk_wlan_op_mode_monitor: Opmode Monitor
 * @dpdk_wlan_op_mode_ocb: Opmode OCB
 * @dpdk_wlan_op_mode_ndi: Opmode NDI
 *
 * Note: Keeping it in alignment with wlan driver opmodes enum
 */
enum dpdk_wlan_op_mode {
	dpdk_wlan_op_mode_unknown,
	dpdk_wlan_op_mode_ap,
	dpdk_wlan_op_mode_ibss,
	dpdk_wlan_op_mode_sta,
	dpdk_wlan_op_mode_monitor,
	dpdk_wlan_op_mode_ocb,
	dpdk_wlan_op_mode_ndi,
};

/*
 * struct dpdk_wlan_soc_info_cmd: Sent by wlan pmd to receive a wlan soc
 * specific info
 * @cmn: common message header
 * @soc_id: soc id of soc
 */
struct dpdk_wlan_soc_info_cmd {
	struct cfgmgr_cmn_msg cmn;
	uint8_t soc_id;
};

/*
 * struct dpdk_wlan_vdev_info_cmd: Sent by wlan pmd to receive wlan vdevs(in an
 * soc) specific info
 * @cmn: common message header
 * @soc_id: soc id of soc
 */
struct dpdk_wlan_vdev_info_cmd {
	struct cfgmgr_cmn_msg cmn;
	uint8_t soc_id;
};

/*
 * struct dpdk_wlan_peer_info_cmd: Sent by wlan pmd to receive wlan peers(in an
 * soc) specific info
 * @cmn: common message header
 * @soc_id: soc id of soc
 */
struct dpdk_wlan_peer_info_cmd {
	struct cfgmgr_cmn_msg cmn;
	uint8_t soc_id;
};

/*
 * struct ring_hp_tp_offset: SRNG head pointer and tail pointer offset in
 * pcie reg. space
 * @hp_addr_offset: head pointer offset
 * @tp_addr_offset: tail pointer offset
 */
struct ring_hp_tp_offset {
	uint32_t hp_addr_offset;
	uint32_t tp_addr_offset;
};

/*
 * struct dpdk_wlan_pdev_info: Pdev info
 * @pdev_id: pdev id
 * @lmac_id: lmac id
 * @vdev count: no. of vdevs in the pdev
 * @tx_descs_max: max tx descriptots
 * @rx_decap_mode: rx decap mode
 * @num_tx_allowed: num tx allowed
 * @num_reg_tx_allowed: num regular tx allowed
 * @num_tx_spl_allowed: num of spcl tx frames allowed
 */
struct dpdk_wlan_pdev_info {
	uint8_t pdev_id;
	uint8_t lmac_id;
	uint8_t vdev_count;
	int32_t tx_descs_max;
	uint32_t rx_decap_mode;
	uint32_t num_tx_allowed;
	uint32_t num_reg_tx_allowed;
	uint32_t num_tx_spl_allowed;
};

/*
 * struct dpdk_wlan_soc_info_event: Sent by wlan driver in response to a soc
 * info cmd
 * @cmn: command message header
 * @soc_id: soc id
 * @pdev_count: no. of pdevs in soc
 * @vdev_count: no. of vdevs in soc
 * @max_peers: max no. of peers supported
 * @max_peer_id: max peer id supported
 * @num_tx_comp_rings: no. of tx completion rings
 * @num_tcl_data_rings: no. of tcl data rings
 * @num_reo_dest_rings: no. of reo destination rings
 * @total_link_descs: total no. of link descriptots
 * @num_tx_allowed: num tx allowed
 * @num_reg_tx_allowed: num regular tx allowed
 * @num_tx_spl_allowed: num spcl tx allowed
 * @tcl_data_rings: tcl ring hp/tp offset info
 * @tx_comp_ring: tx comp ring hp/tp offset info
 * @reo_dest_ring: reo dest ring hp/tp offset info
 * @rx_refill_buf_ring: rx refill ring hp/tp offset info
 * @reo_exception_ring: reo exception ring hp/tp offset info
 * @rx_rel_ring: rx release ring hp/tp offset info
 * @reo_reinject_ring: reo reinject ring hp/tp offset info
 * @pdev_info: per pdev info
 */
struct dpdk_wlan_soc_info_event {
	struct cfgmgr_cmn_msg cmn;
	uint8_t soc_id;
	uint8_t pdev_count;
	uint16_t vdev_count;
	uint32_t max_peers;
	uint32_t max_peer_id;
	uint8_t num_tx_comp_rings;
	uint8_t num_tcl_data_rings;
	uint8_t num_reo_dest_rings;
	uint32_t total_link_descs;
	uint32_t num_tx_allowed;
	uint32_t num_reg_tx_allowed;
	uint32_t num_tx_spl_allowed;
	struct ring_hp_tp_offset tcl_data_rings[DPDK_MAX_TCL_DATA_RINGS];
	struct ring_hp_tp_offset tx_comp_ring[DPDK_MAX_TCL_DATA_RINGS];
	struct ring_hp_tp_offset reo_dest_ring[DPDK_MAX_REO_DEST_RINGS];
	struct ring_hp_tp_offset rx_refill_buf_ring;
	struct ring_hp_tp_offset reo_exception_ring;
	struct ring_hp_tp_offset rx_rel_ring;
	struct ring_hp_tp_offset reo_reinject_ring;
	struct dpdk_wlan_pdev_info pdev_info[];
};

/*
 * struct dpdk_wlan_vdev_info: Vdev info
 * @vdev_id: vdev id
 * @pdev_id: pdev id
 * @lmac_id: lmac id
 * @bank_id: bank id
 * @opmode: vdev opmode
 * @tx_encap_type:  Tx encapsulation type for this VAP
 * @rx_decap_type: Rx Decapsulation type for this VAP
 * @sec_type: security type information for this VAP
 * @mesh_vdev: Indicate if vdev is mesh vdev
 * @ifindex: if index of vdev
 * @mac_addr: vdev mac address
 * @num_peers: number of peers
 * @ap_bridge_enabled: ap bridge status
 */
struct dpdk_wlan_vdev_info {
	uint8_t vdev_id;
	uint8_t pdev_id;
	uint8_t lmac_id;
	uint8_t bank_id;
	uint8_t opmode;
	uint8_t tx_encap_type;
	uint8_t rx_decap_type;
	uint8_t sec_type;
	uint32_t mesh_vdev;
	int32_t ifindex;
	uint8_t mac_addr[MAC_ADDR_SIZE];
	uint16_t num_peers;
	bool ap_bridge_enabled;
};

/*
 * struct dpdk_wlan_vdev_info_event: Sent by wlan driver in response to a vdev
 * info cmd
 * @cmn: common message header
 * @soc_id: soc id
 * @vdev_count: no. of vdevs in soc
 * @vdev_info: per vdev info
 */
struct dpdk_wlan_vdev_info_event {
	struct cfgmgr_cmn_msg cmn;
	uint8_t soc_id;
	uint8_t vdev_count;
	struct dpdk_wlan_vdev_info vdev_info[];
};

/*
 * struct dpdk_wlan_peer_info: Peer info
 * @peer_id: peer id
 * @vdev_id: vdev id
 * @soc_id: soc id
 * @mac_addr: mac address of peer
 * @ast_idx: ast index of peer
 * @ast_hash: ast hash of peer
 */
struct dpdk_wlan_peer_info {
	uint16_t peer_id;
	uint8_t vdev_id;
	uint8_t soc_id;
	uint8_t mac_addr[MAC_ADDR_SIZE];
	uint16_t ast_idx;
	uint16_t ast_hash;
};

/*
 * struct dpdk_wlan_peer_info_event: Sent by wlan driver in response to a peer
 * info cmd
 * @cmn: common message header
 * @more_msg: flag to indiate if all peer info is sent or pending
 * @soc_id: soc id
 * @peer_count: how many peers data available in this msg
 * @peer_info: per peer info
 */
struct dpdk_wlan_peer_info_event {
	struct cfgmgr_cmn_msg cmn;
	bool more_msg;
	uint8_t soc_id;
	uint16_t peer_count;
	struct dpdk_wlan_peer_info peer_info[];
};

/*
 * struct dpdk_wlan_vdev_create_info: Sent by wlan driver for vdev creation
 * @cmn: common message header
 * @vdev_id: vdev id
 * @pdev_id: pdev id
 * @lmac_id: lmac id
 * @bank_id: bank id
 * @soc_id: soc id
 * @opmode: vdev opmode
 * @mac_addr: vdev mac address
 * @ifindex: if index of vdev
 * @mesh_vdev: Indicate if vdev is mesh vdev
 */
struct dpdk_wlan_vdev_create_info {
	struct cfgmgr_cmn_msg cmn;
	uint8_t vdev_id;
	uint8_t pdev_id;
	uint8_t lmac_id;
	uint8_t bank_id;
	uint8_t soc_id;
	uint8_t opmode;
	uint8_t mac_addr[MAC_ADDR_SIZE];
	int ifindex;
	uint32_t mesh_vdev;
};

/*
 * struct dpdk_wlan_vdev_delete_info: Sent by wlan driver for vdev deletion
 * @cmn: common message header
 * @vdev_id: vdev id
 * @soc_id: soc id
 * @mac_addr: vdev mac address
 */
struct dpdk_wlan_vdev_delete_info {
	struct cfgmgr_cmn_msg cmn;
	uint8_t vdev_id;
	uint8_t soc_id;
	uint8_t mac_addr[MAC_ADDR_SIZE];
};

/*
 * struct dpdk_wlan_peer_create_info: Sent by wlan driver for peer creation
 * @cmn: common message header
 * @peer_id: peer id
 * @vdev_id: vdev id
 * @soc_id: soc id
 * @mac_addr: peer mac address
 * @ast_idx: ast index of peer
 * @ast_hash: ast hash of peer
 */
struct dpdk_wlan_peer_create_info {
	struct cfgmgr_cmn_msg cmn;
	uint16_t peer_id;
	uint8_t vdev_id;
	uint8_t soc_id;
	uint8_t mac_addr[MAC_ADDR_SIZE];
	uint16_t ast_idx;
	uint16_t ast_hash;
};

/*
 * struct dpdk_wlan_peer_delete_info: Sent by wlan driver for peer deletion
 * @cmn: common message header
 * @peer_id: peer id
 * @vdev_id: vdev id
 * @soc_id: soc id
 * @mac_addr: peer mac address
 */
struct dpdk_wlan_peer_delete_info {
	struct cfgmgr_cmn_msg cmn;
	uint16_t peer_id;
	uint8_t vdev_id;
	uint8_t soc_id;
	uint8_t mac_addr[MAC_ADDR_SIZE];
};
#endif /* _DPDK_WLAN_MSG_TYPES_H_ */
