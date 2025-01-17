/*
 * Copyright (c) 2020 The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
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

#ifndef __qca_multi_link_H_
#define __qca_multi_link_H_

#include <qdf_nbuf.h>
#include <qdf_module.h>
#include <qdf_list.h>
#include <qdf_util.h>
#include <qdf_lock.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/version.h>
#include <linux/wireless.h>
#include <net/cfg80211.h>

#include <ieee80211.h>
#include <ieee80211_defines.h>
#include <qca_multi_link_tbl.h>
#include "if_upperproto.h"


#define QCA_MULTI_LINK_RADIO_LIST_SIZE 6
#define QCA_ML_MAX_MLO_GROUPS 2

typedef void (*qca_multi_link_set_loop_detection_fn_t)(void *context, bool val);

/**
 * qca_multi_link_needs_enq - rptr return status
 * @QCA_MULTI_LINK_ALLOW_VAP_ENQ: Allow the packet to be enqueued
 * @QCA_MULTI_LINK_SKIP_VAP_ENQ: SKIP the enqueue
 */
typedef enum qca_multi_link_needs_enq {
	QCA_MULTI_LINK_ALLOW_VAP_ENQ = 0,
	QCA_MULTI_LINK_SKIP_VAP_ENQ,
} qca_multi_link_needs_enq_t;

/**
 * enum qca_multi_link_status - rptr return status
 * @qca_multi_link_PKT_ALLOW: Allow the packet to be received or transmitted
 * @qca_multi_link_PKT_DROP: Drop the packet
 * @qca_multi_link_PKT_CONSUMED: The packet is consumed in the repeater processing
 */
typedef enum qca_multi_link_status {
	QCA_MULTI_LINK_PKT_NONE = 0,
	QCA_MULTI_LINK_PKT_ALLOW,
	QCA_MULTI_LINK_PKT_DROP,
	QCA_MULTI_LINK_PKT_CONSUMED
} qca_multi_link_status_t;

/**
 * struct qca_multi_link_statistics - rptr drop statistics
 */
typedef struct qca_multi_link_statistics {
	uint32_t ap_rx_sec_sta_null;
	uint32_t sta_rx_sec_sta_mcast_no_fdb;
	uint32_t sta_rx_sec_sta_mcast_dup_pkts;
	uint32_t sta_rx_sec_sta_mcast_drop_sec;
	uint32_t sta_rx_sec_sta_mcast_drop;
	uint32_t sta_rx_sec_sta_ucast_src_eth;
	uint32_t sta_rx_sec_sta_ucast_src_dif_band;
	uint32_t sta_rx_sec_sta_ucast_no_ap;
	uint32_t sta_rx_pri_sta_mcast_no_fdb;
	uint32_t sta_rx_pri_sta_mcast_drop;
	uint32_t sta_tx_sec_sta_alwys_prim;
	uint32_t sta_tx_sec_sta_mcast_no_fdb;
	uint32_t sta_tx_sec_sta_src_eth;
	uint32_t sta_tx_sec_sta_mcast_drop_sec;
	uint32_t sta_tx_sec_sta_drop_dif_band;
	uint32_t sta_tx_pri_sta_drop_no_fdb;
	uint32_t sta_tx_pri_sta_drop_dif_band;
} qca_ml_global_stats_t;

/**
 * struct qca_multi_link_radio_list_node - rptr list node
 * @node: linked list node
 * @wiphy: wiphy pointer
 * @no_backhaul: is no_backhaul radio
 * @is_fast_lane: is fast_lane radio
 * @sta_dev: radio's station net device
 * @sta_mld_mac: radio's station MLD MAC address
 */
typedef struct qca_multi_link_radio_list_node {
	qdf_list_node_t node;
	struct wiphy *wiphy;
	bool no_backhaul;
	bool is_fast_lane;
	struct net_device *sta_dev;
	struct net_device *sta_mldev;
	uint8_t sta_mld_mac[QDF_MAC_ADDR_SIZE];
} qca_multi_link_radio_node_t;

struct qca_multi_link_ops {
	struct net_device * (*get_ml_link_entry_for_mld_dev)(struct net_device *link_dev, void *mac_addr);
};

/**
 * struct qca_multi_link_parameters - rptr list node
 * @rptr_processing_enable: repeater is enabled
 * @loop_detected: is loop detected
 * @always_primary: is always primary flag enabled
 * @force_client_mcast_traffic: is force client mcast flag enabled
 * @drop_secondary_mcast: is drop secondary mcast flag enabled
 * @primary_wiphy: primary radio pointer
 * @total_stavaps_up: total number of backhauls
 * @radio_list: list of radio participating in repeater
 */
typedef struct qca_multi_link_parameters {
	bool rptr_processing_enable;
	bool loop_detected;
	bool always_primary;
	bool force_client_mcast_traffic;
	bool drop_secondary_mcast;
	struct wiphy *primary_wiphy;
	uint8_t total_stavaps_up;
	qdf_list_t radio_list;
	qdf_spinlock_t radio_lock;
	qca_ml_global_stats_t qca_ml_stats;
	qca_multi_link_set_loop_detection_fn_t qca_ml_set_loop_detection;
	void *qca_ml_loop_detection_context;
	struct wiphy *mlo_wiphy[QCA_ML_MAX_MLO_GROUPS];
	struct qca_multi_link_ops *qca_ml_ops;
} qca_multi_link_parameters_t;

void qca_multi_link_add_mld_wiphy(struct wiphy *wiphy);
void qca_multi_link_del_mld_wiphy(struct wiphy *wiphy);
void qca_multi_link_deinit_module(void);
void qca_multi_link_init_module(struct qca_multi_link_ops *ml_ops);
uint8_t qca_multi_link_get_num_sta(void);
void qca_multi_link_append_num_sta(bool inc_or_dec);
bool qca_multi_link_is_dbdc_processing_reqd(struct net_device *net_dev);
void qca_multi_link_set_drop_sec_mcast(bool val);
void qca_multi_link_set_force_client_mcast(bool val);
void qca_multi_link_set_always_primary(bool val);
bool qca_multi_link_get_always_primary(void);
void qca_multi_link_set_dbdc_enable(bool val);
struct wiphy *qca_multi_link_get_primary_radio(void);
void qca_multi_link_set_primary_radio(struct wiphy *primary_wiphy);
bool qca_multi_link_remove_radio(struct wiphy *wiphy);
bool qca_multi_link_add_radio(struct wiphy *wiphy);
bool qca_multi_link_remove_fastlane_radio(struct wiphy *fl_wiphy);
bool qca_multi_link_add_fastlane_radio(struct wiphy *fl_wiphy);
bool qca_multi_link_remove_no_backhaul_radio(struct wiphy *no_bl_wiphy);
bool qca_multi_link_add_no_backhaul_radio(struct wiphy *no_bl_wiphy);
bool qca_multi_link_remove_station_vap(struct wiphy *wiphy);
bool qca_multi_link_add_station_vap(struct wiphy *wiphy,
				    struct net_device *sta_dev,
				    struct net_device *sta_mldev,
				    uint8_t *mld_mac);
bool qca_multi_link_ap_rx(struct net_device *net_dev, qdf_nbuf_t nbuf);
bool qca_multi_link_sta_rx(struct net_device *net_dev, qdf_nbuf_t nbuf,
			   struct net_device **prim_dev,
			   struct net_device *mld_ndev);
bool qca_multi_link_sta_tx(struct net_device *net_dev, qdf_nbuf_t nbuf,
			   struct net_device *mld_ndev);
void qca_multi_link_set_dbdc_loop_detection_cb(qca_multi_link_set_loop_detection_fn_t qca_ml_cb,
					       void *ctx);
bool qca_multi_link_is_primary_radio(struct wiphy *dev_wiphy);
struct net_device *qca_multi_link_get_station_vap(struct wiphy *wiphy);
#endif
