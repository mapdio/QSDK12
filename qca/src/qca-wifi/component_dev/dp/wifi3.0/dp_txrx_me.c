/*
 * Copyright (c) 2016-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "hal_hw_headers.h"
#include "dp_types.h"
#include "dp_peer.h"
#include "qdf_nbuf.h"
#include "qdf_atomic.h"
#include "qdf_types.h"
#include "dp_tx.h"
#include "dp_tx_desc.h"
#include "dp_internal.h"
#include "dp_txrx_me.h"
#include <dp_me.h>
#include <dp_peer.h>
#define MAX_ME_BUF_CHUNK 1424
#define ME_US_TO_SEC(_x) ((_x) / (1000 * 1000))
#define ME_CLEAN_WAIT_TIMEOUT (200000) /*200ms*/
#define ME_CLEAN_WAIT_COUNT 400

/**
 * dp_tx_me_init():Initialize ME buffer ppol
 * @pdev: DP PDEV handle
 *
 * Return:0 on Succes 1 on failure
 */
static inline uint16_t
dp_tx_me_init(struct dp_pdev *pdev)
{
	uint16_t i, mc_uc_buf_len, num_pool_elems;
	uint32_t pool_size;

	struct dp_tx_me_buf_t *p;

	mc_uc_buf_len = sizeof(struct dp_tx_me_buf_t);

	num_pool_elems = MAX_ME_BUF_CHUNK;
	/* Add flow control buffer count */
	pool_size = (mc_uc_buf_len) * num_pool_elems;
	pdev->me_buf.size = mc_uc_buf_len;
	if (!(pdev->me_buf.vaddr)) {
		qdf_spin_lock_bh(&pdev->tx_mutex);
		pdev->me_buf.vaddr = qdf_mem_malloc(pool_size);
		if (!(pdev->me_buf.vaddr)) {
			qdf_spin_unlock_bh(&pdev->tx_mutex);
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
			  "Error allocating memory pool");
			return 1;
		}
		pdev->me_buf.buf_in_use = 0;
		pdev->me_buf.freelist =
			(struct dp_tx_me_buf_t *)pdev->me_buf.vaddr;
		/*
		 * me_buf looks like this
		 * |=======+==========================|
		 * | ptr   |         Dst MAC          |
		 * |=======+==========================|
		 */
		p = pdev->me_buf.freelist;
		for (i = 0; i < num_pool_elems - 1; i++) {
			p->next = (struct dp_tx_me_buf_t *)
				((char *)p + pdev->me_buf.size);
			p = p->next;
		}
		p->next = NULL;
		qdf_spin_unlock_bh(&pdev->tx_mutex);
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
			  "ME Pool successfully initialized vaddr - %pK",
			  pdev->me_buf.vaddr);
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
			  "paddr - %x\n", (unsigned int)pdev->me_buf.paddr);
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
			  "num_elems = %d", (unsigned int)num_pool_elems);
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
			  "buf_size - %d", (unsigned int)pdev->me_buf.size);
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
			  "pool_size = %d", (unsigned int)pool_size);
	} else {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
			  "ME Already Enabled!!");
	}
	return 0;
}

/**
 * dp_tx_me_alloc_descriptor():Allocate ME descriptor
 * @soc: DP SOC handle
 * @pdev_id: id of DP PDEV handle
 *
 * Return:void
 */
void dp_tx_me_alloc_descriptor(struct cdp_soc_t *soc, uint8_t pdev_id)
{
	struct dp_pdev *pdev =
		dp_get_pdev_from_soc_pdev_id_wifi3((struct dp_soc *)soc,
						   pdev_id);

	if (!pdev)
		return;

	if (qdf_atomic_read(&pdev->mc_num_vap_attached) == 0) {
		dp_tx_me_init(pdev);
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
			  FL("Enable MCAST_TO_UCAST "));
	}
	qdf_atomic_inc(&pdev->mc_num_vap_attached);
}

#ifdef GLOBAL_ASSERT_AVOIDANCE
static inline void dp_tx_me_force_free_descs(struct dp_pdev *pdev)
{
	int i;
	uint16_t num_pool_elems = MAX_ME_BUF_CHUNK;
	struct dp_tx_me_buf_t *me_desc =
				(struct dp_tx_me_buf_t *)pdev->me_buf.vaddr;

	for (i = 0; i < num_pool_elems; i++) {
		if (me_desc->paddr_macbuf) {
			qdf_mem_unmap_nbytes_single(pdev->soc->osdev,
					me_desc->paddr_macbuf,
					QDF_DMA_TO_DEVICE,
					QDF_MAC_ADDR_SIZE);

			me_desc->paddr_macbuf = 0;
			pdev->me_buf.buf_in_use--;
		}

		me_desc = (struct dp_tx_me_buf_t *)
			((char *)me_desc + pdev->me_buf.size);
	}

	if (pdev->me_buf.buf_in_use != 0) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
				"Post flush me buf in use count %d",
				pdev->me_buf.buf_in_use);

		pdev->me_buf.buf_in_use = 0;
	}

	return;
}
#else
static inline void dp_tx_me_force_free_descs(struct dp_pdev *pdev)
{
	qdf_assert_always(0);
}
#endif

/**
 * dp_tx_me_exit():Free memory and other cleanup required for
 * multicast unicast conversion
 * @pdev - DP_PDEV handle
 *
 * Return:void
 */
void
dp_tx_me_exit(struct dp_pdev *pdev)
{
	/* Add flow control buffer count */
	uint32_t wait_time = ME_US_TO_SEC(ME_CLEAN_WAIT_TIMEOUT *
			ME_CLEAN_WAIT_COUNT);

	if (pdev->me_buf.vaddr) {
		uint16_t wait_cnt = 0;

		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
			  "Disabling Mcastenhance,This may take some time");
		qdf_spin_lock_bh(&pdev->tx_mutex);
		while ((pdev->me_buf.buf_in_use > 0) &&
		       (wait_cnt < ME_CLEAN_WAIT_COUNT)) {
			qdf_spin_unlock_bh(&pdev->tx_mutex);
			OS_SLEEP(ME_CLEAN_WAIT_TIMEOUT);
			wait_cnt++;
			qdf_spin_lock_bh(&pdev->tx_mutex);
		}
		if (pdev->me_buf.buf_in_use > 0) {
			QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
				  "Tx-comp pending for %d",
				  pdev->me_buf.buf_in_use);
			QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
				  "ME frames after waiting %ds!!",
				  wait_time);

			dp_tx_me_force_free_descs(pdev);
		}

		qdf_mem_free(pdev->me_buf.vaddr);
		pdev->me_buf.vaddr = NULL;
		pdev->me_buf.freelist = NULL;
		qdf_spin_unlock_bh(&pdev->tx_mutex);
	} else {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
			  "ME Already Disabled !!!");
	}
}

/**
 * dp_tx_me_free_descriptor():free ME descriptor
 * @soc: DP SOC handle
 * @pdev_id: id of DP PDEV handle
 *
 * Return:void
 */
void
dp_tx_me_free_descriptor(struct cdp_soc_t *soc, uint8_t pdev_id)
{
	struct dp_pdev *pdev =
		dp_get_pdev_from_soc_pdev_id_wifi3((struct dp_soc *)soc,
						   pdev_id);

	if (!pdev)
		return;

	if (atomic_read(&pdev->mc_num_vap_attached)) {
		if (qdf_atomic_dec_and_test(&pdev->mc_num_vap_attached)) {
			dp_tx_me_exit(pdev);
			QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
				  "Disable MCAST_TO_UCAST");
		}
	}
}

/**
 * dp_tx_prepare_send_me(): Call to the umac to get the list of clients
 * @vdev: DP VDEV handle
 * @nbuf: Multicast buffer
 *
 * Return: no of packets transmitted
 */
QDF_STATUS
dp_tx_prepare_send_me(struct dp_vdev *vdev, qdf_nbuf_t nbuf)
{
	uint32_t flag = 0;
#if defined(WLAN_FEATURE_11BE_MLO) && defined(WLAN_MLO_MULTI_CHIP)
	if ((DP_MLD_MODE_HYBRID_NONBOND == vdev->pdev->soc->mld_mode_ap) &&
	    (wlan_op_mode_ap == vdev->opmode) &&
	    (CB_FTYPE_MLO_MCAST == qdf_nbuf_get_tx_ftype(nbuf)))
		flag = DP_ME_MCTBL_MLD_VDEV;
#endif

	if (dp_me_mcast_convert((struct cdp_soc_t *)(vdev->pdev->soc),
				vdev->vdev_id, vdev->pdev->pdev_id,
				nbuf, flag) > 0)
		return QDF_STATUS_SUCCESS;

	return QDF_STATUS_E_FAILURE;
}

/**
 * dp_tx_prepare_send_igmp_me(): Call to check igmp ,convert mcast to ucast
 * @vdev: DP VDEV handle
 * @nbuf: Multicast buffer
 *
 * Return: no of packets transmitted
 */
QDF_STATUS
dp_tx_prepare_send_igmp_me(struct dp_vdev *vdev, qdf_nbuf_t nbuf)
{
	if (dp_igmp_me_mcast_convert((struct cdp_soc_t *)(vdev->pdev->soc),
				     vdev->vdev_id, vdev->pdev->pdev_id,
				     nbuf) > 0)
		return QDF_STATUS_SUCCESS;

	return QDF_STATUS_E_FAILURE;
}

/*
 * dp_tx_me_mem_free(): Function to free allocated memory in mcast enahncement
 * pdev: pointer to DP PDEV structure
 * seg_info_head: Pointer to the head of list
 *
 * return: void
 */
static void dp_tx_me_mem_free(struct dp_pdev *pdev,
			      struct dp_tx_seg_info_s *seg_info_head)
{
	struct dp_tx_me_buf_t *mc_uc_buf;
	struct dp_tx_seg_info_s *seg_info_new = NULL;
	qdf_nbuf_t nbuf = NULL;
	uint64_t phy_addr;

	while (seg_info_head) {
		nbuf = seg_info_head->nbuf;
		mc_uc_buf = (struct dp_tx_me_buf_t *)
			seg_info_head->frags[0].vaddr;
		phy_addr = seg_info_head->frags[0].paddr_hi;
		phy_addr =  (phy_addr << 32) | seg_info_head->frags[0].paddr_lo;
		qdf_mem_unmap_nbytes_single(pdev->soc->osdev,
					    phy_addr,
					    QDF_DMA_TO_DEVICE, QDF_MAC_ADDR_SIZE);
		dp_tx_me_free_buf(pdev, mc_uc_buf);
		qdf_nbuf_free(nbuf);
		seg_info_new = seg_info_head;
		seg_info_head = seg_info_head->next;
		qdf_mem_free(seg_info_new);
	}
}

bool dp_peer_check_dms_capable(struct cdp_soc_t *soc_hdl,
			       uint8_t vdev_id,
			       struct dp_peer *peer)
{
	struct dp_txrx_peer *txrx_peer = dp_get_txrx_peer(peer);

	if (!txrx_peer)
		return false;

	return txrx_peer->is_dms;
}

bool dp_peer_check_dms_capable_by_mac(struct cdp_soc_t *soc_hdl,
				      uint8_t vdev_id,
				      uint8_t *mac_addr)
{
	struct dp_peer *peer = NULL;
	struct cdp_peer_info peer_info = { 0 };
	bool is_capable = false;
	struct dp_soc *soc = cdp_soc_t_to_dp_soc(soc_hdl);

	DP_PEER_INFO_PARAMS_INIT(&peer_info, vdev_id, mac_addr, false,
				 CDP_WILD_PEER_TYPE);

	peer = dp_peer_hash_find_wrapper(soc, &peer_info, DP_MOD_ID_CDP);

	if (!peer)
		return false;

	is_capable = dp_peer_check_dms_capable(soc_hdl, vdev_id, peer);
	dp_peer_unref_delete(peer, DP_MOD_ID_CDP);

	return is_capable;
}

#if defined(QCA_SUPPORT_WDS_EXTENDED) || defined(WLAN_FEATURE_11BE_MLO)
/**
 * dp_tx_me_check_primary_peer_by_mac() - Check primary peer using mac address
 * @soc: Datapath soc handle
 * @vdev: DP vdev
 * @mac_addr: Peer mac address
 *
 * Return: True if wds ext peer; false otherwise
 */
static inline
bool dp_tx_me_check_primary_peer_by_mac(struct dp_soc *soc, struct dp_vdev *vdev,
					uint8_t *mac_addr)
{
	struct dp_peer *peer = NULL;
	struct dp_peer *tgt_peer = NULL;
	struct cdp_peer_info peer_info = { 0 };

	if (!dp_vdev_is_wds_ext_enabled(vdev))
		return false;

	DP_PEER_INFO_PARAMS_INIT(&peer_info, DP_VDEV_ALL, mac_addr, false,
				 CDP_WILD_PEER_TYPE);

	peer = dp_peer_hash_find_wrapper((struct dp_soc *)soc, &peer_info,
					  DP_MOD_ID_CDP);

	if (!peer)
		return true;

	tgt_peer = dp_get_tgt_peer_from_peer(peer);

	/* if peer is non primary don't forward packet */
	if (vdev != tgt_peer->vdev) {
		dp_peer_unref_delete(peer, DP_MOD_ID_CDP);
		return true;
	}

	dp_peer_unref_delete(peer, DP_MOD_ID_CDP);
	return false;
}
#else
static inline
bool dp_tx_me_check_primary_peer_by_mac(struct dp_soc *soc, struct dp_vdev *vdev,
					uint8_t *mac_addr)
{
	return false;
}
#endif

/**
 * dp_me_get_primary_peer() - Get primary peer for if @peer is MLD peer
 * MCSD table store the MLD Peer mac address, Hence lookup always returns
 * MLD peer for MLO client.
 * @soc: Datapath soc handle
 * @dp_peer: MLD peer object for which primary obj to be found.
 *
 * Return: Primary peer if found ; else dp_peer.
 */
#if defined(WLAN_FEATURE_11BE_MLO)
static inline struct dp_peer *
dp_me_get_primary_peer(struct dp_soc *soc, struct dp_peer *dp_peer)
{
	struct dp_peer *primary_dp_peer;
	/* If this is MLD Peer find its primary peer and
	 * unref MLD peer reference*/
	if (dp_peer && IS_MLO_DP_MLD_PEER(dp_peer)) {
		primary_dp_peer =
			dp_get_primary_link_peer_by_id(soc, dp_peer->peer_id,
						       DP_MOD_ID_MCAST2UCAST);
		dp_peer_unref_delete(dp_peer, DP_MOD_ID_MCAST2UCAST);
		return primary_dp_peer;
	}
	return dp_peer;
}
#else
static inline struct dp_peer *
dp_me_get_primary_peer(struct dp_soc *soc, struct dp_peer *dp_peer)
{
	return dp_peer;
}
#endif
/**
 * dp_tx_me_send_dms_pkt: function to send dms packet
 * @soc: Datapath soc handle
 * @peer: Datapath peer handle
 * @arg: argument to iter function
 *
 * return void
 */
static void
dp_tx_me_send_dms_pkt(struct dp_soc *soc, struct dp_peer *peer, void *arg)
{
	qdf_nbuf_t  nbuf_ref;
	dp_vdev_dms_me_t *dms_me = (dp_vdev_dms_me_t *)arg;
	uint8_t xmit_type = qdf_nbuf_get_vdev_xmit_type(dms_me->nbuf);

	if (peer->bss_peer || !dp_peer_is_primary_link_peer(peer))
		return;

	if (dp_peer_check_wds_ext_peer(peer))
		return;

	if (!dp_peer_check_dms_capable(dms_me->soc_hdl, dms_me->vdev->vdev_id,
	    peer))
		return;

	dms_me->tx_exc_metadata->peer_id = peer->peer_id;
	/* Update the ref count for each peer */
	qdf_nbuf_ref(dms_me->nbuf);
	nbuf_ref = dms_me->nbuf;
	dms_me->num_pkt_sent++;
	nbuf_ref = dp_tx_send_exception(dms_me->soc_hdl,
					dms_me->vdev->vdev_id,
					nbuf_ref,
					dms_me->tx_exc_metadata);
	if (nbuf_ref) {
		qdf_nbuf_free(nbuf_ref);
		DP_STATS_INC(dms_me->vdev, tx_i[xmit_type].mcast_en.dropped_send_fail, 1);
	}
}

static inline void
dp_tx_me_update_dms_stats(struct dp_vdev *vdev, bool is_igmp,
			  uint8_t xmit_type, uint16_t num_pkt_sent)
{
	if (is_igmp) {
		DP_STATS_INC(vdev, tx_i[xmit_type].igmp_mcast_en.igmp_ucast_converted,
			     num_pkt_sent);
	} else {
		DP_STATS_INC(vdev, tx_i[xmit_type].mcast_en.ucast, num_pkt_sent);
	}
}
/**
 * dp_tx_me_dms_pkt_handler: function to send dms packet
 * @soc: Datapath soc handle
 * @vdev: DP vdev handler
 * @tid : transmit TID
 * @is_igmp: flag to indicate igmp packet
 * @nbuf: Multicast nbuf
* @dp_peer: dp peer object
 *
 * return: no of converted packets
 */
static uint16_t
dp_tx_me_dms_pkt_handler(struct cdp_soc_t *soc_hdl,
			 struct dp_vdev *vdev,
			 uint8_t tid,
			 bool is_igmp,
			 qdf_nbuf_t nbuf, struct dp_peer *dp_peer)
{
	struct dp_soc *soc = cdp_soc_t_to_dp_soc(soc_hdl);
	struct cdp_tx_exception_metadata tx_exc_param = {0};
	dp_vdev_dms_me_t dms_me;
	uint8_t xmit_type = qdf_nbuf_get_vdev_xmit_type(nbuf);

	tx_exc_param.sec_type = vdev->sec_type;
	tx_exc_param.tx_encap_type = vdev->tx_encap_type;
	tx_exc_param.peer_id = HTT_INVALID_PEER;
	tx_exc_param.tid = tid;

	dms_me.soc_hdl = soc_hdl;
	dms_me.vdev = vdev;
	dms_me.nbuf = nbuf;
	dms_me.tx_exc_metadata = &tx_exc_param;
	dms_me.num_pkt_sent = 0;

	if (dp_peer) {
		dp_tx_me_send_dms_pkt(soc, dp_peer, &dms_me);
		dp_tx_me_update_dms_stats(vdev, is_igmp, xmit_type, 1);
		return 1;
	}
	dp_vdev_iterate_peer(vdev, dp_tx_me_send_dms_pkt,
			     &dms_me, DP_MOD_ID_MCAST2UCAST);

	qdf_nbuf_free(nbuf);

	dp_tx_me_update_dms_stats(vdev, is_igmp, xmit_type,
				  dms_me.num_pkt_sent);
	dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_MCAST2UCAST);

	/* only bss peer is present, free the buffer*/
	if (!dms_me.num_pkt_sent)
		return 1;

	return dms_me.num_pkt_sent;
}

/**
 * dp_tx_me_send_convert_ucast(): function to convert multicast to unicast
 * @soc: Datapath soc handle
 * @vdev_id: vdev id
 * @nbuf: Multicast nbuf
 * @newmac: Table of the clients to which packets have to be sent
 * @new_mac_cnt: No of clients
 * @tid: desired tid
 * @is_igmp: flag to indicate if packet is igmp
 * @is_dms_pkt: flag to indicate if packet is dms
 *
 * return: no of converted packets
 */
uint16_t
dp_tx_me_send_convert_ucast(struct cdp_soc_t *soc_hdl, uint8_t vdev_id,
			    qdf_nbuf_t nbuf,
			    uint8_t newmac[][QDF_MAC_ADDR_SIZE],
			    uint8_t new_mac_cnt, uint8_t tid,
			    bool is_igmp, bool is_dms_pkt)
{
	struct dp_soc *soc = cdp_soc_t_to_dp_soc(soc_hdl);
	struct dp_pdev *pdev;
	qdf_ether_header_t *eh;
	uint8_t *data;
	uint16_t len;
	uint16_t dms_pkt_retval = 0;
	struct dp_peer *dp_peer = NULL;

	/* reference to frame dst addr */
	uint8_t *dstmac;
	/* copy of original frame src addr */
	uint8_t srcmac[QDF_MAC_ADDR_SIZE];

	/* local index into newmac */
	uint8_t new_mac_idx = 0;
	struct dp_tx_me_buf_t *mc_uc_buf;
	qdf_nbuf_t  nbuf_clone;
	struct dp_tx_msdu_info_s msdu_info;
	struct dp_tx_seg_info_s *seg_info_head = NULL;
	struct dp_tx_seg_info_s *seg_info_tail = NULL;
	struct dp_tx_seg_info_s *seg_info_new;
	qdf_dma_addr_t paddr_data;
	qdf_dma_addr_t paddr_mcbuf = 0;
	uint8_t empty_entry_mac[QDF_MAC_ADDR_SIZE] = {0};
	QDF_STATUS status;
	uint8_t curr_mac_cnt = 0;
	struct dp_vdev *vdev = dp_vdev_get_ref_by_id(soc, vdev_id,
						     DP_MOD_ID_MCAST2UCAST);
	uint8_t xmit_type = qdf_nbuf_get_vdev_xmit_type(nbuf);

	if (!vdev)
		goto free_return;

	pdev = vdev->pdev;

	if (!pdev)
		goto free_return;

	if (is_dms_pkt && (!dp_vdev_is_wds_ext_enabled(vdev)))
		return dp_tx_me_dms_pkt_handler(soc_hdl, vdev, tid, is_igmp,
						nbuf, dp_peer);

	qdf_mem_zero(&msdu_info, sizeof(msdu_info));

	dp_tx_get_queue(vdev, nbuf, &msdu_info.tx_queue);

	eh = (qdf_ether_header_t *)qdf_nbuf_data(nbuf);
	qdf_mem_copy(srcmac, eh->ether_shost, QDF_MAC_ADDR_SIZE);

	len = qdf_nbuf_len(nbuf);

	data = qdf_nbuf_data(nbuf);

	status = qdf_nbuf_map(vdev->osdev, nbuf,
			QDF_DMA_TO_DEVICE);

	if (status) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
				"Mapping failure Error:%d", status);
		DP_STATS_INC(vdev, tx_i[xmit_type].mcast_en.dropped_map_error, 1);
		qdf_nbuf_free(nbuf);
		return 1;
	}

	paddr_data = qdf_nbuf_mapped_paddr_get(nbuf) + QDF_MAC_ADDR_SIZE;

	for (new_mac_idx = 0; new_mac_idx < new_mac_cnt; new_mac_idx++) {
		bool is_peer_dms = 0;
		dstmac = newmac[new_mac_idx];
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_INFO,
				"added mac addr (%pM)", dstmac);

		/* Check for NULL Mac Address */
		if (!qdf_mem_cmp(dstmac, empty_entry_mac, QDF_MAC_ADDR_SIZE))
			continue;

		/* frame to self mac. skip */
		if (!qdf_mem_cmp(dstmac, srcmac, QDF_MAC_ADDR_SIZE))
			continue;

		/* forward the packet only on primary peer */
		if (dp_tx_me_check_primary_peer_by_mac(soc, vdev, dstmac))
			continue;

		/*
		 * dp_peer_check_dms_capable_by_mac returns:
		 * 1. true, if peer = dms_capable
		 * 2. false in all other cases.
		 */
		is_peer_dms = dp_peer_check_dms_capable_by_mac(soc_hdl, vdev_id, dstmac);

		/*
		 * Lets consider following cases
		 * 1. ME6 = 1, is_peer_dms = 0
		 *    Below condition does not get satisfied and ME5 packet is sent.
		 * 2. ME6 = 1, is_peer_dms = 1
		 *    Amsdu subframe is sent.
		 */
		if (is_dms_pkt && is_peer_dms) {

			dp_peer =
				 dp_find_peer_by_macaddr(soc, dstmac,
							 vdev->vdev_id,
							 DP_MOD_ID_MCAST2UCAST);
			dp_peer = dp_me_get_primary_peer(soc, dp_peer);
			if (qdf_likely(dp_peer)) {
				dms_pkt_retval +=
					dp_tx_me_dms_pkt_handler(soc_hdl,
								 vdev, tid, is_igmp,
								 nbuf, dp_peer);
				dp_peer_unref_delete(dp_peer,
						     DP_MOD_ID_MCAST2UCAST);
			}
			/* return if all clients are processed */
			if (new_mac_idx == new_mac_cnt - 1) {
				dp_vdev_unref_delete(soc, vdev,
						     DP_MOD_ID_MCAST2UCAST);
				qdf_nbuf_free(nbuf);
				if (dms_pkt_retval)
					return dms_pkt_retval;
				return 1;
			}
			continue;
		}
		/*
		 * optimize to avoid malloc in per-packet path
		 * For eg. seg_pool can be made part of vdev structure
		 */
		seg_info_new = qdf_mem_malloc(sizeof(*seg_info_new));

		if (!seg_info_new) {
			QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
					"alloc failed");
			DP_STATS_INC(vdev, tx_i[xmit_type].mcast_en.fail_seg_alloc, 1);
			goto fail_seg_alloc;
		}

		mc_uc_buf = dp_tx_me_alloc_buf(pdev);
		if (!mc_uc_buf)
			goto fail_buf_alloc;

		/*
		 * Check if we need to clone the nbuf
		 * Or can we just use the reference for all cases
		 */
		if (new_mac_idx < (new_mac_cnt - 1)) {
			nbuf_clone = qdf_nbuf_clone((qdf_nbuf_t)nbuf);
			if (!nbuf_clone) {
				DP_STATS_INC(vdev, tx_i[xmit_type].mcast_en.clone_fail, 1);
				goto fail_clone;
			}
		} else {
			/*
			 * Update the ref
			 * to account for frame sent without cloning
			 */
			qdf_nbuf_ref(nbuf);
			nbuf_clone = nbuf;
		}

		qdf_mem_copy(mc_uc_buf->data, dstmac, QDF_MAC_ADDR_SIZE);

		status = qdf_mem_map_nbytes_single(vdev->osdev, mc_uc_buf->data,
				QDF_DMA_TO_DEVICE, QDF_MAC_ADDR_SIZE,
				&paddr_mcbuf);

		if (status) {
			QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
					"Mapping failure Error:%d", status);
			DP_STATS_INC(vdev, tx_i[xmit_type].mcast_en.dropped_map_error, 1);
			mc_uc_buf->paddr_macbuf = 0;
			goto fail_map;
		}
		mc_uc_buf->paddr_macbuf = paddr_mcbuf;
		seg_info_new->frags[0].vaddr =  (uint8_t *)mc_uc_buf;
		seg_info_new->frags[0].paddr_lo = (uint32_t) paddr_mcbuf;
		seg_info_new->frags[0].paddr_hi =
			(uint16_t)((uint64_t)paddr_mcbuf >> 32);
		seg_info_new->frags[0].len = QDF_MAC_ADDR_SIZE;

		/*preparing data fragment*/
		seg_info_new->frags[1].vaddr =
			qdf_nbuf_data(nbuf) + QDF_MAC_ADDR_SIZE;
		seg_info_new->frags[1].paddr_lo = (uint32_t)paddr_data;
		seg_info_new->frags[1].paddr_hi =
			(uint16_t)(((uint64_t)paddr_data) >> 32);
		seg_info_new->frags[1].len = len - QDF_MAC_ADDR_SIZE;

		seg_info_new->nbuf = nbuf_clone;
		seg_info_new->frag_cnt = 2;
		seg_info_new->total_len = len;

		seg_info_new->next = NULL;
		curr_mac_cnt++;

		if (!seg_info_head)
			seg_info_head = seg_info_new;
		else
			seg_info_tail->next = seg_info_new;

		seg_info_tail = seg_info_new;
	}

	if (!seg_info_head) {
		goto unmap_free_return;
	}

	msdu_info.u.sg_info.curr_seg = seg_info_head;
	msdu_info.num_seg = curr_mac_cnt;
	msdu_info.frm_type = dp_tx_frm_me;

	if (tid == HTT_INVALID_TID) {
		msdu_info.tid = HTT_INVALID_TID;
		if (qdf_unlikely(vdev->mcast_enhancement_en > 0) &&
		    qdf_unlikely(pdev->hmmc_tid_override_en))
			msdu_info.tid = pdev->hmmc_tid;
	} else {
		msdu_info.tid = tid;
	}

	if (is_igmp) {
		DP_STATS_INC(vdev, tx_i[xmit_type].igmp_mcast_en.igmp_ucast_converted,
			     curr_mac_cnt);
	} else {
		DP_STATS_INC(vdev, tx_i[xmit_type].mcast_en.ucast, curr_mac_cnt);
	}

	dp_tx_send_msdu_multiple(vdev, nbuf, &msdu_info);

	while (seg_info_head->next) {
		seg_info_new = seg_info_head;
		seg_info_head = seg_info_head->next;
		qdf_mem_free(seg_info_new);
	}
	qdf_mem_free(seg_info_head);

	qdf_nbuf_free(nbuf);
	dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_MCAST2UCAST);
	return new_mac_cnt;

fail_map:
	qdf_nbuf_free(nbuf_clone);

fail_clone:
	dp_tx_me_free_buf(pdev, mc_uc_buf);

fail_buf_alloc:
	qdf_mem_free(seg_info_new);

fail_seg_alloc:
	dp_tx_me_mem_free(pdev, seg_info_head);

unmap_free_return:
	qdf_nbuf_unmap(pdev->soc->osdev, nbuf, QDF_DMA_TO_DEVICE);
free_return:
	if (vdev)
		dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_MCAST2UCAST);
	qdf_nbuf_free(nbuf);
	return 1;
}
