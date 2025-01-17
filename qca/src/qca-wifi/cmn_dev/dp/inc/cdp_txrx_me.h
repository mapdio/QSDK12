/*
 * Copyright (c) 2016-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
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

/**
 * DOC: cdp_txrx_me.h
 * Define the host data path mcast enhance API functions
 * called by the host control SW and the OS interface module
 */
#ifndef _CDP_TXRX_ME_H_
#define _CDP_TXRX_ME_H_

#include <cdp_txrx_ops.h>
#include "cdp_txrx_handle.h"
#include <cdp_txrx_cmn.h>

static inline void
cdp_tx_me_alloc_descriptor(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->me_ops ||
	    !soc->ops->me_ops->tx_me_alloc_descriptor)
		return;

	soc->ops->me_ops->tx_me_alloc_descriptor(soc, pdev_id);
}

static inline void
cdp_tx_me_free_descriptor(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->me_ops ||
	    !soc->ops->me_ops->tx_me_free_descriptor)
		return;

	soc->ops->me_ops->tx_me_free_descriptor(soc, pdev_id);
}

static inline uint16_t
cdp_tx_me_convert_ucast(ol_txrx_soc_handle soc, uint8_t vdev_id,
			qdf_nbuf_t wbuf, u_int8_t newmac[][6],
			uint8_t newmaccnt, uint8_t tid, bool is_igmp,
			bool is_dms_pkt)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->me_ops ||
	    !soc->ops->me_ops->tx_me_convert_ucast)
		return 0;

	return soc->ops->me_ops->tx_me_convert_ucast
			(soc, vdev_id, wbuf, newmac, newmaccnt, tid, is_igmp,
			 is_dms_pkt);
}

static inline bool
cdp_is_peer_dms_capable(ol_txrx_soc_handle soc, uint8_t vdev_id,
			uint8_t *mac_addr)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->me_ops ||
	    !soc->ops->me_ops->is_peer_dms_capable)
		return 0;

	return soc->ops->me_ops->is_peer_dms_capable
			(soc, vdev_id, mac_addr);
}

#endif
