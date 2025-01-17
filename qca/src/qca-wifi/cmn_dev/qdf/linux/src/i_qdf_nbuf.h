/*
 * Copyright (c) 2014-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2024 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: i_qdf_nbuf.h
 * This file provides OS dependent nbuf API's.
 */

#ifndef _I_QDF_NBUF_H
#define _I_QDF_NBUF_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>
#include <asm/cacheflush.h>
#include <qdf_types.h>
#include <qdf_net_types.h>
#include <qdf_status.h>
#include <qdf_util.h>
#include <qdf_mem.h>
#include <linux/tcp.h>
#include <qdf_util.h>
#include <qdf_nbuf_frag.h>
#include "qdf_time.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0))
/* Since commit
 *  baebdf48c3600 ("net: dev: Makes sure netif_rx() can be invoked in any context.")
 *
 * the function netif_rx() can be used in preemptible/thread context as
 * well as in interrupt context.
 *
 * Use netif_rx().
 */
#define netif_rx_ni(skb) netif_rx(skb)
#endif

/*
 * Use socket buffer as the underlying implementation as skbuf .
 * Linux use sk_buff to represent both packet and data,
 * so we use sk_buffer to represent both skbuf .
 */
typedef struct sk_buff *__qdf_nbuf_t;

/*
 * typedef __qdf_nbuf_queue_head_t - abstraction for sk_buff_head linux struct
 *
 * This is used for skb queue management via linux skb buff head APIs
 */
typedef struct sk_buff_head __qdf_nbuf_queue_head_t;

/*
 * typedef __qdf_nbuf_shared_info_t for skb_shinfo linux struct
 *
 * This is used for skb shared info via linux skb shinfo APIs
 */
typedef struct skb_shared_info *__qdf_nbuf_shared_info_t;

/*
 * typedef __qdf_flow_keys_t for flow_keys linux struct
 *
 * Contains flow dissector input and output arguments
 */
typedef struct flow_keys __qdf_flow_keys_t;

#define QDF_NBUF_CB_TX_MAX_OS_FRAGS 1

#define QDF_SHINFO_SIZE    SKB_DATA_ALIGN(sizeof(struct skb_shared_info))

/* QDF_NBUF_CB_TX_MAX_EXTRA_FRAGS -
 * max tx fragments added by the driver
 * The driver will always add one tx fragment (the tx descriptor)
 */
#define QDF_NBUF_CB_TX_MAX_EXTRA_FRAGS 2
#define QDF_NBUF_CB_PACKET_TYPE_EAPOL  1
#define QDF_NBUF_CB_PACKET_TYPE_ARP    2
#define QDF_NBUF_CB_PACKET_TYPE_WAPI   3
#define QDF_NBUF_CB_PACKET_TYPE_DHCP   4
#define QDF_NBUF_CB_PACKET_TYPE_ICMP   5
#define QDF_NBUF_CB_PACKET_TYPE_ICMPv6 6
#define QDF_NBUF_CB_PACKET_TYPE_DHCPV6 7
#define QDF_NBUF_CB_PACKET_TYPE_END_INDICATION 8
#define QDF_NBUF_CB_PACKET_TYPE_TCP_ACK 9

#define RADIOTAP_BASE_HEADER_LEN sizeof(struct ieee80211_radiotap_header)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0))
#define IEEE80211_RADIOTAP_HE 23
#define IEEE80211_RADIOTAP_HE_MU 24
#endif

#define IEEE80211_RADIOTAP_HE_MU_OTHER 25

#define IEEE80211_RADIOTAP_EXT1_USIG	1
#define IEEE80211_RADIOTAP_EXT1_EHT	2

/* mark the first packet after wow wakeup */
#define QDF_MARK_FIRST_WAKEUP_PACKET   0x80000000

/* TCP Related MASK */
#define QDF_NBUF_PKT_TCPOP_FIN			0x01
#define QDF_NBUF_PKT_TCPOP_FIN_ACK		0x11
#define QDF_NBUF_PKT_TCPOP_RST			0x04

#define QDF_NBUF_TRAC_IPV4_OFFSET		14
/*
 * Make sure that qdf_dma_addr_t in the cb block is always 64 bit aligned
 */
typedef union {
	uint64_t       u64;
	qdf_dma_addr_t dma_addr;
} qdf_paddr_t;

/*
 * struct flow_info - Structure used for defining flow
 * @proto: Flow proto
 * @src_port: Source port
 * @dst_port: Destination port
 * @src_ip: Source IP (IPv4/IPv6)
 * @dst_ip: Destination IP (IPv4/IPv6)
 * @flow_label: Flow label if IPv6 is used for src_ip/dst_ip
 */
struct qdf_flow_info {
	uint8_t proto;
	uint16_t src_port;
	uint16_t dst_port;
	union {
		uint32_t ipv4_addr;
		uint32_t ipv6_addr[4];
	} src_ip;
	union {
		uint32_t ipv4_addr;
		uint32_t ipv6_addr[4];
	} dst_ip;
	uint32_t flow_label;
};

typedef void (*qdf_nbuf_trace_update_t)(char *);
typedef void (*qdf_nbuf_free_t)(__qdf_nbuf_t);

#define __qdf_nbuf_mapped_paddr_get(skb) QDF_NBUF_CB_PADDR(skb)

#define __qdf_nbuf_mapped_paddr_set(skb, paddr)	\
	(QDF_NBUF_CB_PADDR(skb) = paddr)

#define __qdf_nbuf_frag_push_head(					\
	skb, frag_len, frag_vaddr, frag_paddr)				\
	do {					\
		QDF_NBUF_CB_TX_NUM_EXTRA_FRAGS(skb) = 1;		\
		QDF_NBUF_CB_TX_EXTRA_FRAG_VADDR(skb) = frag_vaddr;	\
		QDF_NBUF_CB_TX_EXTRA_FRAG_PADDR(skb) = frag_paddr;	\
		QDF_NBUF_CB_TX_EXTRA_FRAG_LEN(skb) = frag_len;		\
	} while (0)

#define __qdf_nbuf_get_frag_vaddr(skb, frag_num)		\
	((frag_num < QDF_NBUF_CB_TX_NUM_EXTRA_FRAGS(skb)) ?		\
	 QDF_NBUF_CB_TX_EXTRA_FRAG_VADDR(skb) : ((skb)->data))

#define __qdf_nbuf_get_frag_vaddr_always(skb)       \
			QDF_NBUF_CB_TX_EXTRA_FRAG_VADDR(skb)

#define __qdf_nbuf_get_frag_paddr(skb, frag_num)			\
	((frag_num < QDF_NBUF_CB_TX_NUM_EXTRA_FRAGS(skb)) ?		\
	 QDF_NBUF_CB_TX_EXTRA_FRAG_PADDR(skb) :				\
	 /* assume that the OS only provides a single fragment */	\
	 QDF_NBUF_CB_PADDR(skb))

#define __qdf_nbuf_get_tx_frag_paddr(skb) QDF_NBUF_CB_TX_EXTRA_FRAG_PADDR(skb)

#define __qdf_nbuf_get_frag_len(skb, frag_num)			\
	((frag_num < QDF_NBUF_CB_TX_NUM_EXTRA_FRAGS(skb)) ?		\
	 QDF_NBUF_CB_TX_EXTRA_FRAG_LEN(skb) : (skb)->len)

#define __qdf_nbuf_get_frag_is_wordstream(skb, frag_num)		\
	((frag_num < QDF_NBUF_CB_TX_NUM_EXTRA_FRAGS(skb))		\
	 ? (QDF_NBUF_CB_TX_EXTRA_FRAG_WORDSTR_EFRAG(skb))		\
	 : (QDF_NBUF_CB_TX_EXTRA_FRAG_WORDSTR_NBUF(skb)))

#define __qdf_nbuf_set_frag_is_wordstream(skb, frag_num, is_wstrm)	\
	do {								\
		if (frag_num >= QDF_NBUF_CB_TX_NUM_EXTRA_FRAGS(skb))	\
			frag_num = QDF_NBUF_CB_TX_MAX_EXTRA_FRAGS;	\
		if (frag_num)						\
			QDF_NBUF_CB_TX_EXTRA_FRAG_WORDSTR_EFRAG(skb) =  \
							      is_wstrm; \
		else					\
			QDF_NBUF_CB_TX_EXTRA_FRAG_WORDSTR_NBUF(skb) =   \
							      is_wstrm; \
	} while (0)

#define __qdf_nbuf_set_vdev_ctx(skb, vdev_id) \
	do { \
		QDF_NBUF_CB_TX_VDEV_CTX((skb)) = (vdev_id); \
	} while (0)

#define __qdf_nbuf_get_vdev_ctx(skb) \
	QDF_NBUF_CB_TX_VDEV_CTX((skb))

#define __qdf_nbuf_set_tx_ftype(skb, type) \
	do { \
		QDF_NBUF_CB_TX_FTYPE((skb)) = (type); \
	} while (0)

#define __qdf_nbuf_set_vdev_xmit_type(skb, type) \
	do { \
		QDF_NBUF_CB_PKT_XMIT_TYPE((skb)) = (type); \
	} while (0)

#define __qdf_nbuf_get_tx_ftype(skb) \
		 QDF_NBUF_CB_TX_FTYPE((skb))

#define __qdf_nbuf_get_vdev_xmit_type(skb) \
		 QDF_NBUF_CB_PKT_XMIT_TYPE((skb))


#define __qdf_nbuf_set_rx_ftype(skb, type) \
	do { \
		QDF_NBUF_CB_RX_FTYPE((skb)) = (type); \
	} while (0)

#define __qdf_nbuf_get_rx_ftype(skb) \
		 QDF_NBUF_CB_RX_FTYPE((skb))

#define __qdf_nbuf_set_rx_chfrag_start(skb, val) \
	((QDF_NBUF_CB_RX_CHFRAG_START((skb))) = val)

#define __qdf_nbuf_is_rx_chfrag_start(skb) \
	(QDF_NBUF_CB_RX_CHFRAG_START((skb)))

#define __qdf_nbuf_set_rx_chfrag_cont(skb, val) \
	do { \
		(QDF_NBUF_CB_RX_CHFRAG_CONT((skb))) = val; \
	} while (0)

#define __qdf_nbuf_is_rx_chfrag_cont(skb) \
	(QDF_NBUF_CB_RX_CHFRAG_CONT((skb)))

#define __qdf_nbuf_set_rx_chfrag_end(skb, val) \
	((QDF_NBUF_CB_RX_CHFRAG_END((skb))) = val)

#define __qdf_nbuf_is_rx_chfrag_end(skb) \
	(QDF_NBUF_CB_RX_CHFRAG_END((skb)))

#define __qdf_nbuf_set_da_mcbc(skb, val) \
	((QDF_NBUF_CB_RX_DA_MCBC((skb))) = val)

#define __qdf_nbuf_is_da_mcbc(skb) \
	(QDF_NBUF_CB_RX_DA_MCBC((skb)))

#define __qdf_nbuf_set_da_valid(skb, val) \
	((QDF_NBUF_CB_RX_DA_VALID((skb))) = val)

#define __qdf_nbuf_is_da_valid(skb) \
	(QDF_NBUF_CB_RX_DA_VALID((skb)))

#define __qdf_nbuf_set_sa_valid(skb, val) \
	((QDF_NBUF_CB_RX_SA_VALID((skb))) = val)

#define __qdf_nbuf_is_sa_valid(skb) \
	(QDF_NBUF_CB_RX_SA_VALID((skb)))

#define __qdf_nbuf_set_rx_retry_flag(skb, val) \
	((QDF_NBUF_CB_RX_RETRY_FLAG((skb))) = val)

#define __qdf_nbuf_is_rx_retry_flag(skb) \
	(QDF_NBUF_CB_RX_RETRY_FLAG((skb)))

#define __qdf_nbuf_set_raw_frame(skb, val) \
	((QDF_NBUF_CB_RX_RAW_FRAME((skb))) = val)

#define __qdf_nbuf_is_raw_frame(skb) \
	(QDF_NBUF_CB_RX_RAW_FRAME((skb)))

#define __qdf_nbuf_is_fr_ds_set(skb) \
	(QDF_NBUF_CB_RX_FROM_DS((skb)))

#define __qdf_nbuf_is_to_ds_set(skb) \
	(QDF_NBUF_CB_RX_TO_DS((skb)))

#define __qdf_nbuf_get_tid_val(skb) \
	(QDF_NBUF_CB_RX_TID_VAL((skb)))

#define __qdf_nbuf_set_tid_val(skb, val) \
	((QDF_NBUF_CB_RX_TID_VAL((skb))) = val)

#define __qdf_nbuf_set_is_frag(skb, val) \
	((QDF_NBUF_CB_RX_IS_FRAG((skb))) = val)

#define __qdf_nbuf_is_frag(skb) \
	(QDF_NBUF_CB_RX_IS_FRAG((skb)))

#define __qdf_nbuf_set_tx_chfrag_start(skb, val) \
	((QDF_NBUF_CB_TX_EXTRA_FRAG_FLAGS_CHFRAG_START((skb))) = val)

#define __qdf_nbuf_is_tx_chfrag_start(skb) \
	(QDF_NBUF_CB_TX_EXTRA_FRAG_FLAGS_CHFRAG_START((skb)))

#define __qdf_nbuf_set_tx_chfrag_cont(skb, val) \
	do { \
		(QDF_NBUF_CB_TX_EXTRA_FRAG_FLAGS_CHFRAG_CONT((skb))) = val; \
	} while (0)

#define __qdf_nbuf_is_tx_chfrag_cont(skb) \
	(QDF_NBUF_CB_TX_EXTRA_FRAG_FLAGS_CHFRAG_CONT((skb)))

#define __qdf_nbuf_set_tx_chfrag_end(skb, val) \
	((QDF_NBUF_CB_TX_EXTRA_FRAG_FLAGS_CHFRAG_END((skb))) = val)

#define __qdf_nbuf_is_tx_chfrag_end(skb) \
	(QDF_NBUF_CB_TX_EXTRA_FRAG_FLAGS_CHFRAG_END((skb)))

#define __qdf_nbuf_trace_set_proto_type(skb, proto_type)  \
	(QDF_NBUF_CB_TX_PROTO_TYPE(skb) = (proto_type))

#define __qdf_nbuf_trace_get_proto_type(skb) \
	QDF_NBUF_CB_TX_PROTO_TYPE(skb)

#define __qdf_nbuf_queue_walk_safe(queue, var, tvar)	\
		skb_queue_walk_safe(queue, var, tvar)

/*
 * prototypes. Implemented in qdf_nbuf.c
 */

/**
 * __qdf_nbuf_alloc() - Allocate nbuf
 * @osdev: Device handle
 * @size: Netbuf requested size
 * @reserve: headroom to start with
 * @align: Align
 * @prio: Priority
 * @func: Function name of the call site
 * @line: line number of the call site
 *
 * This allocates a nbuf aligns if needed and reserves some space in the front,
 * since the reserve is done after alignment the reserve value if being
 * unaligned will result in an unaligned address.
 *
 * Return: nbuf or %NULL if no memory
 */
__qdf_nbuf_t
__qdf_nbuf_alloc(__qdf_device_t osdev, size_t size, int reserve, int align,
		 int prio, const char *func, uint32_t line);

__qdf_nbuf_t __qdf_nbuf_alloc_simple(__qdf_device_t osdev, size_t size,
				     const char *func, uint32_t line);

#if defined(QCA_DP_NBUF_FAST_PPEDS)
/**
 * __qdf_nbuf_alloc_ppe_ds() - Allocates nbuf
 * @osdev: Device handle
 * @size: Netbuf requested size
 * @func: Function name of the call site
 * @line: line number of the call site
 *
 * This allocates an nbuf for wifi module
 * in DS mode and uses __netdev_alloc_skb_no_skb_reset API.
 * The netdev API invokes skb_recycler_alloc with reset_skb
 * as false. Hence, recycler pool will not do reset_struct
 * when it allocates DS used buffer to DS module, which will
 * helps to improve the performance
 *
 * Return: nbuf or %NULL if no memory
 */

__qdf_nbuf_t __qdf_nbuf_alloc_ppe_ds(__qdf_device_t osdev, size_t size,
				     const char *func, uint32_t line);
#endif /* QCA_DP_NBUF_FAST_PPEDS */

/**
 * __qdf_nbuf_frag_alloc() - Allocate nbuf in page fragment way.
 * @osdev: Device handle
 * @size: Netbuf requested size
 * @reserve: headroom to start with
 * @align: Align
 * @prio: Priority
 * @func: Function name of the call site
 * @line: line number of the call site
 *
 * This allocates a nbuf aligns if needed and reserves some space in the front,
 * since the reserve is done after alignment the reserve value if being
 * unaligned will result in an unaligned address.
 * It will call into kernel page fragment APIs, long time keeping for scattered
 * allocations should be considered for avoidance.
 * This also brings in more probability of page frag allocation failures during
 * low memory situation. In case of page frag allocation failure, fallback to
 * non-frag slab allocations.
 *
 * Return: nbuf or %NULL if no memory
 */
__qdf_nbuf_t
__qdf_nbuf_frag_alloc(__qdf_device_t osdev, size_t size, int reserve, int align,
		      int prio, const char *func, uint32_t line);

/**
 * __qdf_nbuf_alloc_no_recycler() - Allocates skb
 * @size: Size to be allocated for skb
 * @reserve: Reserve headroom size
 * @align: Align data
 * @func: Function name of the call site
 * @line: Line number of the callsite
 *
 * This API allocates a nbuf and aligns it if needed and reserves some headroom
 * space after the alignment where nbuf is not allocated from skb recycler pool.
 *
 * Return: Allocated nbuf pointer
 */
__qdf_nbuf_t __qdf_nbuf_alloc_no_recycler(size_t size, int reserve, int align,
					  const char *func, uint32_t line);

/**
 * __qdf_nbuf_page_frag_alloc() - Allocate nbuf from @pf_cache page
 *				  fragment cache
 * @osdev: Device handle
 * @size: Netbuf requested size
 * @reserve: headroom to start with
 * @align: Align
 * @pf_cache: Reference to page fragment cache
 * @func: Function name of the call site
 * @line: line number of the call site
 *
 * This allocates a nbuf, aligns if needed and reserves some space in the front,
 * since the reserve is done after alignment the reserve value if being
 * unaligned will result in an unaligned address.
 *
 * It will call kernel page fragment APIs for allocation of skb->head, prefer
 * this API for buffers that are allocated and freed only once i.e., for
 * reusable buffers.
 *
 * Return: nbuf or %NULL if no memory
 */
__qdf_nbuf_t
__qdf_nbuf_page_frag_alloc(__qdf_device_t osdev, size_t size, int reserve,
			   int align, __qdf_frag_cache_t *pf_cache,
			   const char *func, uint32_t line);

/**
 * __qdf_nbuf_clone() - clone the nbuf (copy is readonly)
 * @nbuf: Pointer to network buffer
 *
 * if GFP_ATOMIC is overkill then we can check whether its
 * called from interrupt context and then do it or else in
 * normal case use GFP_KERNEL
 *
 * example     use "in_irq() || irqs_disabled()"
 *
 * Return: cloned skb
 */
__qdf_nbuf_t __qdf_nbuf_clone(__qdf_nbuf_t nbuf);

/**
 * __qdf_nbuf_free() - free the nbuf its interrupt safe
 * @skb: Pointer to network buffer
 *
 * Return: none
 */
void __qdf_nbuf_free(struct sk_buff *skb);

/**
 * __qdf_nbuf_map() - map a buffer to local bus address space
 * @osdev: OS device
 * @skb: Pointer to network buffer
 * @dir: Direction
 *
 * Return: QDF_STATUS
 */
QDF_STATUS __qdf_nbuf_map(__qdf_device_t osdev,
			struct sk_buff *skb, qdf_dma_dir_t dir);

/**
 * __qdf_nbuf_unmap() - to unmap a previously mapped buf
 * @osdev: OS device
 * @skb: Pointer to network buffer
 * @dir: dma direction
 *
 * Return: none
 */
void __qdf_nbuf_unmap(__qdf_device_t osdev,
			struct sk_buff *skb, qdf_dma_dir_t dir);

/**
 * __qdf_nbuf_map_single() - map a single buffer to local bus address space
 * @osdev: OS device
 * @skb: Pointer to network buffer
 * @dir: Direction
 *
 * Return: QDF_STATUS
 */
QDF_STATUS __qdf_nbuf_map_single(__qdf_device_t osdev,
				 struct sk_buff *skb, qdf_dma_dir_t dir);

/**
 * __qdf_nbuf_unmap_single() -  unmap a previously mapped buf
 * @osdev: OS device
 * @skb: Pointer to network buffer
 * @dir: Direction
 *
 * Return: none
 */
void __qdf_nbuf_unmap_single(__qdf_device_t osdev,
			struct sk_buff *skb, qdf_dma_dir_t dir);

/**
 * __qdf_nbuf_reg_trace_cb() - register trace callback
 * @cb_func_ptr: Pointer to trace callback function
 *
 * Return: none
 */
void __qdf_nbuf_reg_trace_cb(qdf_nbuf_trace_update_t cb_func_ptr);

/**
 * __qdf_nbuf_reg_free_cb() - register nbuf free callback
 * @cb_func_ptr: function pointer to the nbuf free callback
 *
 * This function registers a callback function for nbuf free.
 *
 * Return: none
 */
void __qdf_nbuf_reg_free_cb(qdf_nbuf_free_t cb_func_ptr);

/**
 * __qdf_nbuf_dmamap_create() - create a DMA map.
 * @osdev: qdf device handle
 * @dmap: dma map handle
 *
 * This can later be used to map networking buffers. They :
 * - need space in adf_drv's software descriptor
 * - are typically created during adf_drv_create
 * - need to be created before any API(qdf_nbuf_map) that uses them
 *
 * Return: QDF STATUS
 */
QDF_STATUS __qdf_nbuf_dmamap_create(qdf_device_t osdev, __qdf_dma_map_t *dmap);

/**
 * __qdf_nbuf_dmamap_destroy() - delete a dma map
 * @osdev: qdf device handle
 * @dmap: dma map handle
 *
 * Return: none
 */
void __qdf_nbuf_dmamap_destroy(qdf_device_t osdev, __qdf_dma_map_t dmap);

/**
 * __qdf_nbuf_dmamap_set_cb() - setup the map callback for a dma map
 * @dmap: dma map
 * @cb: callback
 * @arg: argument
 *
 * Return: none
 */
void __qdf_nbuf_dmamap_set_cb(__qdf_dma_map_t dmap, void *cb, void *arg);

/**
 * __qdf_nbuf_map_nbytes() - get the dma map of the nbuf
 * @osdev: os device
 * @skb: skb handle
 * @dir: dma direction
 * @nbytes: number of bytes to be mapped
 *
 * Return: QDF_STATUS
 */
QDF_STATUS __qdf_nbuf_map_nbytes(qdf_device_t osdev, struct sk_buff *skb,
				 qdf_dma_dir_t dir, int nbytes);

/**
 * __qdf_nbuf_unmap_nbytes() - to unmap a previously mapped buf
 * @osdev: OS device
 * @skb: skb handle
 * @dir: direction
 * @nbytes: number of bytes
 *
 * Return: none
 */
void __qdf_nbuf_unmap_nbytes(qdf_device_t osdev, struct sk_buff *skb,
			     qdf_dma_dir_t dir, int nbytes);

/**
 * __qdf_nbuf_sync_for_cpu() - nbuf sync
 * @osdev: os device
 * @skb: sk buff
 * @dir: direction
 *
 * Return: none
 */
void __qdf_nbuf_sync_for_cpu(qdf_device_t osdev, struct sk_buff *skb,
	qdf_dma_dir_t dir);

/**
 * __qdf_nbuf_dma_map_info() - return the dma map info
 * @bmap: dma map
 * @sg: dma map info
 *
 * Return: none
 */
void __qdf_nbuf_dma_map_info(__qdf_dma_map_t bmap, qdf_dmamap_info_t *sg);

/**
 * __qdf_nbuf_get_frag_size() - get frag size
 * @nbuf: sk buffer
 * @cur_frag: current frag
 *
 * Return: frag size
 */
uint32_t __qdf_nbuf_get_frag_size(__qdf_nbuf_t nbuf, uint32_t cur_frag);

/**
 * __qdf_nbuf_frag_info() - return the frag data & len, where frag no. is
 *			specified by the index
 * @skb: sk buff
 * @sg: scatter/gather list of all the frags
 *
 * Return: none
 */
void __qdf_nbuf_frag_info(struct sk_buff *skb, qdf_sglist_t  *sg);

/**
 * __qdf_nbuf_frag_map() - dma map frag
 * @osdev: os device
 * @nbuf: sk buff
 * @offset: offset
 * @dir: direction
 * @cur_frag: current fragment
 *
 * Return: QDF status
 */
QDF_STATUS __qdf_nbuf_frag_map(
	qdf_device_t osdev, __qdf_nbuf_t nbuf,
	int offset, qdf_dma_dir_t dir, int cur_frag);

/**
 * qdf_nbuf_classify_pkt() - classify packet
 * @skb: sk buff
 *
 * Return: none
 */
void qdf_nbuf_classify_pkt(struct sk_buff *skb);

/**
 * __qdf_nbuf_is_ipv4_wapi_pkt() - check if skb data is a wapi packet
 * @skb: Pointer to network buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is WAPI packet
 *	   false otherwise.
 */
bool __qdf_nbuf_is_ipv4_wapi_pkt(struct sk_buff *skb);

/**
 * __qdf_nbuf_is_ipv4_tdls_pkt() - check if skb data is a tdls packet
 * @skb: Pointer to network buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is tdls packet
 *	   false otherwise.
 */
bool __qdf_nbuf_is_ipv4_tdls_pkt(struct sk_buff *skb);

/**
 * __qdf_nbuf_data_is_ipv4_pkt() - check if packet is a ipv4 packet
 * @data: Pointer to network data
 *
 * This api is for Tx packets.
 *
 * Return: true if packet is ipv4 packet
 *	   false otherwise
 */
bool __qdf_nbuf_data_is_ipv4_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv6_pkt() - check if it is IPV6 packet.
 * @data: Pointer to IPV6 packet data buffer
 *
 * This func. checks whether it is a IPV6 packet or not.
 *
 * Return: TRUE if it is a IPV6 packet
 *         FALSE if not
 */
bool __qdf_nbuf_data_is_ipv6_pkt(uint8_t *data);

/**
 *  __qdf_nbuf_get_ether_type() - Get the ether type
 * @data: Pointer to network data buffer
 *
 * Get the ether type in case of 8021Q and 8021AD tag
 * is present in L2 header, e.g for the returned ether type
 * value, if IPV4 data ether type 0x0800, return 0x0008.
 *
 * Return ether type.
 */
uint16_t __qdf_nbuf_get_ether_type(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv4_mcast_pkt() - check if it is IPV4 multicast packet.
 * @data: Pointer to IPV4 packet data buffer
 *
 * This func. checks whether it is a IPV4 multicast packet or not.
 *
 * Return: TRUE if it is a IPV4 multicast packet
 *         FALSE if not
 */
bool __qdf_nbuf_data_is_ipv4_mcast_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv6_mcast_pkt() - check if it is IPV6 multicast packet.
 * @data: Pointer to IPV6 packet data buffer
 *
 * This func. checks whether it is a IPV6 multicast packet or not.
 *
 * Return: TRUE if it is a IPV6 multicast packet
 *         FALSE if not
 */
bool __qdf_nbuf_data_is_ipv6_mcast_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_icmp_pkt() - check if it is IPV4 ICMP packet.
 * @data: Pointer to IPV4 ICMP packet data buffer
 *
 * This func. checks whether it is a ICMP packet or not.
 *
 * Return: TRUE if it is a ICMP packet
 *         FALSE if not
 */
bool __qdf_nbuf_data_is_icmp_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_icmpv6_pkt() - check if it is IPV6 ICMPV6 packet.
 * @data: Pointer to IPV6 ICMPV6 packet data buffer
 *
 * This func. checks whether it is a ICMPV6 packet or not.
 *
 * Return: TRUE if it is a ICMPV6 packet
 *         FALSE if not
 */
bool __qdf_nbuf_data_is_icmpv6_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv4_udp_pkt() - check if it is IPV4 UDP packet.
 * @data: Pointer to IPV4 UDP packet data buffer
 *
 * This func. checks whether it is a IPV4 UDP packet or not.
 *
 * Return: TRUE if it is a IPV4 UDP packet
 *         FALSE if not
 */
bool __qdf_nbuf_data_is_ipv4_udp_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv4_tcp_pkt() - check if it is IPV4 TCP packet.
 * @data: Pointer to IPV4 TCP packet data buffer
 *
 * This func. checks whether it is a IPV4 TCP packet or not.
 *
 * Return: TRUE if it is a IPV4 TCP packet
 *         FALSE if not
 */
bool __qdf_nbuf_data_is_ipv4_tcp_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv6_udp_pkt() - check if it is IPV6 UDP packet.
 * @data: Pointer to IPV6 UDP packet data buffer
 *
 * This func. checks whether it is a IPV6 UDP packet or not.
 *
 * Return: TRUE if it is a IPV6 UDP packet
 *         FALSE if not
 */
bool __qdf_nbuf_data_is_ipv6_udp_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv6_tcp_pkt() - check if it is IPV6 TCP packet.
 * @data: Pointer to IPV6 TCP packet data buffer
 *
 * This func. checks whether it is a IPV6 TCP packet or not.
 *
 * Return: TRUE if it is a IPV6 TCP packet
 *         FALSE if not
 */
bool __qdf_nbuf_data_is_ipv6_tcp_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv4_dhcp_pkt() - check if skb data is a dhcp packet
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is DHCP packet
 *	   false otherwise
 */
bool __qdf_nbuf_data_is_ipv4_dhcp_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv6_dhcp_pkt() - check if skb data is a dhcp packet
 * @data: Pointer to network data buffer
 *
 * This api is for ipv6 packet.
 *
 * Return: true if packet is DHCP packet
 *	   false otherwise
 */
bool __qdf_nbuf_data_is_ipv6_dhcp_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv6_mdns_pkt() - check if skb data is a mdns packet
 * @data: Pointer to network data buffer
 *
 * This api is for ipv6 packet.
 *
 * Return: true if packet is MDNS packet
 *	   false otherwise
 */
bool __qdf_nbuf_data_is_ipv6_mdns_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv4_eapol_pkt() - check if skb data is a eapol packet
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is EAPOL packet
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_ipv4_eapol_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv4_igmp_pkt() - check if skb data is a igmp packet
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is igmp packet
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_ipv4_igmp_pkt(uint8_t *data);

/**
 * __qdf_nbuf_data_is_ipv6_igmp_pkt() - check if skb data is a igmp packet
 * @data: Pointer to network data buffer
 *
 * This api is for ipv6 packet.
 *
 * Return: true if packet is igmp packet
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_ipv6_igmp_pkt(uint8_t *data);

/**
 * __qdf_nbuf_is_ipv4_igmp_leave_pkt() - check if skb is a igmp leave packet
 * @buf: Pointer to network buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is igmp packet
 *	   false otherwise.
 */
bool __qdf_nbuf_is_ipv4_igmp_leave_pkt(__qdf_nbuf_t buf);

/**
 * __qdf_nbuf_is_ipv6_igmp_leave_pkt() - check if skb is a igmp leave packet
 * @buf: Pointer to network buffer
 *
 * This api is for ipv6 packet.
 *
 * Return: true if packet is igmp packet
 *	   false otherwise.
 */
bool __qdf_nbuf_is_ipv6_igmp_leave_pkt(__qdf_nbuf_t buf);

/**
 * __qdf_nbuf_data_is_ipv4_arp_pkt() - check if skb data is a arp packet
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is ARP packet
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_ipv4_arp_pkt(uint8_t *data);

/**
 * __qdf_nbuf_is_bcast_pkt() - is destination address broadcast
 * @nbuf: sk buff
 *
 * Return: true if packet is broadcast
 *	   false otherwise
 */
bool __qdf_nbuf_is_bcast_pkt(__qdf_nbuf_t nbuf);

/**
 * __qdf_nbuf_is_mcast_replay() - is multicast replay packet
 * @nbuf: sk buff
 *
 * Return: true if packet is multicast replay
 *	   false otherwise
 */
bool __qdf_nbuf_is_mcast_replay(__qdf_nbuf_t nbuf);

/**
 * __qdf_nbuf_is_arp_local() - check if local or non local arp
 * @skb: pointer to sk_buff
 *
 * Return: true if local arp or false otherwise.
 */
bool __qdf_nbuf_is_arp_local(struct sk_buff *skb);

/**
 * __qdf_nbuf_data_is_arp_req() - check if skb data is a arp request
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is ARP request
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_arp_req(uint8_t *data);

/**
 * __qdf_nbuf_data_is_arp_rsp() - check if skb data is a arp response
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is ARP response
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_arp_rsp(uint8_t *data);

/**
 * __qdf_nbuf_get_arp_src_ip() - get arp src IP
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: ARP packet source IP value.
 */
uint32_t __qdf_nbuf_get_arp_src_ip(uint8_t *data);

/**
 * __qdf_nbuf_get_arp_tgt_ip() - get arp target IP
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: ARP packet target IP value.
 */
uint32_t __qdf_nbuf_get_arp_tgt_ip(uint8_t *data);

/**
 * __qdf_nbuf_get_dns_domain_name() - get dns domain name
 * @data: Pointer to network data buffer
 * @len: length to copy
 *
 * This api is for dns domain name
 *
 * Return: dns domain name.
 */
uint8_t *__qdf_nbuf_get_dns_domain_name(uint8_t *data, uint32_t len);

/**
 * __qdf_nbuf_data_is_dns_query() - check if skb data is a dns query
 * @data: Pointer to network data buffer
 *
 * This api is for dns query packet.
 *
 * Return: true if packet is dns query packet.
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_dns_query(uint8_t *data);

/**
 * __qdf_nbuf_data_is_dns_response() - check if skb data is a dns response
 * @data: Pointer to network data buffer
 *
 * This api is for dns query response.
 *
 * Return: true if packet is dns response packet.
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_dns_response(uint8_t *data);

/**
 * __qdf_nbuf_data_is_tcp_fin() - check if skb data is a tcp fin
 * @data: Pointer to network data buffer
 *
 * This api is to check if the packet is tcp fin.
 *
 * Return: true if packet is tcp fin packet.
 *         false otherwise.
 */
bool __qdf_nbuf_data_is_tcp_fin(uint8_t *data);

/**
 * __qdf_nbuf_data_is_tcp_fin_ack() - check if skb data is a tcp fin ack
 * @data: Pointer to network data buffer
 *
 * This api is to check if the tcp packet is fin ack.
 *
 * Return: true if packet is tcp fin ack packet.
 *         false otherwise.
 */
bool __qdf_nbuf_data_is_tcp_fin_ack(uint8_t *data);

/**
 * __qdf_nbuf_data_is_tcp_syn() - check if skb data is a tcp syn
 * @data: Pointer to network data buffer
 *
 * This api is for tcp syn packet.
 *
 * Return: true if packet is tcp syn packet.
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_tcp_syn(uint8_t *data);

/**
 * __qdf_nbuf_data_is_tcp_syn_ack() - check if skb data is a tcp syn ack
 * @data: Pointer to network data buffer
 *
 * This api is for tcp syn ack packet.
 *
 * Return: true if packet is tcp syn ack packet.
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_tcp_syn_ack(uint8_t *data);

/**
 * __qdf_nbuf_data_is_tcp_rst() - check if skb data is a tcp rst
 * @data: Pointer to network data buffer
 *
 * This api is to check if the tcp packet is rst.
 *
 * Return: true if packet is tcp rst packet.
 *         false otherwise.
 */
bool __qdf_nbuf_data_is_tcp_rst(uint8_t *data);

/**
 * __qdf_nbuf_data_is_tcp_ack() - check if skb data is a tcp ack
 * @data: Pointer to network data buffer
 *
 * This api is for tcp ack packet.
 *
 * Return: true if packet is tcp ack packet.
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_tcp_ack(uint8_t *data);

/**
 * __qdf_nbuf_data_get_tcp_src_port() - get tcp src port
 * @data: Pointer to network data buffer
 *
 * This api is for tcp packet.
 *
 * Return: tcp source port value.
 */
uint16_t __qdf_nbuf_data_get_tcp_src_port(uint8_t *data);

/**
 * __qdf_nbuf_data_get_tcp_dst_port() - get tcp dst port
 * @data: Pointer to network data buffer
 *
 * This api is for tcp packet.
 *
 * Return: tcp destination port value.
 */
uint16_t __qdf_nbuf_data_get_tcp_dst_port(uint8_t *data);

/**
 * __qdf_nbuf_data_is_icmpv4_req() - check if skb data is a icmpv4 request
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 req packet.
 *
 * Return: true if packet is icmpv4 request
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_icmpv4_req(uint8_t *data);

/**
 * __qdf_nbuf_data_is_icmpv4_redirect() - check if skb data is a icmpv4 redirect
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 req packet.
 *
 * Return: true if packet is icmpv4 redirect
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_icmpv4_redirect(uint8_t *data);

/**
 * __qdf_nbuf_data_is_icmpv6_redirect() - check if skb data is a icmpv6 redirect
 * @data: Pointer to network data buffer
 *
 * This api is for ipv6 req packet.
 *
 * Return: true if packet is icmpv6 redirect
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_icmpv6_redirect(uint8_t *data);

/**
 * __qdf_nbuf_data_is_icmpv4_rsp() - check if skb data is a icmpv4 res
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 res packet.
 *
 * Return: true if packet is icmpv4 response
 *	   false otherwise.
 */
bool __qdf_nbuf_data_is_icmpv4_rsp(uint8_t *data);

/**
 * __qdf_nbuf_get_icmpv4_src_ip() - get icmpv4 src IP
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: icmpv4 packet source IP value.
 */
uint32_t __qdf_nbuf_get_icmpv4_src_ip(uint8_t *data);

/**
 * __qdf_nbuf_get_icmpv4_tgt_ip() - get icmpv4 target IP
 * @data: Pointer to network data buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: icmpv4 packet target IP value.
 */
uint32_t __qdf_nbuf_get_icmpv4_tgt_ip(uint8_t *data);

/**
 * __qdf_nbuf_data_get_dhcp_subtype() - get the subtype
 *              of DHCP packet.
 * @data: Pointer to DHCP packet data buffer
 *
 * This func. returns the subtype of DHCP packet.
 *
 * Return: subtype of the DHCP packet.
 */
enum qdf_proto_subtype  __qdf_nbuf_data_get_dhcp_subtype(uint8_t *data);

/**
 * __qdf_nbuf_data_get_eapol_subtype() - get the subtype of EAPOL packet.
 * @data: Pointer to EAPOL packet data buffer
 *
 * This func. returns the subtype of EAPOL packet.
 *
 * Return: subtype of the EAPOL packet.
 */
enum qdf_proto_subtype  __qdf_nbuf_data_get_eapol_subtype(uint8_t *data);

/**
 * __qdf_nbuf_data_get_arp_subtype() - get the subtype
 *            of ARP packet.
 * @data: Pointer to ARP packet data buffer
 *
 * This func. returns the subtype of ARP packet.
 *
 * Return: subtype of the ARP packet.
 */
enum qdf_proto_subtype  __qdf_nbuf_data_get_arp_subtype(uint8_t *data);

/**
 * __qdf_nbuf_data_get_icmp_subtype() - get the subtype
 *            of IPV4 ICMP packet.
 * @data: Pointer to IPV4 ICMP packet data buffer
 *
 * This func. returns the subtype of ICMP packet.
 *
 * Return: subtype of the ICMP packet.
 */
enum qdf_proto_subtype  __qdf_nbuf_data_get_icmp_subtype(uint8_t *data);

/**
 * __qdf_nbuf_data_get_icmpv6_subtype() - get the subtype
 *            of IPV6 ICMPV6 packet.
 * @data: Pointer to IPV6 ICMPV6 packet data buffer
 *
 * This func. returns the subtype of ICMPV6 packet.
 *
 * Return: subtype of the ICMPV6 packet.
 */
enum qdf_proto_subtype  __qdf_nbuf_data_get_icmpv6_subtype(uint8_t *data);

/**
 * __qdf_nbuf_data_get_ipv4_proto() - get the proto type
 *            of IPV4 packet.
 * @data: Pointer to IPV4 packet data buffer
 *
 * This func. returns the proto type of IPV4 packet.
 *
 * Return: proto type of IPV4 packet.
 */
uint8_t __qdf_nbuf_data_get_ipv4_proto(uint8_t *data);

/**
 * __qdf_nbuf_data_get_ipv6_proto() - get the proto type
 *            of IPV6 packet.
 * @data: Pointer to IPV6 packet data buffer
 *
 * This func. returns the proto type of IPV6 packet.
 *
 * Return: proto type of IPV6 packet.
 */
uint8_t __qdf_nbuf_data_get_ipv6_proto(uint8_t *data);

/**
 * __qdf_nbuf_data_get_ipv4_tos() - get the TOS type of IPv4 packet
 * @data: Pointer to skb payload
 *
 * This func. returns the TOS type of IPv4 packet.
 *
 * Return: TOS type of IPv4 packet.
 */
uint8_t __qdf_nbuf_data_get_ipv4_tos(uint8_t *data);

/**
 * __qdf_nbuf_data_get_ipv6_tc() - get the TC field
 *                                 of IPv6 packet.
 * @data: Pointer to IPv6 packet data buffer
 *
 * This func. returns the TC field of IPv6 packet.
 *
 * Return: traffic classification of IPv6 packet.
 */
uint8_t __qdf_nbuf_data_get_ipv6_tc(uint8_t *data);

/**
 * __qdf_nbuf_data_set_ipv4_tos() - set the TOS for IPv4 packet
 * @data: pointer to skb payload
 * @tos: value of TOS to be set
 *
 * This func. set the TOS field of IPv4 packet.
 *
 * Return: None
 */
void __qdf_nbuf_data_set_ipv4_tos(uint8_t *data, uint8_t tos);

/**
 * __qdf_nbuf_data_set_ipv6_tc() - set the TC field
 *                                 of IPv6 packet.
 * @data: Pointer to skb payload
 * @tc: value to set to IPv6 header TC field
 *
 * This func. set the TC field of IPv6 header.
 *
 * Return: None
 */
void __qdf_nbuf_data_set_ipv6_tc(uint8_t *data, uint8_t tc);

/**
 * __qdf_nbuf_is_ipv4_last_fragment() - Check if IPv4 packet is last fragment
 * @skb: Buffer
 *
 * This function checks IPv4 packet is last fragment or not.
 * Caller has to call this function for IPv4 packets only.
 *
 * Return: True if IPv4 packet is last fragment otherwise false
 */
bool __qdf_nbuf_is_ipv4_last_fragment(struct sk_buff *skb);

/**
 * __qdf_nbuf_is_ipv4_fragment() - Check if IPv4 packet is fragment
 * @skb: Buffer
 *
 * This function checks IPv4 packet is fragment or not.
 * Caller has to call this function for IPv4 packets only.
 *
 * Return: True if IPv4 packet is fragment otherwise false
 */
bool __qdf_nbuf_is_ipv4_fragment(struct sk_buff *skb);

bool __qdf_nbuf_is_ipv4_v6_pure_tcp_ack(struct sk_buff *skb);
bool __qdf_nbuf_sock_is_ipv4_pkt(struct sk_buff *skb);
bool __qdf_nbuf_sock_is_ipv6_pkt(struct sk_buff *skb);
bool __qdf_nbuf_sock_is_udp_pkt(struct sk_buff *skb);
bool __qdf_nbuf_sock_is_tcp_pkt(struct sk_buff *skb);

#ifdef QDF_NBUF_GLOBAL_COUNT
/**
 * __qdf_nbuf_count_get() - get nbuf global count
 *
 * Return: nbuf global count
 */
int __qdf_nbuf_count_get(void);

/**
 * __qdf_nbuf_count_inc() - increment nbuf global count
 *
 * @nbuf: sk buff
 *
 * Return: void
 */
void __qdf_nbuf_count_inc(struct sk_buff *nbuf);

/**
 * __qdf_nbuf_count_dec() - decrement nbuf global count
 *
 * @nbuf: sk buff
 *
 * Return: void
 */
void __qdf_nbuf_count_dec(struct sk_buff *nbuf);

/**
 * __qdf_nbuf_mod_init() - Initialization routine for qdf_nbuf
 *
 * Return void
 */
void __qdf_nbuf_mod_init(void);

/**
 * __qdf_nbuf_mod_exit() - Unintialization routine for qdf_nbuf
 *
 * Return void
 */
void __qdf_nbuf_mod_exit(void);

#else

static inline int __qdf_nbuf_count_get(void)
{
	return 0;
}

static inline void __qdf_nbuf_count_inc(struct sk_buff *skb)
{
	return;
}

static inline void __qdf_nbuf_count_dec(struct sk_buff *skb)
{
	return;
}

static inline void __qdf_nbuf_mod_init(void)
{
	return;
}

static inline void __qdf_nbuf_mod_exit(void)
{
	return;
}
#endif

/**
 * __qdf_to_status() - OS to QDF status conversion
 * @error : OS error
 *
 * Return: QDF status
 */
static inline QDF_STATUS __qdf_to_status(signed int error)
{
	switch (error) {
	case 0:
		return QDF_STATUS_SUCCESS;
	case ENOMEM:
	case -ENOMEM:
		return QDF_STATUS_E_NOMEM;
	default:
		return QDF_STATUS_E_NOSUPPORT;
	}
}

/**
 * __qdf_nbuf_cat() - link two nbufs
 * @dst: Buffer to piggyback into
 * @src: Buffer to put
 *
 * Concat two nbufs, the new buf(src) is piggybacked into the older one.
 * It is callers responsibility to free the src skb.
 *
 * Return: QDF_STATUS (status of the call) if failed the src skb
 *         is released
 */
static inline QDF_STATUS
__qdf_nbuf_cat(struct sk_buff *dst, struct sk_buff *src)
{
	QDF_STATUS error = 0;

	qdf_assert(dst && src);

	/*
	 * Since pskb_expand_head unconditionally reallocates the skb->head
	 * buffer, first check whether the current buffer is already large
	 * enough.
	 */
	if (skb_tailroom(dst) < src->len) {
		error = pskb_expand_head(dst, 0, src->len, GFP_ATOMIC);
		if (error)
			return __qdf_to_status(error);
	}

	memcpy(skb_tail_pointer(dst), src->data, src->len);
	skb_put(dst, src->len);
	return __qdf_to_status(error);
}

/*
 * nbuf manipulation routines
 */
/**
 * __qdf_nbuf_headroom() - return the amount of tail space available
 * @skb: Pointer to network buffer
 *
 * Return: amount of tail room
 */
static inline int __qdf_nbuf_headroom(struct sk_buff *skb)
{
	return skb_headroom(skb);
}

/**
 * __qdf_nbuf_tailroom() - return the amount of tail space available
 * @skb: Pointer to network buffer
 *
 * Return: amount of tail room
 */
static inline uint32_t __qdf_nbuf_tailroom(struct sk_buff *skb)
{
	return skb_tailroom(skb);
}

/**
 * __qdf_nbuf_put_tail() - Puts data in the end
 * @skb: Pointer to network buffer
 * @size: size to be pushed
 *
 * Return: data pointer of this buf where new data has to be
 *         put, or NULL if there is not enough room in this buf.
 */
static inline uint8_t *__qdf_nbuf_put_tail(struct sk_buff *skb, size_t size)
{
	if (skb_tailroom(skb) < size) {
		if (unlikely(pskb_expand_head(skb, 0,
			size - skb_tailroom(skb), GFP_ATOMIC))) {
			__qdf_nbuf_count_dec(skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
			dev_consume_skb_any(skb);
#else
			dev_kfree_skb_any(skb);
#endif
			return NULL;
		}
	}
	return skb_put(skb, size);
}

/**
 * __qdf_nbuf_trim_tail() - trim data out from the end
 * @skb: Pointer to network buffer
 * @size: size to be popped
 *
 * Return: none
 */
static inline void __qdf_nbuf_trim_tail(struct sk_buff *skb, size_t size)
{
	return skb_trim(skb, skb->len - size);
}

/**
 * __qdf_nbuf_set_tx_ip_cksum() - re-calculate and set tx ip cksum
 * @skb: Pointer to network buffer
 *
 * Return: none
 */
static inline void __qdf_nbuf_set_tx_ip_cksum(struct sk_buff *skb)
{
	struct iphdr *iph = NULL;

	iph = (struct iphdr *)(skb->data + QDF_NBUF_TRAC_IPV4_OFFSET);
	ip_send_check(iph);
}

/**
 * __qdf_nbuf_is_ipv4_first_fragment() - check if first fragmented packet
 * @skb: Pointer to network buffer
 *
 * Return: true if first frag else false
 */
static inline bool __qdf_nbuf_is_ipv4_first_fragment(const struct sk_buff *skb)
{
	struct iphdr *iph;

	if (skb->protocol == htons(ETH_P_IP)) {
		iph = (struct iphdr *)((uint8_t *)(skb->data) +
						QDF_NBUF_TRAC_IPV4_OFFSET);
		if ((iph->frag_off & htons(IP_OFFSET)) == 0)
			return true;
	}
	return false;
}

/**
 * __qdf_nbuf_get_ipv4_flow_info() - get ipv4 flow info
 * @skb: Pointer to network buffer
 * @flow_info: pointer to qdf_flow_info
 *
 * Return: QDF_STATUS
 */
static inline
QDF_STATUS __qdf_nbuf_get_ipv4_flow_info(const struct sk_buff *skb,
					 struct qdf_flow_info *flow_info)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned int ihl;
	struct udphdr *udph;

	if (skb->protocol != htons(ETH_P_IP))
		return QDF_STATUS_E_NOSUPPORT;

	iph = (struct iphdr *)((uint8_t *)(skb->data) +
					QDF_NBUF_TRAC_IPV4_OFFSET);
	ihl = iph->ihl << 2;

	flow_info->src_ip.ipv4_addr = ntohl(iph->saddr);
	flow_info->dst_ip.ipv4_addr = ntohl(iph->daddr);
	flow_info->proto = iph->protocol;

	if (IPPROTO_UDP == iph->protocol) {
		udph = (struct udphdr *)((uint8_t *)(skb->data) +
			QDF_NBUF_TRAC_IPV4_OFFSET + ihl);
		flow_info->src_port = ntohs(udph->source);
		flow_info->dst_port = ntohs(udph->dest);
		return QDF_STATUS_SUCCESS;
	} else if (IPPROTO_TCP == iph->protocol) {
		tcph = (struct tcphdr *)((uint8_t *)(skb->data) +
			QDF_NBUF_TRAC_IPV4_OFFSET + ihl);
		flow_info->src_port = ntohs(tcph->source);
		flow_info->dst_port = ntohs(tcph->dest);
		return QDF_STATUS_SUCCESS;
	}
	return QDF_STATUS_E_NOSUPPORT;
}

/**
 * __qdf_nbuf_get_ipv6_flow_info() - get ipv6 flow info
 * @skb: Pointer to network buffer
 * @flow_info: pointer to qdf_flow_info
 *
 * Return: QDF_STATUS
 */
static inline
QDF_STATUS __qdf_nbuf_get_ipv6_flow_info(const struct sk_buff *skb,
					 struct qdf_flow_info *flow_info)
{
	struct ipv6hdr *ipv6h;
	unsigned char offset;
	unsigned int nexthdr;

	if (skb->protocol == htons(ETH_P_IPV6)) {
		ipv6h = (struct ipv6hdr *)skb_network_header(skb);

		memcpy(&flow_info->src_ip.ipv6_addr, &ipv6h->saddr,
		       sizeof(flow_info->src_ip.ipv6_addr));
		memcpy(&flow_info->dst_ip.ipv6_addr, &ipv6h->daddr,
		       sizeof(flow_info->dst_ip.ipv6_addr));

		nexthdr = ipv6h->nexthdr;
		offset = sizeof(struct ipv6hdr);

		while (nexthdr != NEXTHDR_NONE) {
			switch (nexthdr) {
			case NEXTHDR_HOP:
			case NEXTHDR_ROUTING:
			case NEXTHDR_DEST:
				nexthdr = ((struct ipv6_opt_hdr *)(skb_network_header(skb) +
						offset))->nexthdr;
				offset += (((struct ipv6_opt_hdr *)(skb_network_header(skb) +
						offset))->hdrlen + 1) << 3;
				break;
			case IPPROTO_TCP:
				if ((offset + sizeof(struct tcphdr)) > skb->len)
					return QDF_STATUS_E_INVAL;

				flow_info->src_port = ntohs(*(uint16_t *)
					(skb_network_header(skb) + offset));
				flow_info->dst_port = ntohs(*(uint16_t *)
					(skb_network_header(skb) + offset + 2));
				flow_info->proto = IPPROTO_TCP;
				return QDF_STATUS_SUCCESS;
			case IPPROTO_UDP:
				if ((offset + sizeof(struct udphdr)) > skb->len)
					return QDF_STATUS_E_INVAL;

				flow_info->src_port = ntohs(*(uint16_t *)
					(skb_network_header(skb) + offset));
				flow_info->dst_port = ntohs(*(uint16_t *)
					(skb_network_header(skb) + offset + 2));
				flow_info->proto = IPPROTO_UDP;
				return QDF_STATUS_SUCCESS;
			default:
				return QDF_STATUS_E_NOSUPPORT;
			}
		}
	}
	return QDF_STATUS_E_NOSUPPORT;
}

/**
 * __qdf_nbuf_flow_dissect_flow_keys() - extract the flow_keys struct and return
 * @skb: Pointer to network buffer
 * @flow: list of flow keys
 *
 * Return: true if successful else false
 */
static inline bool __qdf_nbuf_flow_dissect_flow_keys(const struct sk_buff *skb,
						     struct flow_keys *flow)
{
	return skb_flow_dissect_flow_keys(skb, flow,
					  FLOW_DISSECTOR_F_PARSE_1ST_FRAG);
}

/**
 * __qdf_flow_is_frag() - check if fragmented packet
 * @flow: list of flow keys
 *
 * Return: true if frag else false
 */
static inline unsigned int __qdf_flow_is_frag(struct flow_keys *flow)
{
	if (flow->control.flags & FLOW_DIS_IS_FRAGMENT)
		return true;
	else
		return false;
}

/**
 * __qdf_flow_is_first_frag() - check if first fragmented packet
 * @flow: list of flow keys
 *
 * Return: true if first frag else false
 */
static inline unsigned int __qdf_flow_is_first_frag(struct flow_keys *flow)
{
	unsigned int flags = FLOW_DIS_FIRST_FRAG | FLOW_DIS_IS_FRAGMENT;

	if ((flow->control.flags & flags) == flags)
		return true;
	else
		return false;
}

/**
 * __qdf_flow_get_proto() - get proto from flow
 * @flow: list of flow keys
 *
 * Return: protocol
 */
static inline qdf_be16_t __qdf_flow_get_proto(struct flow_keys *flow)
{
	return flow->basic.ip_proto;
}

/**
 * __qdf_flow_get_flow_label() - get flow_label from flow
 * @flow: list of flow keys
 *
 * Return: IPv6 flow label
 */
static inline unsigned int  __qdf_flow_get_flow_label(struct flow_keys *flow)
{
	return flow->tags.flow_label;
}

/**
 * __qdf_flow_get_ipv4_src_addr() - get ipv4 src ip addr
 * @flow: list of flow keys
 *
 * Return: ipv4 src address
 */
static inline unsigned int __qdf_flow_get_ipv4_src_addr(struct flow_keys *flow)
{
	return flow->addrs.v4addrs.src;
}

/**
 * __qdf_flow_get_ipv4_dst_addr() - get ipv4 dst ip addr
 * @flow: list of flow keys
 *
 * Return: ipv4 dst address
 */
static inline unsigned int __qdf_flow_get_ipv4_dst_addr(struct flow_keys *flow)
{
	return flow->addrs.v4addrs.dst;
}

/**
 * __qdf_flow_get_ipv6_src_addr() - get ipv6 src ip addr
 * @flow: list of flow keys
 * @buf: ipv6 addr buffer
 *
 * Return: none
 */
static inline void __qdf_flow_get_ipv6_src_addr(struct flow_keys *flow,
						void *buf)
{
	memcpy(buf, &flow->addrs.v6addrs.src, sizeof(flow->addrs.v6addrs.src));
}

/**
 * __qdf_flow_get_ipv6_dst_addr() - get ipv6 dst ip addr
 * @flow: list of flow keys
 * @buf: ipv6 addr buffer
 *
 * Return: none
 */
static inline void __qdf_flow_get_ipv6_dst_addr(struct flow_keys *flow,
						void *buf)
{
	memcpy(buf, &flow->addrs.v6addrs.dst, sizeof(flow->addrs.v6addrs.dst));
}

/**
 * __qdf_nbuf_flow_get_ports() - extract the upper layer ports
 * @skb: Pointer to network buffer
 * @flow: list of flow keys
 *
 * Return: none
 */
static inline void __qdf_nbuf_flow_get_ports(const struct sk_buff *skb,
					     struct flow_keys *flow)
{
	flow->ports.ports = skb_flow_get_ports(skb, flow->control.thoff,
				  flow->basic.ip_proto);
}

/**
 * __qdf_flow_parse_src_port() - parse src port from flow keys
 * @flow: list of flow keys
 *
 * Return: src port
 */
static inline unsigned short __qdf_flow_parse_src_port(struct flow_keys *flow)
{
	return flow->ports.src;
}

/**
 * __qdf_flow_parse_dst_port() - parse dst port from flow keys
 * @flow: list of flow keys
 *
 * Return: dst port
 */
static inline unsigned short __qdf_flow_parse_dst_port(struct flow_keys *flow)
{
	return flow->ports.dst;
}

/*
 * prototypes. Implemented in qdf_nbuf.c
 */

/**
 * __qdf_nbuf_get_tx_cksum() - get tx checksum
 * @skb: Pointer to network buffer
 *
 * Return: TX checksum value
 */
qdf_nbuf_tx_cksum_t __qdf_nbuf_get_tx_cksum(struct sk_buff *skb);

/**
 * __qdf_nbuf_set_rx_cksum() - set rx checksum
 * @skb: Pointer to network buffer
 * @cksum: Pointer to checksum value
 *
 * Return: QDF_STATUS
 */
QDF_STATUS __qdf_nbuf_set_rx_cksum(struct sk_buff *skb,
				   qdf_nbuf_rx_cksum_t *cksum);

/**
 * __qdf_nbuf_get_tid() - get tid
 * @skb: Pointer to network buffer
 *
 * Return: tid
 */
uint8_t __qdf_nbuf_get_tid(struct sk_buff *skb);

/**
 * __qdf_nbuf_set_tid() - set tid
 * @skb: Pointer to network buffer
 * @tid: TID value to set
 *
 * Return: none
 */
void __qdf_nbuf_set_tid(struct sk_buff *skb, uint8_t tid);

/**
 * __qdf_nbuf_get_exemption_type() - get exemption type
 * @skb: Pointer to network buffer
 *
 * Return: exemption type
 */
uint8_t __qdf_nbuf_get_exemption_type(struct sk_buff *skb);

/**
 * __qdf_nbuf_ref() - Reference the nbuf so it can get held until the last free.
 * @skb: sk_buff handle
 *
 * Return: none
 */

void __qdf_nbuf_ref(struct sk_buff *skb);

/**
 * __qdf_nbuf_shared() - Check whether the buffer is shared
 *  @skb: sk_buff buffer
 *
 *  Return: true if more than one person has a reference to this buffer.
 */
int __qdf_nbuf_shared(struct sk_buff *skb);

/**
 * __qdf_nbuf_get_nr_frags() - return the number of fragments in an skb,
 * @skb: sk buff
 *
 * Return: number of fragments
 */
static inline size_t __qdf_nbuf_get_nr_frags(struct sk_buff *skb)
{
	return skb_shinfo(skb)->nr_frags;
}

/**
 * __qdf_nbuf_get_nr_frags_in_fraglist() - return the number of fragments
 * @skb: sk buff
 *
 * This API returns a total number of fragments from the fraglist
 * Return: total number of fragments
 */
static inline uint32_t __qdf_nbuf_get_nr_frags_in_fraglist(struct sk_buff *skb)
{
	uint32_t num_frag = 0;
	struct sk_buff *list = NULL;

	num_frag = skb_shinfo(skb)->nr_frags;
	skb_walk_frags(skb, list)
		num_frag += skb_shinfo(list)->nr_frags;

	return num_frag;
}

/*
 * qdf_nbuf_pool_delete() implementation - do nothing in linux
 */
#define __qdf_nbuf_pool_delete(osdev)

/**
 * __qdf_nbuf_copy() - returns a private copy of the skb
 * @skb: Pointer to network buffer
 *
 * This API returns a private copy of the skb, the skb returned is completely
 *  modifiable by callers
 *
 * Return: skb or NULL
 */
static inline struct sk_buff *__qdf_nbuf_copy(struct sk_buff *skb)
{
	struct sk_buff *skb_new = NULL;

	skb_new = skb_copy(skb, GFP_ATOMIC);
	if (skb_new) {
		__qdf_nbuf_count_inc(skb_new);
	}
	return skb_new;
}

#define __qdf_nbuf_reserve      skb_reserve

/**
 * __qdf_nbuf_set_data_pointer() - set buffer data pointer
 * @skb: Pointer to network buffer
 * @data: data pointer
 *
 * Return: none
 */
static inline void
__qdf_nbuf_set_data_pointer(struct sk_buff *skb, uint8_t *data)
{
	skb->data = data;
}

/**
 * __qdf_nbuf_set_len() - set buffer data length
 * @skb: Pointer to network buffer
 * @len: data length
 *
 * Return: none
 */
static inline void
__qdf_nbuf_set_len(struct sk_buff *skb, uint32_t len)
{
	skb->len = len;
}

/**
 * __qdf_nbuf_set_tail_pointer() - set buffer data tail pointer
 * @skb: Pointer to network buffer
 * @len: skb data length
 *
 * Return: none
 */
static inline void
__qdf_nbuf_set_tail_pointer(struct sk_buff *skb, int len)
{
	skb_set_tail_pointer(skb, len);
}

/**
 * __qdf_nbuf_unlink_no_lock() - unlink an skb from skb queue
 * @skb: Pointer to network buffer
 * @list: list to use
 *
 * This is a lockless version, driver must acquire locks if it
 * needs to synchronize
 *
 * Return: none
 */
static inline void
__qdf_nbuf_unlink_no_lock(struct sk_buff *skb, struct sk_buff_head *list)
{
	__skb_unlink(skb, list);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
/**
 * __qdf_nbuf_is_dev_scratch_supported() - dev_scratch support for network
 *                                         buffer in kernel
 *
 * Return: true if dev_scratch is supported
 *         false if dev_scratch is not supported
 */
static inline bool __qdf_nbuf_is_dev_scratch_supported(void)
{
	return true;
}

/**
 * __qdf_nbuf_get_dev_scratch() - get dev_scratch of network buffer
 * @skb: Pointer to network buffer
 *
 * Return: dev_scratch if dev_scratch supported
 *         0 if dev_scratch not supported
 */
static inline unsigned long __qdf_nbuf_get_dev_scratch(struct sk_buff *skb)
{
	return skb->dev_scratch;
}

/**
 * __qdf_nbuf_set_dev_scratch() - set dev_scratch of network buffer
 * @skb: Pointer to network buffer
 * @value: value to be set in dev_scratch of network buffer
 *
 * Return: void
 */
static inline void
__qdf_nbuf_set_dev_scratch(struct sk_buff *skb, unsigned long value)
{
	skb->dev_scratch = value;
}
#else
static inline bool __qdf_nbuf_is_dev_scratch_supported(void)
{
	return false;
}

static inline unsigned long __qdf_nbuf_get_dev_scratch(struct sk_buff *skb)
{
	return 0;
}

static inline void
__qdf_nbuf_set_dev_scratch(struct sk_buff *skb, unsigned long value)
{
}
#endif /* KERNEL_VERSION(4, 14, 0) */

/**
 * __qdf_nbuf_head() - return the pointer the skb's head pointer
 * @skb: Pointer to network buffer
 *
 * Return: Pointer to head buffer
 */
static inline uint8_t *__qdf_nbuf_head(struct sk_buff *skb)
{
	return skb->head;
}

/**
 * __qdf_nbuf_data() - return the pointer to data header in the skb
 * @skb: Pointer to network buffer
 *
 * Return: Pointer to skb data
 */
static inline uint8_t *__qdf_nbuf_data(struct sk_buff *skb)
{
	return skb->data;
}

static inline uint8_t *__qdf_nbuf_data_addr(struct sk_buff *skb)
{
	return (uint8_t *)&skb->data;
}

/**
 * __qdf_nbuf_get_protocol() - return the protocol value of the skb
 * @skb: Pointer to network buffer
 *
 * Return: skb protocol
 */
static inline uint16_t __qdf_nbuf_get_protocol(struct sk_buff *skb)
{
	return skb->protocol;
}

/**
 * __qdf_nbuf_get_ip_summed() - return the ip checksum value of the skb
 * @skb: Pointer to network buffer
 *
 * Return: skb ip_summed
 */
static inline uint8_t __qdf_nbuf_get_ip_summed(struct sk_buff *skb)
{
	return skb->ip_summed;
}

/**
 * __qdf_nbuf_set_ip_summed() - sets the ip_summed value of the skb
 * @skb: Pointer to network buffer
 * @ip_summed: ip checksum
 *
 * Return: none
 */
static inline void __qdf_nbuf_set_ip_summed(struct sk_buff *skb,
		 uint8_t ip_summed)
{
	skb->ip_summed = ip_summed;
}

/**
 * __qdf_nbuf_get_priority() - return the priority value of the skb
 * @skb: Pointer to network buffer
 *
 * Return: skb priority
 */
static inline uint32_t __qdf_nbuf_get_priority(struct sk_buff *skb)
{
	return skb->priority;
}

/**
 * __qdf_nbuf_set_priority() - sets the priority value of the skb
 * @skb: Pointer to network buffer
 * @p: priority
 *
 * Return: none
 */
static inline void __qdf_nbuf_set_priority(struct sk_buff *skb, uint32_t p)
{
	skb->priority = p;
}

/**
 * __qdf_nbuf_set_next() - sets the next skb pointer of the current skb
 * @skb: Current skb
 * @skb_next: Next skb
 *
 * Return: void
 */
static inline void
__qdf_nbuf_set_next(struct sk_buff *skb, struct sk_buff *skb_next)
{
	skb->next = skb_next;
}

/**
 * __qdf_nbuf_next() - return the next skb pointer of the current skb
 * @skb: Current skb
 *
 * Return: the next skb pointed to by the current skb
 */
static inline struct sk_buff *__qdf_nbuf_next(struct sk_buff *skb)
{
	return skb->next;
}

/**
 * __qdf_nbuf_set_next_ext() - sets the next skb pointer of the current skb
 * @skb: Current skb
 * @skb_next: Next skb
 *
 * This fn is used to link up extensions to the head skb. Does not handle
 * linking to the head
 *
 * Return: none
 */
static inline void
__qdf_nbuf_set_next_ext(struct sk_buff *skb, struct sk_buff *skb_next)
{
	skb->next = skb_next;
}

/**
 * __qdf_nbuf_next_ext() - return the next skb pointer of the current skb
 * @skb: Current skb
 *
 * Return: the next skb pointed to by the current skb
 */
static inline struct sk_buff *__qdf_nbuf_next_ext(struct sk_buff *skb)
{
	return skb->next;
}

/**
 * __qdf_nbuf_append_ext_list() - link list of packet extensions to the head
 * @skb_head: head_buf nbuf holding head segment (single)
 * @ext_list: nbuf list holding linked extensions to the head
 * @ext_len: Total length of all buffers in the extension list
 *
 * This function is used to link up a list of packet extensions (seg1, 2,*  ...)
 * to the nbuf holding the head segment (seg0)
 *
 * Return: none
 */
static inline void
__qdf_nbuf_append_ext_list(struct sk_buff *skb_head,
			struct sk_buff *ext_list, size_t ext_len)
{
	skb_shinfo(skb_head)->frag_list = ext_list;
	skb_head->data_len += ext_len;
	skb_head->len += ext_len;
}

/**
 * __qdf_nbuf_get_shinfo() - return the shared info of the skb
 * @head_buf: Pointer to network buffer
 *
 * Return: skb shared info from head buf
 */
static inline
struct skb_shared_info *__qdf_nbuf_get_shinfo(struct sk_buff *head_buf)
{
	return skb_shinfo(head_buf);
}

/**
 * __qdf_nbuf_get_ext_list() - Get the link to extended nbuf list.
 * @head_buf: Network buf holding head segment (single)
 *
 * This ext_list is populated when we have Jumbo packet, for example in case of
 * monitor mode amsdu packet reception, and are stiched using frags_list.
 *
 * Return: Network buf list holding linked extensions from head buf.
 */
static inline struct sk_buff *__qdf_nbuf_get_ext_list(struct sk_buff *head_buf)
{
	return (skb_shinfo(head_buf)->frag_list);
}

/**
 * __qdf_nbuf_get_age() - return the checksum value of the skb
 * @skb: Pointer to network buffer
 *
 * Return: checksum value
 */
static inline uint32_t __qdf_nbuf_get_age(struct sk_buff *skb)
{
	return skb->csum;
}

/**
 * __qdf_nbuf_set_age() - sets the checksum value of the skb
 * @skb: Pointer to network buffer
 * @v: Value
 *
 * Return: none
 */
static inline void __qdf_nbuf_set_age(struct sk_buff *skb, uint32_t v)
{
	skb->csum = v;
}

/**
 * __qdf_nbuf_adj_age() - adjusts the checksum/age value of the skb
 * @skb: Pointer to network buffer
 * @adj: Adjustment value
 *
 * Return: none
 */
static inline void __qdf_nbuf_adj_age(struct sk_buff *skb, uint32_t adj)
{
	skb->csum -= adj;
}

/**
 * __qdf_nbuf_copy_bits() - return the length of the copy bits for skb
 * @skb: Pointer to network buffer
 * @offset: Offset value
 * @len: Length
 * @to: Destination pointer
 *
 * Return: length of the copy bits for skb
 */
static inline int32_t
__qdf_nbuf_copy_bits(struct sk_buff *skb, int32_t offset, int32_t len, void *to)
{
	return skb_copy_bits(skb, offset, to, len);
}

/**
 * __qdf_nbuf_set_pktlen() - sets the length of the skb and adjust the tail
 * @skb: Pointer to network buffer
 * @len:  Packet length
 *
 * Return: none
 */
static inline void __qdf_nbuf_set_pktlen(struct sk_buff *skb, uint32_t len)
{
	if (skb->len > len) {
		skb_trim(skb, len);
	} else {
		if (skb_tailroom(skb) < len - skb->len) {
			if (unlikely(pskb_expand_head(skb, 0,
				len - skb->len - skb_tailroom(skb),
				GFP_ATOMIC))) {
				QDF_DEBUG_PANIC(
				   "SKB tailroom is lessthan requested length."
				   " tail-room: %u, len: %u, skb->len: %u",
				   skb_tailroom(skb), len, skb->len);
				__qdf_nbuf_count_dec(skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
				dev_consume_skb_any(skb);
#else
				dev_kfree_skb_any(skb);
#endif
			}
		}
		skb_put(skb, (len - skb->len));
	}
}

/**
 * __qdf_nbuf_set_protocol() - sets the protocol value of the skb
 * @skb: Pointer to network buffer
 * @protocol: Protocol type
 *
 * Return: none
 */
static inline void
__qdf_nbuf_set_protocol(struct sk_buff *skb, uint16_t protocol)
{
	skb->protocol = protocol;
}

#define __qdf_nbuf_set_tx_htt2_frm(skb, candi) \
	(QDF_NBUF_CB_TX_HL_HTT2_FRM(skb) = (candi))

#define __qdf_nbuf_get_tx_htt2_frm(skb)	\
	QDF_NBUF_CB_TX_HL_HTT2_FRM(skb)

/**
 * __qdf_dmaaddr_to_32s() - return high and low parts of dma_addr
 * @dmaaddr: DMA address
 * @lo: low 32-bits of @dmaaddr
 * @hi: high 32-bits of @dmaaddr
 *
 * Returns the high and low 32-bits of the DMA addr in the provided ptrs
 *
 * Return: N/A
 */
void __qdf_dmaaddr_to_32s(qdf_dma_addr_t dmaaddr,
				      uint32_t *lo, uint32_t *hi);

/**
 * __qdf_nbuf_get_tso_info() - function to divide a TSO nbuf
 * into segments
 * @osdev: qdf device handle
 * @skb: network buffer to be segmented
 * @tso_info: This is the output. The information about the
 *           TSO segments will be populated within this.
 *
 * This function fragments a TCP jumbo packet into smaller
 * segments to be transmitted by the driver. It chains the TSO
 * segments created into a list.
 *
 * Return: number of TSO segments
 */
uint32_t __qdf_nbuf_get_tso_info(qdf_device_t osdev, struct sk_buff *skb,
				 struct qdf_tso_info_t *tso_info);

/**
 * __qdf_nbuf_unmap_tso_segment() - function to dma unmap TSO segment element
 *
 * @osdev: qdf device handle
 * @tso_seg: TSO segment element to be unmapped
 * @is_last_seg: whether this is last tso seg or not
 *
 * Return: none
 */
void __qdf_nbuf_unmap_tso_segment(qdf_device_t osdev,
			  struct qdf_tso_seg_elem_t *tso_seg,
			  bool is_last_seg);

#ifdef FEATURE_TSO
/**
 * __qdf_nbuf_get_tcp_payload_len() - function to return the tcp
 *                                    payload len
 * @skb: buffer
 *
 * Return: size
 */
size_t __qdf_nbuf_get_tcp_payload_len(struct sk_buff *skb);

/**
 * __qdf_nbuf_get_tso_num_seg() - function to divide a TSO nbuf
 *                                into segments
 * @skb:   network buffer to be segmented
 *
 * This function fragments a TCP jumbo packet into smaller
 * segments to be transmitted by the driver. It chains the TSO
 * segments created into a list.
 *
 * Return: number of segments
 */
uint32_t __qdf_nbuf_get_tso_num_seg(struct sk_buff *skb);

#else
static inline
size_t __qdf_nbuf_get_tcp_payload_len(struct sk_buff *skb)
{
	return 0;
}

static inline uint32_t __qdf_nbuf_get_tso_num_seg(struct sk_buff *skb)
{
	return 0;
}

#endif /* FEATURE_TSO */

static inline bool __qdf_nbuf_is_tso(struct sk_buff *skb)
{
	if (skb_is_gso(skb) &&
		(skb_is_gso_v6(skb) ||
		(skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4)))
		return true;
	else
		return false;
}

struct sk_buff *__qdf_nbuf_inc_users(struct sk_buff *skb);

int __qdf_nbuf_get_users(struct sk_buff *skb);

/**
 * __qdf_nbuf_tx_info_get() - Modify pkt_type, set pkt_subtype,
 *			      and get hw_classify by peeking
 *			      into packet
 * @skb:		Network buffer (skb on Linux)
 * @pkt_type:		Pkt type (from enum htt_pkt_type)
 * @pkt_subtype:	Bit 4 of this field in HTT descriptor
 *			needs to be set in case of CE classification support
 *			Is set by this macro.
 * @hw_classify:	This is a flag which is set to indicate
 *			CE classification is enabled.
 *			Do not set this bit for VLAN packets
 *			OR for mcast / bcast frames.
 *
 * This macro parses the payload to figure out relevant Tx meta-data e.g.
 * whether to enable tx_classify bit in CE.
 *
 * Overrides pkt_type only if required for 802.3 frames (original ethernet)
 * If protocol is less than ETH_P_802_3_MIN (0x600), then
 * it is the length and a 802.3 frame else it is Ethernet Type II
 * (RFC 894).
 * Bit 4 in pkt_subtype is the tx_classify bit
 *
 * Return:	void
 */
#define __qdf_nbuf_tx_info_get(skb, pkt_type,			\
				pkt_subtype, hw_classify)	\
do {								\
	struct ethhdr *eh = (struct ethhdr *)skb->data;		\
	uint16_t ether_type = ntohs(eh->h_proto);		\
	bool is_mc_bc;						\
								\
	is_mc_bc = is_broadcast_ether_addr((uint8_t *)eh) ||	\
		   is_multicast_ether_addr((uint8_t *)eh);	\
								\
	if (likely((ether_type != ETH_P_8021Q) && !is_mc_bc)) {	\
		hw_classify = 1;				\
		pkt_subtype = 0x01 <<				\
			HTT_TX_CLASSIFY_BIT_S;			\
	}							\
								\
	if (unlikely(ether_type < ETH_P_802_3_MIN))		\
		pkt_type = htt_pkt_type_ethernet;		\
								\
} while (0)

/*
 * nbuf private buffer routines
 */

/**
 * __qdf_nbuf_peek_header() - return the header's addr & m_len
 * @skb: Pointer to network buffer
 * @addr: Pointer to store header's addr
 * @len: network buffer length
 *
 * Return: none
 */
static inline void
__qdf_nbuf_peek_header(struct sk_buff *skb, uint8_t **addr, uint32_t *len)
{
	*addr = skb->data;
	*len = skb->len;
}

/**
 * typedef __qdf_nbuf_queue_t -  network buffer queue
 * @head: Head pointer
 * @tail: Tail pointer
 * @qlen: Queue length
 */
typedef struct __qdf_nbuf_qhead {
	struct sk_buff *head;
	struct sk_buff *tail;
	unsigned int qlen;
} __qdf_nbuf_queue_t;

/******************Functions *************/

/**
 * __qdf_nbuf_queue_init() - initiallize the queue head
 * @qhead: Queue head
 *
 * Return: QDF status
 */
static inline QDF_STATUS __qdf_nbuf_queue_init(__qdf_nbuf_queue_t *qhead)
{
	memset(qhead, 0, sizeof(struct __qdf_nbuf_qhead));
	return QDF_STATUS_SUCCESS;
}

/**
 * __qdf_nbuf_queue_add() - add an skb in the tail of the queue
 * @qhead: Queue head
 * @skb: Pointer to network buffer
 *
 * This is a lockless version, driver must acquire locks if it
 * needs to synchronize
 *
 * Return: none
 */
static inline void
__qdf_nbuf_queue_add(__qdf_nbuf_queue_t *qhead, struct sk_buff *skb)
{
	skb->next = NULL;       /*Nullify the next ptr */

	if (!qhead->head)
		qhead->head = skb;
	else
		qhead->tail->next = skb;

	qhead->tail = skb;
	qhead->qlen++;
}

/**
 * __qdf_nbuf_queue_append() - Append src list at the end of dest list
 * @dest: target netbuf queue
 * @src:  source netbuf queue
 *
 * Return: target netbuf queue
 */
static inline __qdf_nbuf_queue_t *
__qdf_nbuf_queue_append(__qdf_nbuf_queue_t *dest, __qdf_nbuf_queue_t *src)
{
	if (!dest)
		return NULL;
	else if (!src || !(src->head))
		return dest;

	if (!(dest->head))
		dest->head = src->head;
	else
		dest->tail->next = src->head;

	dest->tail = src->tail;
	dest->qlen += src->qlen;
	return dest;
}

/**
 * __qdf_nbuf_queue_insert_head() - add an skb at  the head  of the queue
 * @qhead: Queue head
 * @skb: Pointer to network buffer
 *
 * This is a lockless version, driver must acquire locks if it needs to
 * synchronize
 *
 * Return: none
 */
static inline void
__qdf_nbuf_queue_insert_head(__qdf_nbuf_queue_t *qhead, __qdf_nbuf_t skb)
{
	if (!qhead->head) {
		/*Empty queue Tail pointer Must be updated */
		qhead->tail = skb;
	}
	skb->next = qhead->head;
	qhead->head = skb;
	qhead->qlen++;
}

/**
 * __qdf_nbuf_queue_remove_last() - remove a skb from the tail of the queue
 * @qhead: Queue head
 *
 * This is a lockless version. Driver should take care of the locks
 *
 * Return: skb or NULL
 */
static inline struct sk_buff *
__qdf_nbuf_queue_remove_last(__qdf_nbuf_queue_t *qhead)
{
	__qdf_nbuf_t tmp_tail, node = NULL;

	if (qhead->head) {
		qhead->qlen--;
		tmp_tail = qhead->tail;
		node = qhead->head;
		if (qhead->head == qhead->tail) {
			qhead->head = NULL;
			qhead->tail = NULL;
			return node;
		} else {
			while (tmp_tail != node->next)
			       node = node->next;
			qhead->tail = node;
			return node->next;
		}
	}
	return node;
}

/**
 * __qdf_nbuf_queue_remove() - remove a skb from the head of the queue
 * @qhead: Queue head
 *
 * This is a lockless version. Driver should take care of the locks
 *
 * Return: skb or NULL
 */
static inline
struct sk_buff *__qdf_nbuf_queue_remove(__qdf_nbuf_queue_t *qhead)
{
	__qdf_nbuf_t tmp = NULL;

	if (qhead->head) {
		qhead->qlen--;
		tmp = qhead->head;
		if (qhead->head == qhead->tail) {
			qhead->head = NULL;
			qhead->tail = NULL;
		} else {
			qhead->head = tmp->next;
		}
		tmp->next = NULL;
	}
	return tmp;
}

/**
 * __qdf_nbuf_queue_first() - returns the first skb in the queue
 * @qhead: head of queue
 *
 * Return: NULL if the queue is empty
 */
static inline struct sk_buff *
__qdf_nbuf_queue_first(__qdf_nbuf_queue_t *qhead)
{
	return qhead->head;
}

/**
 * __qdf_nbuf_queue_last() - returns the last skb in the queue
 * @qhead: head of queue
 *
 * Return: NULL if the queue is empty
 */
static inline struct sk_buff *
__qdf_nbuf_queue_last(__qdf_nbuf_queue_t *qhead)
{
	return qhead->tail;
}

/**
 * __qdf_nbuf_queue_len() - return the queue length
 * @qhead: Queue head
 *
 * Return: Queue length
 */
static inline uint32_t __qdf_nbuf_queue_len(__qdf_nbuf_queue_t *qhead)
{
	return qhead->qlen;
}

/**
 * __qdf_nbuf_queue_next() - return the next skb from packet chain
 * @skb: Pointer to network buffer
 *
 * This API returns the next skb from packet chain, remember the skb is
 * still in the queue
 *
 * Return: NULL if no packets are there
 */
static inline struct sk_buff *__qdf_nbuf_queue_next(struct sk_buff *skb)
{
	return skb->next;
}

/**
 * __qdf_nbuf_is_queue_empty() - check if the queue is empty or not
 * @qhead: Queue head
 *
 * Return: true if length is 0 else false
 */
static inline bool __qdf_nbuf_is_queue_empty(__qdf_nbuf_queue_t *qhead)
{
	return qhead->qlen == 0;
}

/*
 * Use sk_buff_head as the implementation of qdf_nbuf_queue_t.
 * Because the queue head will most likely put in some structure,
 * we don't use pointer type as the definition.
 */

/*
 * Use sk_buff_head as the implementation of qdf_nbuf_queue_t.
 * Because the queue head will most likely put in some structure,
 * we don't use pointer type as the definition.
 */

static inline void
__qdf_nbuf_set_send_complete_flag(struct sk_buff *skb, bool flag)
{
}

/**
 * __qdf_nbuf_realloc_headroom() - This keeps the skb shell intact
 *        expands the headroom
 *        in the data region. In case of failure the skb is released.
 * @skb: sk buff
 * @headroom: size of headroom
 *
 * Return: skb or NULL
 */
static inline struct sk_buff *
__qdf_nbuf_realloc_headroom(struct sk_buff *skb, uint32_t headroom)
{
	if (pskb_expand_head(skb, headroom, 0, GFP_ATOMIC)) {
		__qdf_nbuf_count_dec(skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
		dev_consume_skb_any(skb);
#else
		dev_kfree_skb_any(skb);
#endif
		skb = NULL;
	}
	return skb;
}

/**
 * __qdf_nbuf_realloc_tailroom() - This keeps the skb shell intact
 *        exapnds the tailroom
 *        in data region. In case of failure it releases the skb.
 * @skb: sk buff
 * @tailroom: size of tailroom
 *
 * Return: skb or NULL
 */
static inline struct sk_buff *
__qdf_nbuf_realloc_tailroom(struct sk_buff *skb, uint32_t tailroom)
{
	if (likely(!pskb_expand_head(skb, 0, tailroom, GFP_ATOMIC)))
		return skb;
	/**
	 * unlikely path
	 */
	__qdf_nbuf_count_dec(skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	dev_consume_skb_any(skb);
#else
	dev_kfree_skb_any(skb);
#endif
	return NULL;
}

/**
 * __qdf_nbuf_linearize() - skb linearize
 * @skb: sk buff
 *
 * create a version of the specified nbuf whose contents
 * can be safely modified without affecting other
 * users.If the nbuf is non-linear then this function
 * linearize. if unable to linearize returns -ENOMEM on
 * success 0 is returned
 *
 * Return: 0 on Success, -ENOMEM on failure is returned.
 */
static inline int
__qdf_nbuf_linearize(struct sk_buff *skb)
{
	return skb_linearize(skb);
}

/**
 * __qdf_nbuf_unshare() - skb unshare
 * @skb: sk buff
 *
 * create a version of the specified nbuf whose contents
 * can be safely modified without affecting other
 * users.If the nbuf is a clone then this function
 * creates a new copy of the data. If the buffer is not
 * a clone the original buffer is returned.
 *
 * Return: skb or NULL
 */
static inline struct sk_buff *
__qdf_nbuf_unshare(struct sk_buff *skb)
{
	struct sk_buff *skb_new;

	__qdf_frag_count_dec(__qdf_nbuf_get_nr_frags(skb));

	skb_new = skb_unshare(skb, GFP_ATOMIC);
	if (skb_new)
		__qdf_frag_count_inc(__qdf_nbuf_get_nr_frags(skb_new));

	return skb_new;
}

/**
 * __qdf_nbuf_is_cloned() - test whether the nbuf is cloned or not
 * @skb: sk buff
 *
 * Return: true/false
 */
static inline bool __qdf_nbuf_is_cloned(struct sk_buff *skb)
{
	return skb_cloned(skb);
}

/**
 * __qdf_nbuf_pool_init() - init pool
 * @net: net handle
 *
 * Return: QDF status
 */
static inline QDF_STATUS __qdf_nbuf_pool_init(qdf_net_handle_t net)
{
	return QDF_STATUS_SUCCESS;
}

/*
 * adf_nbuf_pool_delete() implementation - do nothing in linux
 */
#define __qdf_nbuf_pool_delete(osdev)

/**
 * __qdf_nbuf_expand() - Expand both tailroom & headroom. In case of failure
 *        release the skb.
 * @skb: sk buff
 * @headroom: size of headroom
 * @tailroom: size of tailroom
 *
 * Return: skb or NULL
 */
static inline struct sk_buff *
__qdf_nbuf_expand(struct sk_buff *skb, uint32_t headroom, uint32_t tailroom)
{
	if (likely(!pskb_expand_head(skb, headroom, tailroom, GFP_ATOMIC)))
		return skb;

	__qdf_nbuf_count_dec(skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	dev_consume_skb_any(skb);
#else
	dev_kfree_skb_any(skb);
#endif
	return NULL;
}

/**
 * __qdf_nbuf_copy_expand() - copy and expand nbuf
 * @buf: Network buf instance
 * @headroom: Additional headroom to be added
 * @tailroom: Additional tailroom to be added
 *
 * Return: New nbuf that is a copy of buf, with additional head and tailroom
 *	or NULL if there is no memory
 */
static inline struct sk_buff *
__qdf_nbuf_copy_expand(struct sk_buff *buf, int headroom, int tailroom)
{
	struct sk_buff *copy;
	copy = skb_copy_expand(buf, headroom, tailroom, GFP_ATOMIC);
	if (copy)
		__qdf_nbuf_count_inc(copy);

	return copy;
}

/**
 * __qdf_nbuf_has_fraglist() - check buf has fraglist
 * @buf: Network buf instance
 *
 * Return: True, if buf has frag_list else return False
 */
static inline bool
__qdf_nbuf_has_fraglist(struct sk_buff *buf)
{
	return skb_has_frag_list(buf);
}

/**
 * __qdf_nbuf_get_last_frag_list_nbuf() - Get last frag_list nbuf
 * @buf: Network buf instance
 *
 * Return: Network buf instance
 */
static inline struct sk_buff *
__qdf_nbuf_get_last_frag_list_nbuf(struct sk_buff *buf)
{
	struct sk_buff *list;

	if (!__qdf_nbuf_has_fraglist(buf))
		return NULL;

	for (list = skb_shinfo(buf)->frag_list; list->next; list = list->next)
		;

	return list;
}

/**
 * __qdf_nbuf_get_ref_fraglist() - get reference to fragments
 * @buf: Network buf instance
 *
 * Return: void
 */
static inline void
__qdf_nbuf_get_ref_fraglist(struct sk_buff *buf)
{
	struct sk_buff *list;

	skb_walk_frags(buf, list)
		skb_get(list);
}

/**
 * __qdf_nbuf_tx_cksum_info() - tx checksum info
 * @skb: Network buffer
 * @hdr_off:
 * @where:
 *
 * Return: true/false
 */
static inline bool
__qdf_nbuf_tx_cksum_info(struct sk_buff *skb, uint8_t **hdr_off,
			 uint8_t **where)
{
	qdf_assert(0);
	return false;
}

/**
 * __qdf_nbuf_reset_ctxt() - mem zero control block
 * @nbuf: buffer
 *
 * Return: none
 */
static inline void __qdf_nbuf_reset_ctxt(__qdf_nbuf_t nbuf)
{
	qdf_mem_zero(nbuf->cb, sizeof(nbuf->cb));
}

/**
 * __qdf_nbuf_network_header() - get network header
 * @buf: buffer
 *
 * Return: network header pointer
 */
static inline void *__qdf_nbuf_network_header(__qdf_nbuf_t buf)
{
	return skb_network_header(buf);
}

/**
 * __qdf_nbuf_transport_header() - get transport header
 * @buf: buffer
 *
 * Return: transport header pointer
 */
static inline void *__qdf_nbuf_transport_header(__qdf_nbuf_t buf)
{
	return skb_transport_header(buf);
}

/**
 *  __qdf_nbuf_tcp_tso_size() - return the size of TCP segment size (MSS),
 *  passed as part of network buffer by network stack
 * @skb: sk buff
 *
 * Return: TCP MSS size
 *
 */
static inline size_t __qdf_nbuf_tcp_tso_size(struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_size;
}

/**
 * __qdf_nbuf_init() - Re-initializes the skb for re-use
 * @nbuf: sk buff
 *
 * Return: none
 */
void __qdf_nbuf_init(__qdf_nbuf_t nbuf);

/**
 *  __qdf_nbuf_get_cb() - returns a pointer to skb->cb
 * @nbuf: sk buff
 *
 * Return: void ptr
 */
static inline void *
__qdf_nbuf_get_cb(__qdf_nbuf_t nbuf)
{
	return (void *)nbuf->cb;
}

/**
 * __qdf_nbuf_headlen() - return the length of linear buffer of the skb
 * @skb: sk buff
 *
 * Return: head size
 */
static inline size_t
__qdf_nbuf_headlen(struct sk_buff *skb)
{
	return skb_headlen(skb);
}

/**
 * __qdf_nbuf_tso_tcp_v4() - to check if the TSO TCP pkt is a IPv4 or not.
 * @skb: sk buff
 *
 * Return: true/false
 */
static inline bool __qdf_nbuf_tso_tcp_v4(struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_type == SKB_GSO_TCPV4 ? 1 : 0;
}

/**
 * __qdf_nbuf_tso_tcp_v6() - to check if the TSO TCP pkt is a IPv6 or not.
 * @skb: sk buff
 *
 * Return: true/false
 */
static inline bool __qdf_nbuf_tso_tcp_v6(struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_type == SKB_GSO_TCPV6 ? 1 : 0;
}

/**
 * __qdf_nbuf_l2l3l4_hdr_len() - return the l2+l3+l4 hdr length of the skb
 * @skb: sk buff
 *
 * Return: size of l2+l3+l4 header length
 */
static inline size_t __qdf_nbuf_l2l3l4_hdr_len(struct sk_buff *skb)
{
	return skb_transport_offset(skb) + tcp_hdrlen(skb);
}

/**
 * __qdf_nbuf_get_tcp_hdr_len() - return TCP header length of the skb
 * @skb: sk buff
 *
 * Return: size of TCP header length
 */
static inline size_t __qdf_nbuf_get_tcp_hdr_len(struct sk_buff *skb)
{
	return tcp_hdrlen(skb);
}

/**
 * __qdf_nbuf_is_nonlinear() - test whether the nbuf is nonlinear or not
 * @skb: sk buff
 *
 * Return:  true/false
 */
static inline bool __qdf_nbuf_is_nonlinear(struct sk_buff *skb)
{
	if (skb_is_nonlinear(skb))
		return true;
	else
		return false;
}

/**
 * __qdf_nbuf_tcp_seq() - get the TCP sequence number of the  skb
 * @skb: sk buff
 *
 * Return: TCP sequence number
 */
static inline uint32_t __qdf_nbuf_tcp_seq(struct sk_buff *skb)
{
	return ntohl(tcp_hdr(skb)->seq);
}

/**
 * __qdf_nbuf_get_priv_ptr() - get the priv pointer from the nbuf'f private space
 *@skb: sk buff
 *
 * Return: data pointer to typecast into your priv structure
 */
static inline char *
__qdf_nbuf_get_priv_ptr(struct sk_buff *skb)
{
	return &skb->cb[8];
}

/**
 * __qdf_nbuf_mark_wakeup_frame() - mark wakeup frame.
 * @buf: Pointer to nbuf
 *
 * Return: None
 */
static inline void
__qdf_nbuf_mark_wakeup_frame(__qdf_nbuf_t buf)
{
	buf->mark |= QDF_MARK_FIRST_WAKEUP_PACKET;
}

/**
 * __qdf_nbuf_record_rx_queue() - set rx queue in skb
 *
 * @skb: sk buff
 * @queue_id: Queue id
 *
 * Return: void
 */
static inline void
__qdf_nbuf_record_rx_queue(struct sk_buff *skb, uint16_t queue_id)
{
	skb_record_rx_queue(skb, queue_id);
}

/**
 * __qdf_nbuf_get_queue_mapping() - get the queue mapping set by linux kernel
 *
 * @skb: sk buff
 *
 * Return: Queue mapping
 */
static inline uint16_t
__qdf_nbuf_get_queue_mapping(struct sk_buff *skb)
{
	return skb->queue_mapping;
}

/**
 * __qdf_nbuf_set_queue_mapping() - get the queue mapping set by linux kernel
 *
 * @skb: sk buff
 * @val: queue_id
 *
 */
static inline void
__qdf_nbuf_set_queue_mapping(struct sk_buff *skb, uint16_t val)
{
	skb_set_queue_mapping(skb, val);
}

/**
 * __qdf_nbuf_set_timestamp() - set the timestamp for frame
 *
 * @skb: sk buff
 *
 * Return: void
 */
static inline void
__qdf_nbuf_set_timestamp(struct sk_buff *skb)
{
	__net_timestamp(skb);
}

/**
 * __qdf_nbuf_get_timestamp() - get the timestamp for frame
 *
 * @skb: sk buff
 *
 * Return: timestamp stored in skb in ms
 */
static inline uint64_t
__qdf_nbuf_get_timestamp(struct sk_buff *skb)
{
	return ktime_to_ms(skb_get_ktime(skb));
}

/**
 * __qdf_nbuf_get_timestamp_us() - get the timestamp for frame
 *
 * @skb: sk buff
 *
 * Return: timestamp stored in skb in us
 */
static inline uint64_t
__qdf_nbuf_get_timestamp_us(struct sk_buff *skb)
{
	return ktime_to_us(skb_get_ktime(skb));
}

/**
 * __qdf_nbuf_get_timedelta_ms() - get time difference in ms
 *
 * @skb: sk buff
 *
 * Return: time difference in ms
 */
static inline uint64_t
__qdf_nbuf_get_timedelta_ms(struct sk_buff *skb)
{
	return ktime_to_ms(net_timedelta(skb->tstamp));
}

/**
 * __qdf_nbuf_get_timedelta_us() - get time difference in micro seconds
 *
 * @skb: sk buff
 *
 * Return: time difference in micro seconds
 */
static inline uint64_t
__qdf_nbuf_get_timedelta_us(struct sk_buff *skb)
{
	return ktime_to_us(net_timedelta(skb->tstamp));
}

/**
 * __qdf_nbuf_orphan() - orphan a nbuf
 * @skb: sk buff
 *
 * If a buffer currently has an owner then we call the
 * owner's destructor function
 *
 * Return: void
 */
static inline void __qdf_nbuf_orphan(struct sk_buff *skb)
{
	return skb_orphan(skb);
}

/**
 * __qdf_nbuf_get_end_offset() - Return the size of the nbuf from
 * head pointer to end pointer
 * @nbuf: qdf_nbuf_t
 *
 * Return: size of network buffer from head pointer to end
 * pointer
 */
static inline unsigned int __qdf_nbuf_get_end_offset(__qdf_nbuf_t nbuf)
{
	return skb_end_offset(nbuf);
}

/**
 * __qdf_nbuf_get_truesize() - Return the true size of the nbuf
 * including the header and variable data area
 * @skb: sk buff
 *
 * Return: size of network buffer
 */
static inline unsigned int __qdf_nbuf_get_truesize(struct sk_buff *skb)
{
	return skb->truesize;
}

/**
 * __qdf_nbuf_get_allocsize() - Return the actual size of the skb->head
 * excluding the header and variable data area
 * @skb: sk buff
 *
 * Return: actual allocated size of network buffer
 */
static inline unsigned int __qdf_nbuf_get_allocsize(struct sk_buff *skb)
{
	return SKB_WITH_OVERHEAD(skb->truesize) -
		SKB_DATA_ALIGN(sizeof(struct sk_buff));
}

#ifdef CONFIG_WLAN_SYSFS_MEM_STATS
/**
 * __qdf_record_nbuf_nbytes() - add or subtract the size of the nbuf
 * from the total skb mem and DP tx/rx skb mem
 * @nbytes: number of bytes
 * @dir: direction
 * @is_mapped: is mapped or unmapped memory
 *
 * Return: none
 */
static inline void __qdf_record_nbuf_nbytes(
	int nbytes, qdf_dma_dir_t dir, bool is_mapped)
{
	if (is_mapped) {
		if (dir == QDF_DMA_TO_DEVICE) {
			qdf_mem_dp_tx_skb_cnt_inc();
			qdf_mem_dp_tx_skb_inc(nbytes);
		} else if (dir == QDF_DMA_FROM_DEVICE) {
			qdf_mem_dp_rx_skb_cnt_inc();
			qdf_mem_dp_rx_skb_inc(nbytes);
		}
		qdf_mem_skb_total_inc(nbytes);
	} else {
		if (dir == QDF_DMA_TO_DEVICE) {
			qdf_mem_dp_tx_skb_cnt_dec();
			qdf_mem_dp_tx_skb_dec(nbytes);
		} else if (dir == QDF_DMA_FROM_DEVICE) {
			qdf_mem_dp_rx_skb_cnt_dec();
			qdf_mem_dp_rx_skb_dec(nbytes);
		}
		qdf_mem_skb_total_dec(nbytes);
	}
}

#else /* CONFIG_WLAN_SYSFS_MEM_STATS */
static inline void __qdf_record_nbuf_nbytes(
	int nbytes, qdf_dma_dir_t dir, bool is_mapped)
{
}
#endif /* CONFIG_WLAN_SYSFS_MEM_STATS */

static inline struct sk_buff *
__qdf_nbuf_queue_head_dequeue(struct sk_buff_head *skb_queue_head)
{
	return skb_dequeue(skb_queue_head);
}

static inline
uint32_t __qdf_nbuf_queue_head_qlen(struct sk_buff_head *skb_queue_head)
{
	return skb_queue_head->qlen;
}

static inline
void __qdf_nbuf_queue_head_enqueue_tail(struct sk_buff_head *skb_queue_head,
					struct sk_buff *skb)
{
	return skb_queue_tail(skb_queue_head, skb);
}

static inline
void __qdf_nbuf_queue_head_init(struct sk_buff_head *skb_queue_head)
{
	return skb_queue_head_init(skb_queue_head);
}

static inline
void __qdf_nbuf_queue_head_purge(struct sk_buff_head *skb_queue_head)
{
	return skb_queue_purge(skb_queue_head);
}

static inline
int __qdf_nbuf_queue_empty(__qdf_nbuf_queue_head_t *nbuf_queue_head)
{
	return skb_queue_empty(nbuf_queue_head);
}

/**
 * __qdf_nbuf_queue_head_lock() - Acquire the skb list lock
 * @skb_queue_head: skb list for which lock is to be acquired
 *
 * Return: void
 */
static inline
void __qdf_nbuf_queue_head_lock(struct sk_buff_head *skb_queue_head)
{
	spin_lock_bh(&skb_queue_head->lock);
}

/**
 * __qdf_nbuf_queue_head_unlock() - Release the skb list lock
 * @skb_queue_head: skb list for which lock is to be release
 *
 * Return: void
 */
static inline
void __qdf_nbuf_queue_head_unlock(struct sk_buff_head *skb_queue_head)
{
	spin_unlock_bh(&skb_queue_head->lock);
}

/**
 * __qdf_nbuf_get_frag_size_by_idx() - Get nbuf frag size at index idx
 * @nbuf: qdf_nbuf_t
 * @idx: Index for which frag size is requested
 *
 * Return: Frag size
 */
static inline unsigned int __qdf_nbuf_get_frag_size_by_idx(__qdf_nbuf_t nbuf,
							   uint8_t idx)
{
	unsigned int size = 0;

	if (likely(idx < __QDF_NBUF_MAX_FRAGS))
		size = skb_frag_size(&skb_shinfo(nbuf)->frags[idx]);
	return size;
}

/**
 * __qdf_nbuf_get_frag_addr() - Get nbuf frag address at index idx
 * @nbuf: qdf_nbuf_t
 * @idx: Index for which frag address is requested
 *
 * Return: Frag address in success, else NULL
 */
static inline __qdf_frag_t __qdf_nbuf_get_frag_addr(__qdf_nbuf_t nbuf,
						    uint8_t idx)
{
	__qdf_frag_t frag_addr = NULL;

	if (likely(idx < __QDF_NBUF_MAX_FRAGS))
		frag_addr = skb_frag_address(&skb_shinfo(nbuf)->frags[idx]);
	return frag_addr;
}

/**
 * __qdf_nbuf_trim_add_frag_size() - Increase/Decrease frag_size by size
 * @nbuf: qdf_nbuf_t
 * @idx: Frag index
 * @size: Size by which frag_size needs to be increased/decreased
 *        +Ve means increase, -Ve means decrease
 * @truesize: truesize
 */
static inline void __qdf_nbuf_trim_add_frag_size(__qdf_nbuf_t nbuf, uint8_t idx,
						 int size,
						 unsigned int truesize)
{
	skb_coalesce_rx_frag(nbuf, idx, size, truesize);
}

/**
 * __qdf_nbuf_move_frag_page_offset() - Move frag page_offset by size
 *          and adjust length by size.
 * @nbuf: qdf_nbuf_t
 * @idx: Frag index
 * @offset: Frag page offset should be moved by offset.
 *      +Ve - Move offset forward.
 *      -Ve - Move offset backward.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS __qdf_nbuf_move_frag_page_offset(__qdf_nbuf_t nbuf, uint8_t idx,
					    int offset);

/**
 * __qdf_nbuf_remove_frag() - Remove frag from nbuf
 * @nbuf: nbuf pointer
 * @idx: frag idx need to be removed
 * @truesize: truesize of frag
 *
 * Return : void
 */
void __qdf_nbuf_remove_frag(__qdf_nbuf_t nbuf, uint16_t idx, uint16_t truesize);
/**
 * __qdf_nbuf_add_rx_frag() - Add frag to nbuf at nr_frag index
 * @buf: Frag pointer needs to be added in nbuf frag
 * @nbuf: qdf_nbuf_t where frag will be added
 * @offset: Offset in frag to be added to nbuf_frags
 * @frag_len: Frag length
 * @truesize: truesize
 * @take_frag_ref: Whether to take ref for frag or not
 *      This bool must be set as per below comdition:
 *      1. False: If this frag is being added in any nbuf
 *              for the first time after allocation.
 *      2. True: If frag is already attached part of any
 *              nbuf.
 *
 * It takes ref_count based on boolean flag take_frag_ref
 */
void __qdf_nbuf_add_rx_frag(__qdf_frag_t buf, __qdf_nbuf_t nbuf,
			    int offset, int frag_len,
			    unsigned int truesize, bool take_frag_ref);

/**
 * __qdf_nbuf_ref_frag() - get frag reference
 * @buf: Pointer to nbuf
 *
 * Return: void
 */
void __qdf_nbuf_ref_frag(qdf_frag_t buf);

/**
 * __qdf_nbuf_set_mark() - Set nbuf mark
 * @buf: Pointer to nbuf
 * @mark: Value to set mark
 *
 * Return: None
 */
static inline void __qdf_nbuf_set_mark(__qdf_nbuf_t buf, uint32_t mark)
{
	buf->mark = mark;
}

/**
 * __qdf_nbuf_get_mark() - Get nbuf mark
 * @buf: Pointer to nbuf
 *
 * Return: Value of mark
 */
static inline uint32_t __qdf_nbuf_get_mark(__qdf_nbuf_t buf)
{
	return buf->mark;
}

/**
 * __qdf_nbuf_get_data_len() - Return the size of the nbuf from
 * the data pointer to the end pointer
 * @nbuf: qdf_nbuf_t
 *
 * Return: size of skb from data pointer to end pointer
 */
static inline qdf_size_t __qdf_nbuf_get_data_len(__qdf_nbuf_t nbuf)
{
	return (skb_end_pointer(nbuf) - nbuf->data);
}

/**
 * __qdf_nbuf_set_data_len() - Return the data_len of the nbuf
 * @nbuf: qdf_nbuf_t
 * @len: data_len to be set
 *
 * Return: value of data_len
 */
static inline
qdf_size_t __qdf_nbuf_set_data_len(__qdf_nbuf_t nbuf, uint32_t len)
{
	return nbuf->data_len = len;
}

/**
 * __qdf_nbuf_get_only_data_len() - Return the data_len of the nbuf
 * @nbuf: qdf_nbuf_t
 *
 * Return: value of data_len
 */
static inline qdf_size_t __qdf_nbuf_get_only_data_len(__qdf_nbuf_t nbuf)
{
	return nbuf->data_len;
}

/**
 * __qdf_nbuf_set_hash() - set the hash of the buf
 * @buf: Network buf instance
 * @len: len to be set
 *
 * Return: None
 */
static inline void __qdf_nbuf_set_hash(__qdf_nbuf_t buf, uint32_t len)
{
	buf->hash = len;
}

/**
 * __qdf_nbuf_set_sw_hash() - set the sw hash of the buf
 * @buf: Network buf instance
 * @len: len to be set
 *
 * Return: None
 */
static inline void __qdf_nbuf_set_sw_hash(__qdf_nbuf_t buf, uint32_t len)
{
	buf->sw_hash = len;
}

/**
 * __qdf_nbuf_set_csum_start() - set the csum start of the buf
 * @buf: Network buf instance
 * @len: len to be set
 *
 * Return: None
 */
static inline void __qdf_nbuf_set_csum_start(__qdf_nbuf_t buf, uint16_t len)
{
	buf->csum_start = len;
}

/**
 * __qdf_nbuf_set_csum_offset() - set the csum offset of the buf
 * @buf: Network buf instance
 * @len: len to be set
 *
 * Return: None
 */
static inline void __qdf_nbuf_set_csum_offset(__qdf_nbuf_t buf, uint16_t len)
{
	buf->csum_offset = len;
}

/**
 * __qdf_nbuf_get_gso_segs() - Return the number of gso segments
 * @skb: Pointer to network buffer
 *
 * Return: Return the number of gso segments
 */
static inline uint16_t __qdf_nbuf_get_gso_segs(struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_segs;
}

/**
 * __qdf_nbuf_set_gso_segs() - set the number of gso segments
 * @skb: Pointer to network buffer
 * @val: val to be set
 *
 * Return: None
 */
static inline void __qdf_nbuf_set_gso_segs(struct sk_buff *skb, uint16_t val)
{
	skb_shinfo(skb)->gso_segs = val;
}

/**
 * __qdf_nbuf_set_gso_type_udp_l4() - set the gso type to GSO UDP L4
 * @skb: Pointer to network buffer
 *
 * Return: None
 */
static inline void __qdf_nbuf_set_gso_type_udp_l4(struct sk_buff *skb)
{
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
}

/**
 * __qdf_nbuf_set_ip_summed_partial() - set the ip summed to CHECKSUM_PARTIAL
 * @skb: Pointer to network buffer
 *
 * Return: None
 */
static inline void __qdf_nbuf_set_ip_summed_partial(struct sk_buff *skb)
{
	skb->ip_summed = CHECKSUM_PARTIAL;
}

/**
 * __qdf_nbuf_get_gso_size() - Return the number of gso size
 * @skb: Pointer to network buffer
 *
 * Return: Return the number of gso segments
 */
static inline unsigned int __qdf_nbuf_get_gso_size(struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_size;
}

/**
 * __qdf_nbuf_set_gso_size() - Set the gso size in nbuf
 * @skb: Pointer to network buffer
 * @val: the number of GSO segments
 *
 * Return: None
 */
static inline void
__qdf_nbuf_set_gso_size(struct sk_buff *skb, unsigned int val)
{
	skb_shinfo(skb)->gso_size = val;
}

/**
 * __qdf_nbuf_kfree() - Free nbuf using kfree
 * @skb: Pointer to network buffer
 *
 * This function is called to free the skb on failure cases
 *
 * Return: None
 */
static inline void __qdf_nbuf_kfree(struct sk_buff *skb)
{
	kfree_skb(skb);
}

/**
 * __qdf_nbuf_dev_kfree_list() - Free nbuf list using dev based os call
 * @nbuf_queue_head: Pointer to nbuf queue head
 *
 * This function is called to free the nbuf list on failure cases
 *
 * Return: None
 */
void
__qdf_nbuf_dev_kfree_list(__qdf_nbuf_queue_head_t *nbuf_queue_head);

/**
 * __qdf_nbuf_dev_queue_head() - queue a buffer using dev at the list head
 * @nbuf_queue_head: Pointer to skb list head
 * @buff: Pointer to nbuf
 *
 * This function is called to queue buffer at the skb list head
 *
 * Return: None
 */
static inline void
__qdf_nbuf_dev_queue_head(__qdf_nbuf_queue_head_t *nbuf_queue_head,
			  __qdf_nbuf_t buff)
{
	 __skb_queue_head(nbuf_queue_head, buff);
}

/**
 * __qdf_nbuf_dev_kfree() - Free nbuf using dev based os call
 * @skb: Pointer to network buffer
 *
 * This function is called to free the skb on failure cases
 *
 * Return: None
 */
static inline void __qdf_nbuf_dev_kfree(struct sk_buff *skb)
{
	dev_kfree_skb(skb);
}

/**
 * __qdf_nbuf_pkt_type_is_mcast() - check if skb pkt type is mcast
 * @skb: Network buffer
 *
 * Return: TRUE if skb pkt type is mcast
 *         FALSE if not
 */
static inline
bool __qdf_nbuf_pkt_type_is_mcast(struct sk_buff *skb)
{
	return skb->pkt_type == PACKET_MULTICAST;
}

/**
 * __qdf_nbuf_pkt_type_is_bcast() - check if skb pkt type is bcast
 * @skb: Network buffer
 *
 * Return: TRUE if skb pkt type is mcast
 *         FALSE if not
 */
static inline
bool __qdf_nbuf_pkt_type_is_bcast(struct sk_buff *skb)
{
	return skb->pkt_type == PACKET_BROADCAST;
}

/**
 * __qdf_nbuf_set_dev() - set dev of network buffer
 * @skb: Pointer to network buffer
 * @dev: value to be set in dev of network buffer
 *
 * Return: void
 */
static inline
void __qdf_nbuf_set_dev(struct sk_buff *skb, struct net_device *dev)
{
	skb->dev = dev;
}

/**
 * __qdf_nbuf_get_dev_mtu() - get dev mtu in n/w buffer
 * @skb: Pointer to network buffer
 *
 * Return: dev mtu value in nbuf
 */
static inline
unsigned int __qdf_nbuf_get_dev_mtu(struct sk_buff *skb)
{
	return skb->dev->mtu;
}

/**
 * __qdf_nbuf_set_protocol_eth_type_trans() - set protocol using eth trans
 *                                            os API
 * @skb: Pointer to network buffer
 *
 * Return: None
 */
static inline
void __qdf_nbuf_set_protocol_eth_type_trans(struct sk_buff *skb)
{
	skb->protocol = eth_type_trans(skb, skb->dev);
}

/**
 * __qdf_nbuf_net_timedelta() - get time delta
 * @t: time as __qdf_ktime_t object
 *
 * Return: time delta as ktime_t object
 */
static inline qdf_ktime_t __qdf_nbuf_net_timedelta(qdf_ktime_t t)
{
	return net_timedelta(t);
}

#ifdef CONFIG_NBUF_AP_PLATFORM
#include <i_qdf_nbuf_w.h>
#else
#include <i_qdf_nbuf_m.h>
#endif
#endif /*_I_QDF_NET_BUF_H */
