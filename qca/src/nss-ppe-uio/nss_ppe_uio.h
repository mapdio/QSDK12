/*
 * Copyright (c) 2023, Qualcomm Innovation Center, Inc. All rights reserved.
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

#ifndef __NSS_PPE_UIO_H__
#define __NSS_PPE_UIO_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/uio_driver.h>
#include <linux/list.h>

#include <linux/string.h>
#include <linux/pm_runtime.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/bitops.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/clk.h>
#include <linux/crc32.h>
#include <linux/platform_device.h>
#include <linux/mdio.h>
#include <linux/phy.h>
#include <linux/fec.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/regulator/consumer.h>
#include <linux/if_vlan.h>
#include <linux/pinctrl/consumer.h>
#include <linux/prefetch.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>

#include "ppe_uio_regs.h"
#include "ppe_uio_debug.h"

#define DRIVER_NAME	"ppe-uio"
#define PPE_UIO_HW_RESET_ID	"ppe_uio_rst"
#define PPE_UIO_SC_BYPASS		1
#define NAME_LENGTH	30
#define PPE_UIO_RX_RING_SIZE	2048
#define PPE_UIO_TX_RING_SIZE    2048

/*
 * Number of TX/RX queue supported
 */
#define PPE_UIO_QUEUE_NUM 4
#define PPE_UIO_NETDEV_TX_QUEUE_NUM	PPE_UIO_QUEUE_NUM
#define PPE_UIO_NETDEV_RX_QUEUE_NUM	PPE_UIO_QUEUE_NUM

/*
 * PPE_UIO clock's
 */
#define PPE_UIO_CSR_CLK                     "nss-csr-clk"
#define PPE_UIO_NSSNOC_CSR_CLK              "nss-nssnoc-csr-clk"
#define PPE_UIO_TS_CLK                      "nss-ts-clk"
#define PPE_UIO_NSSCC_CLK                   "nss-nsscc-clk"
#define PPE_UIO_NSSCFG_CLK                  "nss-nsscfg-clk"
#define PPE_UIO_NSSCNOC_ATB_CLK             "nss-nsscnoc-atb-clk"
#define PPE_UIO_NSSNOC_NSSCC_CLK            "nss-nssnoc-nsscc-clk"
#define PPE_UIO_NSSNOC_PCNOC_1_CLK          "nss-nssnoc-pcnoc-1-clk"
#define PPE_UIO_NSSNOC_QOSGEN_REF_CLK       "nss-nssnoc-qosgen-ref-clk"
#define PPE_UIO_NSSNOC_SNOC_1_CLK           "nss-nssnoc-snoc-1-clk"
#define PPE_UIO_NSSNOC_SNOC_CLK             "nss-nssnoc-snoc-clk"
#define PPE_UIO_NSSNOC_TIMEOUT_REF_CLK      "nss-nssnoc-timeout-ref-clk"
#define PPE_UIO_NSSNOC_XO_DCD_CLK           "nss-nssnoc-xo-dcd-clk"
#define PPE_UIO_IMEM_QSB_CLK                "nss-imem-qsb-clk"
#define PPE_UIO_NSSNOC_IMEM_QSB_CLK         "nss-nssnoc-imem-qsb-clk"
#define PPE_UIO_IMEM_AHB_CLK                "nss-imem-ahb-clk"
#define PPE_UIO_NSSNOC_IMEM_AHB_CLK         "nss-nssnoc-imem-ahb-clk"
#define PPE_UIO_MEM_NOC_NSSNOC_CLK          "nss-mem-noc-nssnoc-clk"
#define PPE_UIO_TBU_CLK                     "nss-tbu-clk"
#define PPE_UIO_NSSNOC_MEM_NOC_1_CLK        "nss-nssnoc-mem-noc-1-clk"
#define PPE_UIO_NSSNOC_MEMNOC_CLK           "nss-nssnoc-memnoc-clk"

/*
 * PPE_UIO clock's frequencies
 */
#define PPE_UIO_CSR_CLK_FREQ                        100000000
#define PPE_UIO_NSSNOC_CSR_CLK_FREQ                 100000000
#define PPE_UIO_TS_CLK_FREQ                         24000000
#define PPE_UIO_NSSCC_CLK_FREQ                      100000000
#define PPE_UIO_NSSCFG_CLK_FREQ                     100000000
#define PPE_UIO_NSSCNOC_ATB_CLK_FREQ                240000000
#define PPE_UIO_NSSNOC_NSSCC_CLK_FREQ               100000000
#define PPE_UIO_NSSNOC_PCNOC_1_CLK_FREQ             100000000
#define PPE_UIO_NSSNOC_QOSGEN_REF_CLK_FREQ          6000000
#define PPE_UIO_NSSNOC_SNOC_1_CLK_FREQ              342857143
#define PPE_UIO_NSSNOC_SNOC_CLK_FREQ                342857143
#define PPE_UIO_NSSNOC_TIMEOUT_REF_CLK_FREQ         6000000
#define PPE_UIO_NSSNOC_XO_DCD_CLK_FREQ              24000000
#define PPE_UIO_IMEM_QSB_CLK_FREQ                   353000000
#define PPE_UIO_NSSNOC_IMEM_QSB_CLK_FREQ            353000000
#define PPE_UIO_IMEM_AHB_CLK_FREQ                   100000000
#define PPE_UIO_NSSNOC_IMEM_AHB_CLK_FREQ            100000000
#define PPE_UIO_MEM_NOC_NSSNOC_CLK_FREQ             533333333
#define PPE_UIO_TBU_CLK_FREQ                        533333333
#define PPE_UIO_NSSNOC_MEM_NOC_1_CLK_FREQ           533333333
#define PPE_UIO_NSSNOC_MEMNOC_CLK_FREQ              533333333

#define PPE_UIO_MAX_PORTS		6
#define MAX_RX_FILL_RINGS               4
#define MAX_RX_DESC_RINGS_PER_PORT      4
#define MAX_TX_DESC_RINGS_PER_PORT      4
#define MAX_TX_CMPL_RINGS_PER_PORT      4

#define PPE_UIO_MAX_TXCMPL_RINGS_IDX    31      /* Max TxCmpl ring Idx  */
#define PPE_UIO_MAX_RXDESC_RINGS_IDX    23      /* Max RxDesc rings Idx */
#define PPE_UIO_MAX_RXFILL_RINGS_IDX     7      /* Max RxFill rings Idx */
#define PPE_UIO_MAX_TXDESC_RINGS_IDX    31      /* Max TxDesc rings Idx */

/*
 * Tx descriptor
 */

struct ppe_uio_pri_txdesc {
	uint32_t word0;         /* Low 32-bit of buffer address */
	uint32_t word1;         /* Buffer recycling, PTP tag flag, PRI valid flag */
	uint32_t word2;         /* Low 32-bit of opaque value */
	uint32_t word3;         /* High 32-bit of opaque value */
	uint32_t word4;         /* Source/Destination port info */
	uint32_t word5;         /* VLAN offload, csum_mode, ip_csum_en, tso_en, data length */
	uint32_t word6;         /* MSS/hash_value/PTP tag, data offset */
	uint32_t word7;         /* L4/L3 offset, PROT type, L2 type, CVLAN/SVLAN tag, service code */
};

struct ppe_uio_sec_txdesc {
	uint32_t word0;         /* Reserved */
	uint32_t word1;         /* Custom csum offset, payload offset, TTL/NAT action */
	uint32_t word2;         /* NAPT translated port, DSCP value, TTL value */
	uint32_t word3;         /* Flow index value and valid flag */
	uint32_t word4;         /* Reserved */
	uint32_t word5;         /* Reserved */
	uint32_t word6;         /* CVLAN/SVLAN command */
	uint32_t word7;         /* CVLAN/SVLAN tag value */
};

/*
 * TxCmpl descriptor
 */
struct ppe_uio_txcmpl_desc {
	uint32_t word0;         /* Low 32-bit opaque value */
	uint32_t word1;         /* High 32-bit opaque value */
	uint32_t word2;         /* More fragment, transmit ring id, pool id */
	uint32_t word3;         /* Error indications */
};

/*
 * Rx descriptor
 */
struct ppe_uio_rxdesc_desc {
	uint32_t word0;         /* Contains buffer address */
	uint32_t word1;         /* Contains more bit, priority bit, service code */
	uint32_t word2;         /* Contains opaque */
	uint32_t word3;         /* Contains opaque high bits */
	uint32_t word4;         /* Contains destination and source information */
	uint32_t word5;         /* Contains WiFi QoS, data length */
	uint32_t word6;         /* Contains hash value, check sum status */
	uint32_t word7;         /* Contains DSCP, packet offsets */
};

/*
 * Rx secondary descriptor
 */
struct ppe_uio_rxdesc_sec_desc {
	uint32_t word0;         /* Contains timestamp */
	uint32_t word1;         /* Contains secondary checksum status */
	uint32_t word2;         /* Contains QoS tag */
	uint32_t word3;         /* Contains flow index details */
	uint32_t word4;         /* Contains secondary packet offsets */
	uint32_t word5;         /* Contains multicast bit, checksum */
	uint32_t word6;         /* Contains SVLAN, CVLAN */
	uint32_t word7;         /* Contains secondary SVLAN, CVLAN */
};

/*
 * RxFill descriptor
 */
struct ppe_uio_rxfill_desc {
	uint32_t word0;         /* Contains buffer address */
	uint32_t word1;         /* Contains buffer size */
	uint32_t word2;         /* Contains opaque */
	uint32_t word3;         /* Contains opaque high bits */
};

/*
 * nss data plane device structure
 */
struct ppe_private {
	struct platform_device *pdev;	/* Platform device */
	struct resource *reg_resource;
	void __iomem *perdev_base_addr;
	int perdev_reg_size;

	unsigned long flags;		/* internal flags */
	uint32_t misc_intr;		/* Misc IRQ number */

	uint32_t tx_intr_mask;		/* Tx interrupt mask */
	uint32_t misc_intr_mask;	/* misc interrupt interrupt mask */
	uint32_t rx_alloc_size;		/* Buffer size to allocate */

	uint32_t macid;                 /* Sequence# of Mac on the platform */
	unsigned long drv_flags;        /* Driver specific feature flags */

	/* Phy related stuff */
	struct phy_device *phydev;      /* Phy device */
	struct mii_bus *miibus;         /* MII bus */
	uint32_t phy_mii_type;          /* RGMII/SGMII/QSGMII */
	uint32_t phy_mdio_addr;         /* Mdio address */
	bool link_poll;                 /* Link polling enable? */
	struct net_device *netdev;
	dma_addr_t ring_base_dma;
	int ring_dma_size;
	void *desc;
};

struct ppe_uio_info {
	atomic_t ref; /* exclusive, only one open() at a time */
	struct uio_info uio_info;
	char name[NAME_LENGTH];
};

struct ppe_dev {
	u32 index;
	struct device *dev;
	struct resource *reg_resource;
	void __iomem *reg_base;
	struct ppe_uio_info info[PPE_UIO_MAX_PORTS];
	atomic_t active_port_count;
	bool common_init_done;
	struct device_node *device_node;
	struct platform_device *pdev;
	struct ppe_private *ppe_prv[PPE_UIO_MAX_PORTS];
	uint32_t rxfill_intr_mask;	/* Rx fill ring interrupt mask */
        uint32_t rxdesc_intr_mask;	/* Rx Desc ring interrupt mask */
        uint32_t txcmpl_intr_mask;	/* Tx Cmpl ring interrupt mask */
	bool ppe_uio_initialized;

	uint32_t num_txdesc_rings;	/* Number of TxDesc rings */
        uint32_t txdesc_ring_start;	/* Id of first TXDESC ring */
        uint32_t txdesc_ring_end;	/* Id of the last TXDESC ring */
 
	uint32_t num_txcmpl_rings;	/* Number of TxCmpl rings */
	uint32_t txcmpl_ring_start;	/* Id of first TXCMPL ring */
	uint32_t txcmpl_ring_end;	/* Id of last TXCMPL ring */

	uint32_t num_rxfill_rings;	/* Number of RxFill rings */
	uint32_t rxfill_ring_start;	/* Id of first RxFill ring */
	uint32_t rxfill_ring_end;	/* Id of last RxFill ring */
 
	uint32_t num_rxdesc_rings;	/* Number of RxDesc rings */
	uint32_t rxdesc_ring_start;	/* Id of first RxDesc ring */
	uint32_t rxdesc_ring_end;	/* Id of last RxDesc ring */
};

extern struct ppe_dev *ppe_dev;

/*
 * hal_read_reg()
 */
static inline uint32_t hal_read_reg(void __iomem *regbase, uint32_t regoffset)
{
	return (uint32_t)readl(regbase + regoffset);
}

/*
 * hal_write_reg()
 */
static inline void hal_write_reg(void __iomem *regbase, uint32_t regoffset,
                                                                uint32_t val)
{
	writel(val, regbase + regoffset);
}

/*
 * ppe_uio_reg_read()
 *	Read ppe_uio register
 */
static inline uint32_t ppe_uio_reg_read(uint32_t reg_off)
{
	return hal_read_reg(ppe_dev->reg_base, reg_off);
}

/*
 * ppe_uio_reg_write()
 *	Write ppe_uio register
 */
static inline void ppe_uio_reg_write(uint32_t reg_off, uint32_t val)
{
	hal_write_reg(ppe_dev->reg_base, reg_off, val);
}

#endif  /* __NSS_PPE_UIO_H__ */
