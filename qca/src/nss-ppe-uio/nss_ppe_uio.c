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

#include <linux/netdevice.h>
#include <linux/platform_device.h>
#include <linux/switch.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_mdio.h>
#include <linux/phy.h>
#include <linux/reset.h>
#include <fal/fal_qm.h>
#include <fal/fal_rss_hash.h>
#include <fal/fal_servcode.h>

#include "nss_ppe_uio.h"
#include <ppe_drv_sc.h>
#include <ppe_drv.h>

struct ppe_dev *ppe_dev;
static const char ppe_uio_version[] = "PPE UIO driver v1.0";
static const char uio_device_name[] = "ppe-uio";

dma_addr_t rxfill_ring_base_dma;
int rxfill_ring_dma_size;
void *rxfill_desc;

/* ipq40xx_mdio_data */
struct ipq40xx_mdio_data {
        struct mii_bus *mii_bus;
        void __iomem *membase;
        int phy_irq[PHY_MAX_ADDR];
};

static int ppe_uio_open(struct uio_info *info, struct inode *inode)
{
	return 0;
}

static int ppe_uio_release(struct uio_info *info, struct inode *inode)
{
	return 0;
}

static int ppe_uio_mmap(struct uio_info *info, struct vm_area_struct *vma)
{
	u32 ret;
	u32 pfn;

	pfn = (info->mem[vma->vm_pgoff].addr) >> PAGE_SHIFT;

	if (vma->vm_pgoff)
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	else
		vma->vm_page_prot = pgprot_device(vma->vm_page_prot);

	ret = remap_pfn_range(vma, vma->vm_start, pfn,
			vma->vm_end - vma->vm_start, vma->vm_page_prot);
	if (ret) {
		/* Error Handle */
		pr_info("remap_pfn_range failed");
	}

	return ret;
}

typedef struct{
	unsigned char port_id;
	unsigned char port_link;
	unsigned char speed;
	unsigned char duplex;
 }ssdk_port_status;

int ssdk_port_link_notify_register(struct notifier_block *nb);
int ssdk_port_link_notify_unregister(struct notifier_block *nb);

static int ppe_uio_link_event(struct notifier_block *unused, unsigned long event,
		void *ptr)
{
	ssdk_port_status *link_status_p = ptr;
	unsigned char port_id = link_status_p->port_id-1;
	struct ppe_uio_info *ppe_uio_info = &ppe_dev->info[port_id];
	struct uio_info *uio_info = &ppe_uio_info->uio_info;

	pr_info("%s port%d link %s to notify %s\n", __func__, port_id,
						link_status_p->port_link ? "UP" : "DOWN", 
						uio_info->name);
	uio_event_notify(uio_info);

	return NOTIFY_DONE;
}

static struct notifier_block ppe_uio_link_notifier = { .notifier_call = ppe_uio_link_event };

static int ppe_uio_misc_irq_control(struct uio_info *info, s32 irq_on)
{
	uint32_t data =
		PPE_UIO_MISC_AXI_RD_ERR_MASK |
		PPE_UIO_MISC_AXI_WR_ERR_MASK |
		PPE_UIO_MISC_RX_DESC_FIFO_FULL_MASK |
		PPE_UIO_MISC_RX_ERR_BUF_SIZE_MASK |
		PPE_UIO_MISC_TX_SRAM_FULL_MASK |
		PPE_UIO_MISC_TX_CMPL_BUF_FULL_MASK |
		PPE_UIO_MISC_DATA_LEN_ERR_MASK |
		PPE_UIO_MISC_TX_TIMEOUT_MASK;

	if (irq_on == 0) {
		pr_info("%s, disable MISC IRQ", __func__);
		ppe_uio_reg_write(PPE_UIO_REG_MISC_INT_MASK, ~data);

	} else if (irq_on == 1) {
		pr_info("%s, enable MISC IRQ", __func__);
		ppe_uio_reg_write(PPE_UIO_REG_MISC_INT_MASK, data);
	}

	return 0;
}

static irqreturn_t ppe_uio_misc_irq_handler(int irq, struct uio_info *info)
{

	pr_info("%s, irq: %d.", __func__, irq);

	return IRQ_HANDLED;
}

static int __init uio_init(struct ppe_dev *pd,  struct ppe_private *dp_priv)
{
	int ret;
	struct ppe_uio_info *ppe_uio_info;
	char name[19];

	ppe_uio_info = &pd->info[dp_priv->macid-1];
	atomic_set(&ppe_uio_info->ref, 0);
	ppe_uio_info->uio_info.version = ppe_uio_version;
	ppe_uio_info->uio_info.name = ppe_uio_info->name;
	ppe_uio_info->uio_info.irq = UIO_IRQ_CUSTOM;

	if(dp_priv->macid == 1) {
		//assume 1st line is misc IRQ
		ppe_uio_info->uio_info.irq = platform_get_irq(ppe_dev->pdev, 0);
		ppe_uio_info->uio_info.irq_flags = IRQF_SHARED;
		ppe_uio_info->uio_info.irqcontrol = ppe_uio_misc_irq_control;
		ppe_uio_info->uio_info.handler = ppe_uio_misc_irq_handler;
	}

	ppe_uio_info("PPE UIO request irq=%ld\n", ppe_uio_info->uio_info.irq);


	ppe_uio_info->uio_info.mem[0].name = "PPE_REG_SPACE";
	ppe_uio_info->uio_info.mem[0].addr = pd->reg_resource->start;
	ppe_uio_info->uio_info.mem[0].size = resource_size(pd->reg_resource);
	ppe_uio_info->uio_info.mem[0].internal_addr = 0;
	ppe_uio_info->uio_info.mem[0].memtype = UIO_MEM_PHYS;

        ppe_uio_info->uio_info.mem[1].name = "PPE_RING_SPACE";
        ppe_uio_info->uio_info.mem[1].addr = dp_priv->ring_base_dma;
        ppe_uio_info->uio_info.mem[1].size = dp_priv->ring_dma_size;
        ppe_uio_info->uio_info.mem[1].memtype = UIO_MEM_PHYS;

	ppe_uio_info->uio_info.mem[2].name = "PPE_RXFILL_RING_SPACE";
        ppe_uio_info->uio_info.mem[2].addr = rxfill_ring_base_dma;
        ppe_uio_info->uio_info.mem[2].size = rxfill_ring_dma_size;
        ppe_uio_info->uio_info.mem[2].memtype = UIO_MEM_PHYS;

	ppe_uio_info->uio_info.open = ppe_uio_open;
	ppe_uio_info->uio_info.release = ppe_uio_release;
	/* Custom mmap function. */
	ppe_uio_info->uio_info.mmap = ppe_uio_mmap;
	ppe_uio_info->uio_info.priv = pd;

	ret = uio_register_device(ppe_dev->dev, &ppe_uio_info->uio_info);
	if (ret) {
		dev_err(ppe_dev->dev, "ppe_uio: UIO registration failed\n");
		return ret;
	}

	ppe_uio_info("PPE UIO uio_init done");
	return 0;
}

/*
 * ppe_uio_dma_alloc_rxfill()
 *      Allocate resources for RX FILL rings
 */
static int ppe_uio_dma_alloc_rxfill(struct ppe_dev *pd)
{
	uint32_t i;
        int ret;

        struct platform_device *pdev = pd->pdev;

	for (i = 0; i < MAX_RX_FILL_RINGS; i++) {
                rxfill_ring_dma_size += sizeof(struct ppe_uio_rxfill_desc) * PPE_UIO_RX_RING_SIZE;

        }

	/* Allocate memory for buffer descriptors. */
        rxfill_desc = dma_alloc_coherent(&pdev->dev, rxfill_ring_dma_size, &rxfill_ring_base_dma,
                        GFP_KERNEL | __GFP_ZERO);
        if (!rxfill_desc) {
                ppe_uio_err("PPE UIO dma alloc failed for rxfill rings \n");
                return -ENOMEM;
        }

        ppe_uio_info("PPE UIO rxfill rings alloc completed succesfully\n");
        return 0;	
}

/*
 * ppe_uio_dma_alloc()
 *	Allocate resources for TX/RX rings
 */
static int ppe_uio_dma_alloc(struct ppe_dev *pd, struct ppe_private *dp_priv)
{
	uint32_t i;
	int ret;

	struct platform_device *pdev = pd->pdev;

	for (i = 0; i < MAX_TX_DESC_RINGS_PER_PORT; i++) {
		dp_priv->ring_dma_size += sizeof(struct ppe_uio_pri_txdesc) * PPE_UIO_TX_RING_SIZE;
	}

	for (i = 0; i < MAX_TX_DESC_RINGS_PER_PORT; i++) {
		dp_priv->ring_dma_size += sizeof(struct ppe_uio_sec_txdesc) * PPE_UIO_TX_RING_SIZE;
	}

	for (i = 0; i < MAX_TX_CMPL_RINGS_PER_PORT; i++) {
		dp_priv->ring_dma_size += sizeof(struct ppe_uio_txcmpl_desc) * PPE_UIO_TX_RING_SIZE;
	}

	for (i = 0; i < MAX_RX_DESC_RINGS_PER_PORT; i++) {
		dp_priv->ring_dma_size += sizeof(struct ppe_uio_rxdesc_desc) * PPE_UIO_RX_RING_SIZE;
	}

	for (i = 0; i < MAX_RX_DESC_RINGS_PER_PORT; i++) {
		dp_priv->ring_dma_size += sizeof(struct ppe_uio_rxdesc_sec_desc) * PPE_UIO_RX_RING_SIZE;
	}

	/* Allocate memory for buffer descriptors. */
	dp_priv->desc = dma_alloc_coherent(&pdev->dev, dp_priv->ring_dma_size, &dp_priv->ring_base_dma,
			GFP_KERNEL | __GFP_ZERO);
	if (!dp_priv->desc) {
		ppe_uio_err("PPE UIO dma alloc failed \n");
		return -ENOMEM;
	}

	ppe_uio_info("PPE UIO rings alloc completed succesfully\n");
	return 0;
}

/*
 * ppe_uio_rxfill_rings_cleanup()
 *      Cleanup resources for RX FILL rings
 */
static int ppe_uio_rxfill_rings_cleanup(struct ppe_dev *pd)
{
        dma_free_coherent(&pd->pdev->dev, rxfill_ring_dma_size, rxfill_desc, rxfill_ring_base_dma);
        rxfill_desc = NULL;
        rxfill_ring_base_dma = (dma_addr_t)0;

        return 0;
}

/*
 * ppe_uio_rings_cleanup()
 *      Cleanup resources for TX/RX rings
 */
static int ppe_uio_rings_cleanup(struct ppe_dev *pd, struct ppe_private *dp_priv)
{
	dma_free_coherent(&pd->pdev->dev, dp_priv->ring_dma_size, dp_priv->desc, dp_priv->ring_base_dma);
        dp_priv->desc = NULL;
        dp_priv->ring_base_dma = (dma_addr_t)0;

        return 0;
}

/*
 * ppe_uio_clock_set_and_enable()
 *      API to set and enable the PPE_UIO common clocks
 */
static int32_t ppe_uio_clock_set_and_enable(struct device *dev, const char *id, unsigned long rate)
{
        struct clk *clk = NULL;
        int err;

        clk = devm_clk_get(dev, id);
        if (IS_ERR(clk)) {
                return -1;
        }

        if (rate) {
                err = clk_set_rate(clk, rate);
                if (err) {
                        return -1;
		}
	}

        err = clk_prepare_enable(clk);
        if (err) {
                return -1;
        }

        return 0;
}

/*
 * ppe_uio_configure_clocks()
 *      configure the PPE UIO clock's.
 */
int32_t ppe_uio_configure_clocks(struct platform_device *pdev)
{
        int32_t err;

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_CSR_CLK, PPE_UIO_CSR_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_CSR_CLK, PPE_UIO_NSSNOC_CSR_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_TS_CLK, PPE_UIO_TS_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSCC_CLK, PPE_UIO_NSSCC_CLK_FREQ);
        if (err) {
            return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSCFG_CLK, PPE_UIO_NSSCFG_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSCNOC_ATB_CLK,
                                        PPE_UIO_NSSCNOC_ATB_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_NSSCC_CLK,
                                        PPE_UIO_NSSNOC_NSSCC_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_PCNOC_1_CLK,
                                        PPE_UIO_NSSNOC_PCNOC_1_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_QOSGEN_REF_CLK,
                                        PPE_UIO_NSSNOC_QOSGEN_REF_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_SNOC_1_CLK,
                                        PPE_UIO_NSSNOC_SNOC_1_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_SNOC_CLK,
                                        PPE_UIO_NSSNOC_SNOC_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_TIMEOUT_REF_CLK,
                                        PPE_UIO_NSSNOC_TIMEOUT_REF_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_XO_DCD_CLK,
                                        PPE_UIO_NSSNOC_XO_DCD_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_IMEM_QSB_CLK,
                                       PPE_UIO_IMEM_QSB_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_IMEM_QSB_CLK,
                                        PPE_UIO_NSSNOC_IMEM_QSB_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_IMEM_AHB_CLK,
                                        PPE_UIO_IMEM_AHB_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_IMEM_AHB_CLK,
                                       PPE_UIO_NSSNOC_IMEM_AHB_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_MEM_NOC_NSSNOC_CLK,
                                       PPE_UIO_MEM_NOC_NSSNOC_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_TBU_CLK,
                                        PPE_UIO_TBU_CLK_FREQ);
        if (err) {
                return -1;
        }

	err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_MEM_NOC_1_CLK,
                                        PPE_UIO_NSSNOC_MEM_NOC_1_CLK_FREQ);
        if (err) {
                return -1;
        }

        err = ppe_uio_clock_set_and_enable(&pdev->dev, PPE_UIO_NSSNOC_MEMNOC_CLK,
                                        PPE_UIO_NSSNOC_MEMNOC_CLK_FREQ);
        if (err) {
                return -1;
        }

        return 0;
}

/*
 ** ppe_uio_cfg_sc_bypass
 **      Set service code to disable PPE processing
 **/
int ppe_uio_cfg_sc_bypass(struct ppe_dev *pd)
{
	int ret;
	fal_servcode_config_t entry = {0};

	entry.bypass_bitmap[0] = ~((1 << FAKE_MAC_HEADER_BYP)
				| (1 << SERVICE_CODE_BYP)
				| (1 << FAKE_L2_PROTO_BYP));
	entry.bypass_bitmap[1] = ~(1 << ACL_POST_ROUTING_CHECK_BYP);

	ret = fal_servcode_config_set(0, PPE_UIO_SC_BYPASS, &entry);
	if (ret < 0) {
		ppe_uio_err("%px: Error in configuring service code %d\n", pd, ret);
	}

	return ret;
}

/*
 * ppe_uio_hw_reset()
 *      Reset PPE UIO hardware.
 */
int32_t ppe_uio_hw_reset(void *ctx)
{
        struct reset_control *ppe_uio_hw_rst;
        struct platform_device *pdev = (struct platform_device *)ctx;

        ppe_uio_hw_rst = devm_reset_control_get(&pdev->dev, PPE_UIO_HW_RESET_ID);
        if (IS_ERR(ppe_uio_hw_rst)) {
                return -EINVAL;
        }

        reset_control_assert(ppe_uio_hw_rst);
        udelay(100);

        reset_control_deassert(ppe_uio_hw_rst);
        udelay(100);

        return 0;
}

int ppe_uio_hw_init(struct ppe_dev *pd)
{
	int ret = 0;
	uint32_t data;

	data = ppe_uio_reg_read(PPE_UIO_REG_MAS_CTRL);
	ppe_uio_info("PPE_UIO ver %d hw init\n", data);

	/*
	 ** Setup private data structure
	 **/

	pd->rxfill_intr_mask = PPE_UIO_RXFILL_INT_MASK;
	pd->rxdesc_intr_mask = PPE_UIO_RXDESC_INT_MASK_PKT_INT;
	pd->txcmpl_intr_mask = PPE_UIO_TX_INT_MASK_PKT_INT;
	pd->ppe_uio_initialized = false;

	/*
         * Reset PPE UIO
         */
        ret = ppe_uio_hw_reset(pd->pdev);
        if (ret) {
                ppe_uio_err("Error in resetting the hardware. ret: %d\n", ret);
                return ret;
        }

	ret = (int)ppe_uio_cfg_sc_bypass(pd);
	if (ret) {
		ppe_uio_err("Error in configuring service code: %d\n", ret);
		return ret;
	}

	ret = ppe_uio_dma_alloc_rxfill(pd);
	if (ret) {
		ppe_uio_err("Error in initializaing the rxfill rings. ret: %d\n", ret);
		return ret;
	}

	pd->ppe_uio_initialized = true;

	return 0;
}

/*
 * ppe_uio_mdio_attach()
 */
struct mii_bus *ppe_uio_mdio_attach(struct platform_device *pdev)
{
        struct device_node *mdio_node;
        struct platform_device *mdio_plat;
        struct ipq40xx_mdio_data *mdio_data;

        /*
         * Find mii_bus using "mdio-bus" handle.
         */
        mdio_node = of_parse_phandle(pdev->dev.of_node, "mdio-bus", 0);
        if (mdio_node) {
                return of_mdio_find_bus(mdio_node);
        }

        mdio_node = of_find_compatible_node(NULL, NULL, "qcom,qca-mdio");
        if (!mdio_node) {
                mdio_node = of_find_compatible_node(NULL, NULL,
                                                        "qcom,ipq40xx-mdio");
                if (!mdio_node) {
                        dev_err(&pdev->dev, "cannot find mdio node by phandle\n");
                        return NULL;
        }
        }

        mdio_plat = of_find_device_by_node(mdio_node);
        if (!mdio_plat) {
                dev_err(&pdev->dev, "cannot find platform device from mdio node\n");
                of_node_put(mdio_node);
                return NULL;
        }

        mdio_data = dev_get_drvdata(&mdio_plat->dev);
        if (!mdio_data) {
                dev_err(&pdev->dev, "cannot get mii bus reference from device data\n");
                of_node_put(mdio_node);
                return NULL;
        }

        return mdio_data->mii_bus;
}

int32_t ppe_uio_probe(struct platform_device *pdev)
{
	struct net_device *netdev;
	struct ppe_private *dp_priv;
	struct device_node *np = pdev->dev.of_node;
	int32_t ret = 0;
	uint8_t phy_id[MII_BUS_ID_SIZE + 3];
	struct resource res_ppe_uio;
	int i = 0;

	netdev = alloc_etherdev_mqs(sizeof(struct ppe_private),
			PPE_UIO_NETDEV_TX_QUEUE_NUM, PPE_UIO_NETDEV_RX_QUEUE_NUM);
	if (!netdev) {
		pr_info("alloc_etherdev() failed\n");
		return -ENOMEM;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
	/* max_mtu is set to 1500 in ether_setup() */
	netdev->max_mtu = ETH_MAX_MTU;
#endif
	dp_priv = netdev_priv(netdev);
	memset((void *)dp_priv, 0, sizeof(struct ppe_private));

	dp_priv->pdev = pdev;
	dp_priv->netdev = netdev;
	netdev->watchdog_timeo = 5 * HZ;
        netdev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	if (dp_priv->link_poll) {
		dp_priv->miibus = ppe_uio_mdio_attach(pdev);
		if (!dp_priv->miibus) {
			netdev_dbg(netdev, "failed to find miibus\n");
			goto phy_setup_fail;
		}
		snprintf(phy_id, MII_BUS_ID_SIZE + 3, PHY_ID_FMT,
				dp_priv->miibus->id, dp_priv->phy_mdio_addr);

		SET_NETDEV_DEV(netdev, &pdev->dev);

		ppe_uio_info("PPE UIO phy_connect start.");
	}

	ppe_dev->dev = &pdev->dev;
	dp_priv->pdev = pdev;

	platform_set_drvdata(pdev, netdev);

	if (of_property_read_u32(np, "qcom,id", &dp_priv->macid)) {
		ppe_uio_err("Unable to read mac id\n");
		goto abort;
	}

	if ((dp_priv->macid < 1) || (dp_priv->macid > PPE_UIO_MAX_PORTS)) {
		ppe_uio_err("Invalid macid(%d)\n", dp_priv->macid);
		goto abort;
	}

	snprintf(ppe_dev->info[dp_priv->macid-1].name, sizeof(ppe_dev->info[dp_priv->macid-1].name) - 1,
		 "%s%d", uio_device_name, dp_priv->macid-1);

	ret = ppe_uio_dma_alloc(ppe_dev, dp_priv);
        if (ret) {
                ppe_uio_err("Error in initializaing the rings. ret: %d\n", ret);
                goto abort;
        }

	/* Register UIO */
	ret = uio_init(ppe_dev, dp_priv);
	if (ret) {
		if (ret == -517) {
			dev_info(&pdev->dev, "Driver request probe retry: %s\n", __func__);
			goto phy_setup_fail;
		} else {
			dev_err(&pdev->dev, "UIO init Failed\n");
			goto abort;
		}
	}

	netif_carrier_off(netdev);
	dev_info(ppe_dev->dev, "UIO device full name %s initialized\n",
			ppe_dev->info[dp_priv->macid-1].name);

	return 0;

phy_setup_fail:
        free_netdev(netdev);
        return -EFAULT;
abort:
	return ret;
}

int ppe_uio_remove(struct platform_device *pdev)
{
	uint32_t i;
	struct ppe_private *dp_priv = NULL;

	for (i = 0; i < PPE_UIO_MAX_PORTS; i++) {
		dp_priv = ppe_dev->ppe_prv[i];
		if (!dp_priv)
			continue;

		/*
		 * cleanup rings and free
		 */
		ppe_uio_rings_cleanup(ppe_dev, dp_priv);

		uio_unregister_device(&ppe_dev->info[dp_priv->macid-1].uio_info);
		free_netdev(dp_priv->netdev);
		ppe_dev->ppe_prv[i] = NULL;
	}

	return 0;
}

static struct of_device_id ppe_uio_dt_ids[] = {
	        { .compatible = "qcom,ppe-uio" },
		        {},
};
MODULE_DEVICE_TABLE(of, ppe_uio_dt_ids);

static struct platform_driver ppe_uio_drv = {
	.prevent_deferred_probe = false,
	.probe = ppe_uio_probe,
	.remove = ppe_uio_remove,
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(ppe_uio_dt_ids),
		.suppress_bind_attrs = true,
	},
};

/*
 * uio_of_get_pdata()
 *      Read the device tree details for ppe uio
 */
static int uio_of_get_pdata(struct resource *ppe_uio_res)
{
	int ret;
        uint32_t i, j;

	/*
         ** Find PPE UIO node in device tree
         **/
        ppe_dev->device_node = of_find_node_by_name(NULL,DRIVER_NAME);
        if (!ppe_dev->device_node) {
                ppe_uio_warn("PPE UIO device tree node (%s) not found\n", DRIVER_NAME);
                return -EINVAL;
        }

	 /*
         * Get PPE UIO device node
         */
        ppe_dev->pdev = of_find_device_by_node(ppe_dev->device_node);
        if (!ppe_dev->pdev) {
                ppe_uio_err("Platform device for node %px(%s) not found\n",
                                ppe_dev->device_node,
                                (ppe_dev->device_node)->name);
                return -EINVAL;
        }

        /*
         * Get PPE UIO register resource
         */
        if (of_address_to_resource(ppe_dev->device_node, 0, ppe_uio_res) != 0) {
                ppe_uio_err("Unable to get register address for ppe uio device: "
                          DRIVER_NAME"\n");
                return -EINVAL;
        }

	/*
         * Get id of first TXDESC ring
         */
        if (of_property_read_u32(ppe_dev->device_node, "qcom,txdesc-ring-start",
                                &ppe_dev->txdesc_ring_start) != 0) {
                ppe_uio_err("Read error 1st TXDESC ring (txdesc_ring_start)\n");
                return -EINVAL;
        }

        if (ppe_dev->txdesc_ring_start > PPE_UIO_MAX_TXDESC_RINGS_IDX) {
                ppe_uio_err("Incorrect txdesc-ring-start value (%d) received as input\n",
                                ppe_dev->txdesc_ring_start);
                return -EINVAL;
        }
        ppe_uio_debug("txdesc ring start: %d\n", ppe_dev->txdesc_ring_start);

        /*
         * Get number of TXDESC rings
         */
        if (of_property_read_u32(ppe_dev->device_node, "qcom,txdesc-rings",
                                &ppe_dev->num_txdesc_rings) != 0) {
                ppe_uio_err("Unable to read number of txdesc rings.\n");
		return -EINVAL;
        }

        if (ppe_dev->num_txdesc_rings > MAX_TX_DESC_RINGS_PER_PORT * PPE_UIO_MAX_PORTS) {
                ppe_uio_err("Invalid txdesc-rings value (%d) received as input\n",
                                ppe_dev->num_txdesc_rings);
                return -EINVAL;
        }

        ppe_dev->txdesc_ring_end = ppe_dev->txdesc_ring_start +
                                        ppe_dev->num_txdesc_rings - 1;

	if (ppe_dev->txdesc_ring_end > PPE_UIO_MAX_TXDESC_RINGS_IDX) {
                ppe_uio_err("Invalid Txdesc ring configuration: txdesc-ring-start (%d)"
                                " and txdesc-rings (%d)\n",
                                ppe_dev->txdesc_ring_start,
                                ppe_dev->num_txdesc_rings);
                return -EINVAL;
        }
        ppe_uio_debug("txdesc rings count: %d, txdesc ring end: %d\n",
                        ppe_dev->num_txdesc_rings, ppe_dev->txdesc_ring_end);

        /*
         * Get id of first TXCMPL ring
         */
	 if (of_property_read_u32(ppe_dev->device_node, "qcom,txcmpl-ring-start",
                                &ppe_dev->txcmpl_ring_start) != 0) {
                ppe_uio_err("Read error 1st TXCMPL ring (txcmpl_ring_start)\n");
                return -EINVAL;
        }

        if (ppe_dev->txcmpl_ring_start > PPE_UIO_MAX_TXCMPL_RINGS_IDX) {
                ppe_uio_err("Incorrect txcmpl-ring-start value (%d) received as input\n",
                                ppe_dev->txcmpl_ring_start);
                return -EINVAL;
        }
        ppe_uio_debug("txcmpl ring start: %d\n", ppe_dev->txcmpl_ring_start);

        /*
         * Get number of TXCMPL rings
         */
        if (of_property_read_u32(ppe_dev->device_node, "qcom,txcmpl-rings",
                                &ppe_dev->num_txcmpl_rings) != 0) {
                ppe_uio_err("Unable to read number of txcmpl rings.\n");
                return -EINVAL;
        }

        if (ppe_dev->num_txcmpl_rings > MAX_TX_CMPL_RINGS_PER_PORT * PPE_UIO_MAX_PORTS) {
                ppe_uio_err("Invalid txcmpl-rings value (%d) received as input\n",
                                ppe_dev->num_txcmpl_rings);
		return -EINVAL;
        }

        ppe_dev->txcmpl_ring_end = ppe_dev->txcmpl_ring_start + ppe_dev->num_txcmpl_rings - 1;
        if (ppe_dev->txcmpl_ring_end > PPE_UIO_MAX_TXCMPL_RINGS_IDX) {
                ppe_uio_err("Invalid Txcmpl ring configuration: txcmpl-ring-start (%d)"
                                " and txcmpl-rings (%d)\n",
                                ppe_dev->txcmpl_ring_start,
                                ppe_dev->num_txcmpl_rings);
                return -EINVAL;
        }
        ppe_uio_debug("txcmpl rings count: %d, txcmpl ring end: %d\n",
                        ppe_dev->num_txcmpl_rings, ppe_dev->txcmpl_ring_end);

        /*
         * Get id of first RXFILL ring
         */
        if (of_property_read_u32(ppe_dev->device_node, "qcom,rxfill-ring-start",
                                &ppe_dev->rxfill_ring_start) != 0) {
                ppe_uio_err("Read error 1st RXFILL ring (rxfill-ring-start)\n");
                return -EINVAL;
        }

        if (ppe_dev->rxfill_ring_start > PPE_UIO_MAX_RXFILL_RINGS_IDX) {
	 ppe_uio_err("Incorrect rxfill-ring-start value (%d) received as input\n",
                                ppe_dev->rxfill_ring_start);
                return -EINVAL;
        }
        ppe_uio_debug("rxfill ring start: %d\n", ppe_dev->rxfill_ring_start);

        /*
         * Get number of RXFILL rings
         */
        if (of_property_read_u32(ppe_dev->device_node, "qcom,rxfill-rings",
                                        &ppe_dev->num_rxfill_rings) != 0) {
                ppe_uio_err("Unable to read number of rxfill rings.\n");
                return -EINVAL;
        }

        if (ppe_dev->num_rxfill_rings > MAX_RX_FILL_RINGS) {
                ppe_uio_err("Invalid rxfill-rings value (%d) received as input\n",
                                ppe_dev->num_rxfill_rings);
                return -EINVAL;
        }

        ppe_dev->rxfill_ring_end = ppe_dev->rxfill_ring_start +
                                        ppe_dev->num_rxfill_rings - 1;
        if (ppe_dev->rxfill_ring_end > PPE_UIO_MAX_RXFILL_RINGS_IDX) {
                ppe_uio_err("Invalid Rxfill ring configuration: rxfill-ring-start (%d)"
	   " and rxfill-rings (%d)\n",
                                ppe_dev->rxfill_ring_start,
                                ppe_dev->num_rxfill_rings);
                return -EINVAL;
        }
        ppe_uio_debug("rxfill rings count: %d, rxfill ring end: %d\n",
                        ppe_dev->num_rxfill_rings, ppe_dev->rxfill_ring_end);

        /*
         * Get id of first RXDESC ring
         */
        if (of_property_read_u32(ppe_dev->device_node, "qcom,rxdesc-ring-start",
                                &ppe_dev->rxdesc_ring_start) != 0) {
                ppe_uio_err("Read error 1st RXDESC ring (rxdesc-ring-start)\n");
                return -EINVAL;
        }

        if (ppe_dev->rxdesc_ring_start > PPE_UIO_MAX_RXDESC_RINGS_IDX) {
                ppe_uio_err("Incorrect rxdesc-ring-start value (%d) received as input\n",
                                ppe_dev->rxdesc_ring_start);
                return -EINVAL;
        }
        ppe_uio_debug("rxdesc ring start: %d\n", ppe_dev->rxdesc_ring_start);

        /*
         * Get number of RXDESC rings
         */
        if (of_property_read_u32(ppe_dev->device_node, "qcom,rxdesc-rings",
                                        &ppe_dev->num_rxdesc_rings) != 0) {
                ppe_uio_err("Unable to read number of rxdesc rings.\n");
                return -EINVAL;
        }

        if (ppe_dev->num_rxdesc_rings > MAX_RX_DESC_RINGS_PER_PORT * PPE_UIO_MAX_PORTS) {
                ppe_uio_err("Invalid rxdesc-rings value (%d) received as input\n",
                                ppe_dev->num_rxdesc_rings);
                return -EINVAL;
        }

        ppe_dev->rxdesc_ring_end = ppe_dev->rxdesc_ring_start +
                                        ppe_dev->num_rxdesc_rings - 1;
	if (ppe_dev->rxdesc_ring_end > PPE_UIO_MAX_RXDESC_RINGS_IDX) {
                ppe_uio_err("Invalid Rxdesc ring configuration: rxdesc-ring-start (%d)"
                                " and rxdesc-rings (%d)\n",
                                ppe_dev->rxdesc_ring_start,
                                ppe_dev->num_rxdesc_rings);
                return -EINVAL;
        }
        ppe_uio_debug("rxdesc rings count: %d, rxdesc ring end: %d\n",
                        ppe_dev->num_rxdesc_rings, ppe_dev->rxdesc_ring_end);

	return 0;
}

/*
 * ppe_uio_disable_port()
 *      PPE UIO disable port
 */
static void ppe_uio_disable_port(void)
{
        ppe_uio_reg_write(PPE_UIO_REG_PORT_CTRL, PPE_UIO_DISABLE);
}

/*
 * ppe_uio_init()
 *      PPE UIO init
 */
static int ppe_uio_init(void)
{
        int ret = 0, i;
        struct resource res_ppe_uio;
        uint8_t queue_start = 0;

        /*
         * Check the PPE UIO state
         */
        if (likely(ppe_dev->ppe_uio_initialized)) {
                ppe_uio_debug("PPE UIO is already initialized");
                return 0;
        }

	/*
         * Get all the DTS data needed
         */
        if (uio_of_get_pdata(&res_ppe_uio) < 0) {
                ppe_uio_err("Unable to get PPE UIO DTS data.\n");
                return -EINVAL;
        }

	/*
         ** Request memory region for PPE_UIO registers
         **/
        ppe_dev->reg_resource = request_mem_region(res_ppe_uio.start,
                        resource_size(&res_ppe_uio),
                        DRIVER_NAME);
        if (!ppe_dev->reg_resource) {
                ppe_uio_err("Unable to request PPE_UIO register memory.\n");
                return -EFAULT;
        }

        /*
         ** Remap register resource
         **/
        ppe_dev->reg_base = ioremap_nocache((ppe_dev->reg_resource->start),
                        resource_size(ppe_dev->reg_resource));
        if (!ppe_dev->reg_base) {
                ppe_uio_err("Unable to remap PPE_UIO register memory.\n");
                ret = -EFAULT;
		goto ppe_uio_init_remap_fail;
        }

	ret = ppe_uio_configure_clocks(ppe_dev->pdev);
        if (ret) {
                ppe_uio_err("Error in configuring the common PPE UIO clocks\n");
                ret = -EFAULT;
                goto ppe_uio_hw_init_fail;
        }

	ppe_uio_info("PPE UIO common clocks are configured\n");

	if (ppe_uio_hw_init(ppe_dev) != 0) {
                ppe_uio_err("Error in ppe uio initialization\n");
                ret = -EFAULT;
                goto ppe_uio_hw_init_fail;
        }

        return 0;

ppe_uio_hw_init_fail:
	iounmap(ppe_dev->reg_base);

ppe_uio_init_remap_fail:
        release_mem_region((ppe_dev->reg_resource)->start,
                        resource_size(ppe_dev->reg_resource));
        return ret;
}

/*
 * ppe_uio_cleanup()
 *      PPE_UIO cleanup
 */
static void ppe_uio_cleanup(void)
{
	if (!ppe_dev->ppe_uio_initialized) {
		ppe_uio_disable_port();
		return;
        }

        iounmap(ppe_dev->reg_base);
        release_mem_region((ppe_dev->reg_resource)->start,
                        resource_size(ppe_dev->reg_resource));

	/*
         * Mark initialize false, so that we do not
         * try to cleanup again
         */
        ppe_dev->ppe_uio_initialized = false;
}

/*
 * ppe_uio_hal_init()
 *      Initialize PPE_UIO and set gmac ops.
 */
static bool ppe_uio_hal_init(void)
{
        /*
         * Bail out on not supported platform
         */
        if (!of_machine_is_compatible("qcom,ipq9574")) {
                return false;
        }

        if (ppe_uio_init()) {
                return false;
        }

	ppe_uio_info("PPE UIO HAL init completed succesfully.");

        return true;
}

static void ppe_uio_hal_cleanup(void)
{
        ppe_uio_cleanup();
}

/*
 * nss_ppe_uio_init()
 */
int __init nss_ppe_uio_init(void)
{
	int ret;

	/* allocate memory for uio structure */
        ppe_dev = kzalloc(sizeof(*ppe_dev), GFP_KERNEL);
        if (!ppe_dev)
                return -ENOMEM;

	ppe_dev->common_init_done = false;

	/*
	 * Check platform compatibility
	 */
	if (!ppe_uio_hal_init()) {
		pr_err("NSS PPE UIO hal init failed.\n");
		return -EFAULT;
	}

	ret = platform_driver_register(&ppe_uio_drv);
	if (ret)
		pr_info("NSS PPE UIO platform drv register failed\n");

	pr_info("%s:ssdk_port_link_notify_register\n", __func__);
	ret = ssdk_port_link_notify_register(&ppe_uio_link_notifier);
	if (ret < 0) {
		pr_err("Failed to register ssdk_port_link notifier\n" );
	}

	ppe_dev->common_init_done = true;
	pr_info("**********************************************************\n");
	pr_info("* NSS PPE UIO Data Plane driver\n");
	pr_info("**********************************************************\n");

	return ret;
}

/*
 * nss_ppe_uio_exit()
 */
void __exit nss_ppe_uio_exit(void)
{
	if (ppe_dev->common_init_done) {
                ppe_uio_hal_cleanup();
		ssdk_port_link_notify_unregister(&ppe_uio_link_notifier);
		ppe_dev->common_init_done = false;
	}

	if (ppe_dev)
		kfree(ppe_dev);

	/*
	 * cleanup rings and free
	 */
	ppe_uio_rxfill_rings_cleanup(ppe_dev);

	platform_driver_unregister(&ppe_uio_drv);
}

module_init(nss_ppe_uio_init);
module_exit(nss_ppe_uio_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("NSS PPE UIO Driver");
MODULE_AUTHOR("Qualcomm Technologies, Inc.");
