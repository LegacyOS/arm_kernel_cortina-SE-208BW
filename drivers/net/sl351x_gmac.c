/************************************************************************** 
* Copyright 2006 StorLink Semiconductors, Inc.  All rights reserved.
*--------------------------------------------------------------------------
* Name			: sl351x_gmac.c
* Description	: 
*		Ethernet device driver for Storlink SL351x FPGA
*
* History
*
*	Date		Writer		Description
*	-----------	-----------	-------------------------------------------------
*	08/22/2005	Gary Chen	Create and implement
*   27/10/2005  CH Hsu      Porting to Linux   

* Cortina 에서 제공해준 기본 소스가 워낙 보기 힘들고 문제점이 많아서 정리 함.
* 코드 정리 및 IC+ PHY 칩 Detect 처리 변경(__ORIGINAL__ DEF)
* 120724 by. sis
*
****************************************************************************/
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/compiler.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/completion.h>
#include <asm/hardware.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/semaphore.h>
#include <asm/arch/irqs.h>
#include <asm/arch/it8712.h>
#include <linux/mtd/kvctl.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/mtd/kvctl.h>
#include <linux/sysctl_storlink.h>
#include "../../net/bridge/br_private.h"
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/if_pppox.h>

#define	 MIDWAY 
#define	 SL_LEPUS

#undef CONFIG_SL351x_RXTOE

#include <linux/sysctl_storlink.h>
#include <asm/arch/sl2312.h>
#include <asm/arch/sl351x_gmac.h>
#include <asm/arch/sl351x_hash_cfg.h>
#include <asm/arch/sl351x_nat_cfg.h>

// #define SL351x_TEST_WORKAROUND
 
#ifndef CONFIG_SL351X_BR
#define DO_HW_CHKSUM					1
#endif
#define CONFIG_SL_NAPI					1
//#undef CONFIG_SL_NAPI

#define GMAX_TX_INTR_DISABLED			1
#define ENABLE_TSO						1
//#define GMAC_USE_TXQ0					1
//#define NAT_WORKAROUND_BY_RESET_GMAC	1
//#define HW_RXBUF_BY_KMALLOC			1
//#define _DUMP_TX_TCP_CONTENT	1
#define	br_if_ioctl						1
#define GMAC_LEN_1_2_ISSUE				1
#undef  GMAC_DEBUG	
//#define GMAC_DEBUG					1	//defined at sl351x_gmac.h
#define	INTERRUPT_SELECT				1
#define PHY_WORKAROUND					1
//#define BRIDGE_CHARIOT_TEST			1
#define DEBUG_MEMORY_LEAKAGE			1
//#define STORLINK_PHY					1
//#define GMAC_DEBUG_U					1	//defined at sl351x_gmac.h

#define GMAC_EXISTED_FLAG			0x5566abcd

#define CONFIG_MAC_NUM				GMAC_NUM			/* 111228-dhsul-lt */

#define GMAC0_BASE					TOE_GMAC0_BASE
#define GMAC1_BASE					TOE_GMAC1_BASE
#define PAUSE_SET_HW_FREEQ			(TOE_HW_FREEQ_DESC_NUM / 2)
#define PAUSE_REL_HW_FREEQ			((TOE_HW_FREEQ_DESC_NUM / 2) + 10)
#define DEFAULT_RXQ_MAX_CNT			1024

/* define chip information */
#define DRV_NAME					"Cortina Systems, Inc. "
#define DRV_VERSION					"0.2.1"
#define SL351x_DRIVER_NAME  		DRV_NAME "SL351x Giga Ethernet driver " DRV_VERSION

#define toe_gmac_enable_interrupt(irq)	enable_irq(irq)
#define toe_gmac_disable_interrupt(irq)	disable_irq(irq)


#ifdef GMAC_LEN_1_2_ISSUE
	#define _DEBUG_PREFETCH_NUM	256
	int	_debug_prefetch_cnt;
	char _debug_prefetch_buf[_DEBUG_PREFETCH_NUM][4] __attribute__((aligned(4)));
#endif

/*************************************************************
 *         Global Variable
 *************************************************************/
static int	gmac_initialized = 0;
TOE_INFO_T toe_private_data;
spinlock_t gmac_fq_lock;
uint32_t FLAG_SWITCH;

static uint32_t next_tick = 3 * HZ;		
static unsigned char eth_mac[][6]= {{0x00,0x11,0x11,0x87,0x87,0x87}, {0x00,0x22,0x22,0xab,0xab,0xab}};
#ifdef CONFIG_BONDING_MODULE
static unsigned char eth_mac_init[][6]= {{0x00,0x11,0x11,0x87,0x87,0x87}, {0x00,0x22,0x22,0xab,0xab,0xab}}; //same as eth_mac[][]
static unsigned char eth_mac_zero[6]={0x00,0x00,0x00,0x00,0x00,0x00};
#endif//CONFIG_BONDING_MODULE
#undef CONFIG_SL351x_RXTOE
extern NAT_CFG_T nat_cfg;

/************************************************/
/*                 function declare             */
/************************************************/
static int gmac_set_mac_address(struct net_device *dev, void *addr);
static uint32_t gmac_get_phy_vendor(int phy_addr);
static void gmac_set_phy_status(struct net_device *dev);
void gmac_get_phy_status(struct net_device *dev);
static int gmac_netdev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
static void gmac_tx_timeout(struct net_device *dev);
static int gmac_change_mtu(struct net_device *dev, int new_mtu);
static int gmac_phy_thread (void *data);
struct net_device_stats * gmac_get_stats(struct net_device *dev);
static int gmac_start_xmit(struct sk_buff *skb, struct net_device *dev);
static void gmac_set_rx_mode(struct net_device *dev);
static irqreturn_t toe_gmac_interrupt (int irq, void *dev_instance, struct pt_regs *regs);
static inline void toe_gmac_handle_default_rxq(struct net_device *dev, GMAC_INFO_T *tp);

uint32_t mii_read(unsigned char phyad,unsigned char regad);
void mii_write(unsigned char phyad,unsigned char regad,uint32_t value);
void mac_init_drv(void);

static void toe_init_free_queue(void);
static void toe_init_swtx_queue(void);
static void toe_init_default_queue(void);
static void toe_init_interrupt_config(void);
static void toe_gmac_sw_reset(void);
static int toe_gmac_init_chip(struct net_device *dev);
static void toe_gmac_enable_tx_rx(struct net_device* dev);
static void toe_gmac_disable_tx_rx(struct net_device *dev);
static void toe_gmac_hw_start(struct net_device *dev);
static void toe_gmac_hw_stop(struct net_device *dev);
static int toe_gmac_clear_counter(struct net_device *dev);
static void toe_init_gmac(struct net_device *dev);
static inline void toe_gmac_tx_complete(GMAC_INFO_T *tp, uint32_t tx_qid, struct net_device *dev, int interrupt);
#ifdef CONFIG_SL_NAPI
static inline int gmac_rx_poll(struct net_device *dev, int *budget);
// static void toe_gmac_disable_rx(struct net_device *dev);
// static void toe_gmac_enable_rx(struct net_device *dev);
#endif

u32 mac_read_dma_reg(int mac, uint32_t offset);
void mac_write_dma_reg(int mac, uint32_t offset, u32 data);
void mac_stop_txdma(struct net_device *dev);
void mac_get_sw_tx_weight(struct net_device *dev, char *weight);
void mac_set_sw_tx_weight(struct net_device *dev, char *weight);
void mac_get_hw_tx_weight(struct net_device *dev, char *weight);
void mac_set_hw_tx_weight(struct net_device *dev, char *weight);
static void toe_gmac_fill_free_q(void);
static void gmac_reset_task(struct net_device *dev);
void dm_byte(u32 location, int length);
void gmac_get_switch_status(struct net_device *dev);
void dm_long_1(u32 location, int length);

int Giga_switch = 0;

uint32_t switch_port_no = 0;
uint32_t ever_dwon = 0;
uint32_t c_GPIO = 0;

#ifdef TANTOS_0G_SWITCH	
int Tantos_switch = 1;
#else
int Tantos_switch = 0; 
#endif


/************************************************/
/*            GMAC function declare             */
/************************************************/
static int gmac_open (struct net_device *dev);
static int gmac_close (struct net_device *dev);
static void gmac_cleanup_module(void);
static void gmac_get_mac_address(void);

#ifdef CONFIG_SL351x_NAT
static void toe_init_hwtx_queue(void);
extern void sl351x_nat_init(void);
extern int sl351x_nat_add_dev(struct net_device *dev);
extern int sl351x_nat_del_dev(struct net_device *dev);
extern void sl351x_nat_input(struct sk_buff *skb, int port, void *l3off, void *l4off);
extern int sl351x_nat_output(struct sk_buff *skb, int port);
extern int sl351x_nat_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
#else
extern int sl351x_gmac_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
#endif

#ifdef CONFIG_SL351X_BR
static void toe_init_hwtx_queue(void);
extern void sl351x_br_init(void);
extern void sl351x_br_input(struct sk_buff *skb, int port);
#endif


int mac_set_rule_reg(int mac, int rule, int enabled, u32 reg0, u32 reg1, u32 reg2);
void mac_set_rule_enable_bit(int mac, int rule, int data);
int mac_set_rule_action(int mac, int rule, int data);
int mac_get_MRxCRx(int mac, int rule, int ctrlreg);
void mac_set_MRxCRx(int mac, int rule, int ctrlreg, u32 data);

void sl351x_gmac_save_reg(void);
void sl351x_gmac_restore_reg(void);

/*----------------------------------------------------------------------
*	Ethernet Driver init
*----------------------------------------------------------------------*/

static int __init gmac_init_module(void)
{
	GMAC_INFO_T 		*tp;
	struct net_device	*dev;
	int 		i,j;
	uint32_t	chip_id, val_ns;
	uint32_t 	val_1, val_2;

#ifdef CONFIG_SL3516_ASIC
	uint32_t    val;
	/* set GMAC global register */
	val = readl(GMAC_GLOBAL_BASE_ADDR+0x10); 
	val = val | 0x005f0000;
	writel(val,GMAC_GLOBAL_BASE_ADDR+0x10); //Boot loader had writen it.
//	writel(0xb737b737,GMAC_GLOBAL_BASE_ADDR+0x1c); //For Socket Board
	writel(0x77777777,GMAC_GLOBAL_BASE_ADDR+0x20);
//	writel(0xa737b747,GMAC_GLOBAL_BASE_ADDR+0x1c);//For Mounting Board
	//writel(0xa7f0a7f0,GMAC_GLOBAL_BASE_ADDR+0x1c);//For Mounting Board
	writel(0xa7f0b7f0,GMAC_GLOBAL_BASE_ADDR+0x1c);//For Mounting Board

    writel(0x77777777,GMAC_GLOBAL_BASE_ADDR+0x24);
	writel(0x09200030,GMAC_GLOBAL_BASE_ADDR+0x2C);
	val = readl(GMAC_GLOBAL_BASE_ADDR+0x04);
	if ((val&(1<<20))==0) {           // GMAC1 enable
 		val = readl(GMAC_GLOBAL_BASE_ADDR+0x30);
		val = (val & 0xe7ffffff) | 0x08000000;
		writel(val,GMAC_GLOBAL_BASE_ADDR+0x30);
	}
#endif


	val_ns = readl(GMAC_GLOBAL_BASE_ADDR+0x04);
	val_ns = val_ns & (1<<30); 
	chip_id = readl(GMAC_GLOBAL_BASE_ADDR+0x0);
	
	if (Giga_switch == 1) {
		if ((chip_id == 0x3516C3) && (val_ns == 0x40000000))
			c_GPIO = 1;	
		else
			c_GPIO = 0;			
    	
		if (c_GPIO)	{
			val_1 = val_2 = readl(GMAC_GLOBAL_BASE_ADDR+0x30);
			val_1 &= (1 << 4);
			if (val_1 == 0x10) {	/* Bit 4: IDE PADs enable */
				val_2 ^= (1 << 4);	/* IDE PADs disable */
				writel(val_2,GMAC_GLOBAL_BASE_ADDR+0x30);
			}
		}
	}

	if ((chip_id == 0x3512C1) || (chip_id ==0x3512C2)) {
		writel(0x5787a5f0,GMAC_GLOBAL_BASE_ADDR+0x1c);//For 3512 Switch Board 
		writel(0x55557777,GMAC_GLOBAL_BASE_ADDR+0x20);//For 3512 Switch Board
	}
	if (Tantos_switch) {
		writel(0x29f029f0,GMAC_GLOBAL_BASE_ADDR + 0x1c); /* For Millinet EV-Board */
	}

//#endif


	mac_init_drv();

	printk (KERN_INFO SL351x_DRIVER_NAME " built at %s %s\n", __DATE__, __TIME__);

//	init_waitqueue_entry(&wait, current);

	for(i=0,j=0 ; i < CONFIG_MAC_NUM ; j++) {	
		i=j;
		tp = (GMAC_INFO_T *)&toe_private_data.gmac[i];
		if (i != 2)
		tp->dev = NULL;
		
		if (tp->existed != GMAC_EXISTED_FLAG) continue;
		
		/* creating netdevice and assign the variables */
		dev = alloc_etherdev(0);
		
		if (dev == NULL) {
			printk (KERN_ERR "Can't allocate ethernet device #%d .\n",i);
			return -ENOMEM;
		}
		dev->priv=tp;
		tp->dev = dev;
		SET_MODULE_OWNER(dev);

		// spin_lock_init(&tp->lock);
		spin_lock_init(&gmac_fq_lock);

	    dev->open = gmac_open;
	    dev->stop = gmac_close;
		dev->base_addr = tp->base_addr;
		dev->irq = tp->irq;
		dev->hard_start_xmit = gmac_start_xmit;
		dev->get_stats = gmac_get_stats;
		dev->set_multicast_list = gmac_set_rx_mode;
		dev->set_mac_address = gmac_set_mac_address;
		dev->do_ioctl = gmac_netdev_ioctl;
		dev->tx_timeout = gmac_tx_timeout;
		dev->watchdog_timeo = GMAC_DEV_TX_TIMEOUT;

		dev->change_mtu = gmac_change_mtu;

		if (tp->port_id == 0)
			dev->tx_queue_len = TOE_GMAC0_SWTXQ_DESC_NUM;
		else
			dev->tx_queue_len = TOE_GMAC1_SWTXQ_DESC_NUM;

#ifdef DO_HW_CHKSUM
		dev->features |= NETIF_F_SG|NETIF_F_HW_CSUM;
#ifdef ENABLE_TSO
		dev->features |= NETIF_F_TSO;
#endif
#endif
		dev->features |= NETIF_F_HWNAT;
#ifdef CONFIG_SL_NAPI
        dev->poll = gmac_rx_poll;
        dev->weight = GMAC_NAPI_WEIGHT;
#endif

		/* Configure the timeout task */
		INIT_WORK(&tp->tx_timeout_task,
			(void (*)(void *))gmac_reset_task, dev);

		init_waitqueue_head (&tp->thr_wait);
    	init_completion(&tp->thr_exited);

		if (register_netdev(dev)) {
			gmac_cleanup_module();
			return(-1);
		}
	}

	return (0);
}

/*----------------------------------------------------------------------
*	gmac_cleanup_module
*----------------------------------------------------------------------*/

static void gmac_cleanup_module(void)
{
    int i;


    for (i=0;i<CONFIG_MAC_NUM;i++) {
    	if (toe_private_data.gmac[i].dev) {
        	unregister_netdev(toe_private_data.gmac[i].dev);
        	toe_private_data.gmac[i].dev = NULL;
        }
    }
	return ;
}

module_init(gmac_init_module);
module_exit(gmac_cleanup_module);

/*----------------------------------------------------------------------
*	gmac_read_reg
*----------------------------------------------------------------------*/
static inline uint32_t gmac_read_reg(uint32_t base, uint32_t offset)
//static uint32_t gmac_read_reg(uint32_t base, uint32_t offset)
{
    volatile uint32_t reg_val;

    reg_val = readl(base + offset);
	return (reg_val);
}

/*----------------------------------------------------------------------
*	gmac_write_reg
*----------------------------------------------------------------------*/
//static void gmac_write_reg(uint32_t base, uint32_t offset,uint32_t data,uint32_t bit_mask)
static inline void
gmac_write_reg(uint32_t base, uint32_t offset,uint32_t data,uint32_t bit_mask)
{
	volatile uint32_t reg_val;
    uint32_t *addr;

	reg_val = ( gmac_read_reg(base, offset) & (~bit_mask) ) | (data & bit_mask);
	addr = (uint32_t *)(base + offset);

    writel(reg_val, addr);
}

/*----------------------------------------------------------------------
*	mac_init_drv
*----------------------------------------------------------------------*/
void mac_init_drv(void)
{
	TOE_INFO_T			*toe;
	int					i;
	QUEUE_THRESHOLD_T	threshold;
	u32					*destp;
	uint32_t		chip_id,chip_version;

	chip_id = readl(GMAC_GLOBAL_BASE_ADDR+0x0);
	chip_version = chip_id & 0x1;
	
	if (gmac_initialized == 0) {
		gmac_initialized = 1;

		/* clear non TOE Queue Header Area */
		destp = (u32 *)TOE_NONTOE_QUE_HDR_BASE;
		for (; destp < (u32 *)NONTOE_Q_HDR_AREA_END; destp++)
			*destp = 0x00;

		/* clear TOE Queue Header Area */
		destp = (u32 *)TOE_TOE_QUE_HDR_BASE;
		for (; destp < (u32 *)TOE_Q_HDR_AREA_END; destp++)
			*destp = 0x00;

		/* init private data */
		toe = (TOE_INFO_T *)&toe_private_data;
		memset((void *)toe, 0, sizeof(TOE_INFO_T));
		toe->gmac[0].base_addr = GMAC0_BASE;
		toe->gmac[1].base_addr = GMAC1_BASE;
		toe->gmac[0].dma_base_addr = TOE_GMAC0_DMA_BASE;
		toe->gmac[1].dma_base_addr = TOE_GMAC1_DMA_BASE;
		toe->gmac[0].auto_nego_cfg = 1;
		toe->gmac[1].auto_nego_cfg = 1;
#ifdef CONFIG_SL3516_ASIC
#ifdef __ORIGINAL__ 
		toe->gmac[0].speed_cfg = GMAC_SPEED_1000;
#else
		toe->gmac[0].speed_cfg = GMAC_SPEED_100; 
#endif
		toe->gmac[1].speed_cfg = GMAC_SPEED_1000;
#else
		toe->gmac[0].speed_cfg = GMAC_SPEED_100;
		toe->gmac[1].speed_cfg = GMAC_SPEED_100;
#endif
		toe->gmac[0].full_duplex_cfg = 1;
		toe->gmac[1].full_duplex_cfg = 1;
#ifdef CONFIG_SL3516_ASIC
#ifdef __ORIGINAL__
		toe->gmac[0].phy_mode = GMAC_PHY_RGMII_1000;
#else
		toe->gmac[0].phy_mode = GMAC_PHY_RGMII_100;
#endif
		toe->gmac[1].phy_mode = GMAC_PHY_RGMII_1000;
#else
		toe->gmac[0].phy_mode = GMAC_PHY_RGMII_100;
		toe->gmac[1].phy_mode = GMAC_PHY_RGMII_100;
#endif
		toe->gmac[0].port_id = GMAC_PORT0;
		toe->gmac[1].port_id = GMAC_PORT1;
#ifdef CONFIG_PHY_ADDR_FABRIK_SYLO_V11
                toe->gmac[0].phy_addr = 0x3; /*for fabrik's sylo*/
#else
                toe->gmac[0].phy_addr = 0x1;
                toe->gmac[1].phy_addr = 2;
#endif
//		toe->gmac[0].irq = SL2312_INTER
		toe->gmac[0].irq =1;
//		toe->gmac[1].irq = SL2312_INTERRUPT_GMAC1;
		toe->gmac[1].irq =2;
		toe->gmac[0].mac_addr1 = &eth_mac[0][0];
		toe->gmac[1].mac_addr1 = &eth_mac[1][0];

		for (i=0; i<CONFIG_MAC_NUM; i++) {
			uint32_t data, phy_vendor;
			gmac_write_reg(toe->gmac[i].base_addr, GMAC_STA_ADD2, 0x55aa55aa, 0xffffffff);
			data = gmac_read_reg(toe->gmac[i].base_addr, GMAC_STA_ADD2);
			if (data == 0x55aa55aa) {
				if ((Giga_switch == 1) && (i == 1)) {
					toe->gmac[i].existed = GMAC_EXISTED_FLAG;
					break;
				}
				if ((Tantos_switch == 1) && (i == 1)) {
					toe->gmac[i].existed = GMAC_EXISTED_FLAG;
					break;
				}
#ifdef __ORIGINAL__
				phy_vendor = gmac_get_phy_vendor(toe->gmac[i].phy_addr);
				if (phy_vendor != 0 && phy_vendor != 0xffffffff)
					toe->gmac[i].existed = GMAC_EXISTED_FLAG;
#else
				phy_vendor = gmac_get_phy_vendor(0);
				if (phy_vendor != 0 && phy_vendor != 0xffffffff)
					toe->gmac[i].existed = GMAC_EXISTED_FLAG;
				else
				  {
					phy_vendor = gmac_get_phy_vendor(1);
					if (phy_vendor != 0 && phy_vendor != 0xffffffff)
						toe->gmac[i].existed = GMAC_EXISTED_FLAG;
				  }
#endif
			}
		}
		
		/* Write GLOBAL_QUEUE_THRESHOLD_REG */
		threshold.bits32 = 0;
		threshold.bits.swfq_empty = (TOE_SW_FREEQ_DESC_NUM > 256) ? 255 :
									TOE_SW_FREEQ_DESC_NUM/2;
		threshold.bits.hwfq_empty = (TOE_HW_FREEQ_DESC_NUM > 256) ? 256/4 :
									TOE_HW_FREEQ_DESC_NUM/4;
		threshold.bits.toe_class = (TOE_TOE_DESC_NUM > 256) ? 256/4 :
									TOE_TOE_DESC_NUM/4;
		threshold.bits.intrq = (TOE_INTR_DESC_NUM > 256) ? 256/4 :
									TOE_INTR_DESC_NUM/4;
		writel(threshold.bits32, TOE_GLOBAL_BASE + GLOBAL_QUEUE_THRESHOLD_REG);

		FLAG_SWITCH = 0;
		toe_gmac_sw_reset();
		toe_init_free_queue();
		toe_init_swtx_queue();
#ifdef CONFIG_SL351x_NAT
		toe_init_hwtx_queue();
#endif
#ifdef CONFIG_SL351X_BR
		toe_init_hwtx_queue();
#endif
		toe_init_default_queue();
		toe_init_interrupt_config();

		/* for sl351x_ipsec (VPN) */

#if defined(CONFIG_SL351x_NAT) || defined(CONFIG_SL351x_RXTOE) || defined(CONFIG_SL351X_BR) ||  defined(CONFIG_SL351X_IPSEC)
		sl351x_hash_init();
#else
	  {
		volatile u32 *dp1, *dp2, dword;

		dp1 = (volatile u32 *) TOE_V_BIT_BASE;
		dp2 = (volatile u32 *) TOE_A_BIT_BASE;
	
		for (i=0; i<HASH_TOTAL_ENTRIES/32; i++) {
			*dp1++ = 0;
			dword = *dp2++;	// read-clear
		}
	  }
#endif
	}

}

/*----------------------------------------------------------------------
*	toe_init_free_queue
*	(1) Initialize the Free Queue Descriptor Base Address & size
*		Register: TOE_GLOBAL_BASE + 0x0004
*	(2) Initialize DMA Read/Write pointer for 
*		SW Free Queue and HW Free Queue
*	(3)	Initialize DMA Descriptors for
*		SW Free Queue and HW Free Queue, 
*----------------------------------------------------------------------*/
static void toe_init_free_queue(void)
{
	int 				i;
	TOE_INFO_T			*toe;
	DMA_RWPTR_T			rwptr_reg;
//	uint32_t 		rwptr_addr;
	uint32_t		desc_buf;
	GMAC_RXDESC_T		*sw_desc_ptr;
	struct sk_buff 		*skb;
#if defined(CONFIG_SL351x_NAT) || defined(CONFIG_SL351X_BR)
	GMAC_RXDESC_T		*desc_ptr;
	uint32_t		buf_ptr;
#endif

	toe = (TOE_INFO_T *)&toe_private_data;
	desc_buf = (uint32_t)DMA_MALLOC((TOE_SW_FREEQ_DESC_NUM * sizeof(GMAC_RXDESC_T)),
				(dma_addr_t *)&toe->sw_freeq_desc_base_dma);
	sw_desc_ptr = (GMAC_RXDESC_T *)desc_buf;
	if (!desc_buf) {
		printk("%s::DMA_MALLOC fail !\n",__func__);
		return;
	}
	memset((void *)desc_buf, 0, TOE_SW_FREEQ_DESC_NUM * sizeof(GMAC_RXDESC_T));
	
	/* DMA Queue Base & Size */
	writel((toe->sw_freeq_desc_base_dma & DMA_Q_BASE_MASK) | TOE_SW_FREEQ_DESC_POWER,
			TOE_GLOBAL_BASE + GLOBAL_SW_FREEQ_BASE_SIZE_REG);

	/* init descriptor base */
	toe->swfq_desc_base = desc_buf;

	/* SW Free Queue Read/Write Pointer */
	rwptr_reg.bits.wptr = TOE_SW_FREEQ_DESC_NUM - 1;
	rwptr_reg.bits.rptr = 0;
	toe->fq_rx_rwptr.bits32 = rwptr_reg.bits32;
	writel(rwptr_reg.bits32, TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);

	/* SW Free Queue Descriptors */
	for (i=0; i<TOE_SW_FREEQ_DESC_NUM; i++) {
		sw_desc_ptr->word0.bits.buffer_size = SW_RX_BUF_SIZE;
		sw_desc_ptr->word1.bits.sw_id = i;	/* used to locate skb */
		if ((skb=dev_alloc_skb(SW_RX_BUF_SIZE)) == NULL)  /* allocate socket buffer */
		{
			printk("%s::skb buffer allocation fail !\n",__func__);
			while(1);
		}
		REG32(skb->data) = (uint32_t)skb;
		skb_reserve(skb, SKB_RESERVE_BYTES);
		// toe->rx_skb[i] = skb;
		sw_desc_ptr->word2.buf_adr = (uint32_t)__pa(skb->data);
//		consistent_sync((uint32_t)desc_ptr, sizeof(GMAC_RXDESC_T), PCI_DMA_TODEVICE);
		sw_desc_ptr++;
	}

#if defined(CONFIG_SL351x_NAT) || defined(CONFIG_SL351X_BR)
	if (sizeof(skb->cb) < 64) {
		printk("==> %s:: sk structure is incorrect -->Change to cb[64] !\n",__func__);
		while(1);
	}
	/* init hardware free queues */
	desc_buf = (uint32_t)DMA_MALLOC((TOE_HW_FREEQ_DESC_NUM * sizeof(GMAC_RXDESC_T)),
				(dma_addr_t *)&toe->hw_freeq_desc_base_dma) ;
	desc_ptr = (GMAC_RXDESC_T *)desc_buf;
	if (!desc_buf) {
		printk("%s::DMA_MALLOC fail !\n",__func__);
		return;
	}
	memset((void *)desc_buf, 0, TOE_HW_FREEQ_DESC_NUM * sizeof(GMAC_RXDESC_T));

	/* DMA Queue Base & Size */
	writel((toe->hw_freeq_desc_base_dma & DMA_Q_BASE_MASK) | TOE_HW_FREEQ_DESC_POWER,
			TOE_GLOBAL_BASE + GLOBAL_HW_FREEQ_BASE_SIZE_REG);

	/* init descriptor base */
	toe->hwfq_desc_base = desc_buf;

	/* HW Free Queue Read/Write Pointer */
	rwptr_reg.bits.wptr = TOE_HW_FREEQ_DESC_NUM - 1;
	rwptr_reg.bits.rptr = 0;
	writel(rwptr_reg.bits32, TOE_GLOBAL_BASE + GLOBAL_HWFQ_RWPTR_REG);
#ifndef HW_RXBUF_BY_KMALLOC
	buf_ptr = (uint32_t)DMA_MALLOC(TOE_HW_FREEQ_DESC_NUM * HW_RX_BUF_SIZE,
				(dma_addr_t *)&toe->hwfq_buf_base_dma);
#else
	buf_ptr = (uint32_t)kmalloc(TOE_HW_FREEQ_DESC_NUM * HW_RX_BUF_SIZE, GFP_KERNEL);
	toe->hwfq_buf_base_dma = __pa(buf_ptr);
#endif
	if (!buf_ptr) {
		printk("===> %s::Failed to allocate HW TxQ Buffers!\n",__func__);
		while(1);
		/* should not happen. if so, adjust the buffer descriptor number */
		return;
	}

	toe->hwfq_buf_base = buf_ptr;
	toe->hwfq_buf_end_dma = toe->hwfq_buf_base_dma + (TOE_HW_FREEQ_DESC_NUM * HW_RX_BUF_SIZE);
	buf_ptr = (uint32_t)toe->hwfq_buf_base_dma;
	for (i=0; i<TOE_HW_FREEQ_DESC_NUM; i++) {
		desc_ptr->word0.bits.buffer_size = HW_RX_BUF_SIZE;
		desc_ptr->word1.bits.sw_id = i;
		desc_ptr->word2.buf_adr = (uint32_t)buf_ptr;
		//consistent_sync((uint32_t)desc_ptr, sizeof(GMAC_RXDESC_T), PCI_DMA_TODEVICE);
		//consistent_sync((uint32_t)buf_ptr, HW_RX_BUF_SIZE, PCI_DMA_TODEVICE);
		desc_ptr++;
		buf_ptr += HW_RX_BUF_SIZE;
	}
#else
	/* DMA Queue Base & Size */
	writel((0) | TOE_SW_FREEQ_DESC_POWER,
			TOE_GLOBAL_BASE + GLOBAL_HW_FREEQ_BASE_SIZE_REG);
	rwptr_reg.bits.wptr = TOE_HW_FREEQ_DESC_NUM - 1;
	rwptr_reg.bits.rptr = 0;
	writel(rwptr_reg.bits32, TOE_GLOBAL_BASE + GLOBAL_HWFQ_RWPTR_REG);

#endif
}

/*----------------------------------------------------------------------
*	toe_init_swtx_queue
*	(2) Initialize the GMAC 0/1 SW TXQ Queue Descriptor Base Address & sizeup
*		GMAC_SW_TX_QUEUE_BASE_REG(0x0050)
*	(2) Initialize DMA Read/Write pointer for 
*		GMAC 0/1 SW TX Q0-5
*----------------------------------------------------------------------*/
static void toe_init_swtx_queue(void)
{
	int 			i;
	TOE_INFO_T		*toe;
	DMA_RWPTR_T		rwptr_reg;
	uint32_t 		rwptr_addr;
	uint32_t		desc_buf;

	toe = (TOE_INFO_T *)&toe_private_data;

	/*
	 * GMAC-0, SW-TXQ
	 * The GMAC-0 and GMAC-0 maybe have different descriptor number
	 * so, not use for instruction
	 */
	desc_buf = (uint32_t)DMA_MALLOC((TOE_GMAC0_SWTXQ_DESC_NUM * TOE_SW_TXQ_NUM * sizeof(GMAC_TXDESC_T)),
				(dma_addr_t *)&toe->gmac[0].swtxq_desc_base_dma) ;
	toe->gmac[0].swtxq_desc_base = desc_buf;
	if (!desc_buf) {
		printk("%s::DMA_MALLOC fail !\n",__func__);
		return;
	}
	memset((void *)desc_buf, 0,	TOE_GMAC0_SWTXQ_DESC_NUM * TOE_SW_TXQ_NUM * sizeof(GMAC_TXDESC_T));
	writel((toe->gmac[0].swtxq_desc_base_dma & DMA_Q_BASE_MASK) | TOE_GMAC0_SWTXQ_DESC_POWER,
			TOE_GMAC0_DMA_BASE+ GMAC_SW_TX_QUEUE_BASE_REG);

	/* GMAC0 SW TX Q0-Q5 */
	rwptr_reg.bits.wptr = 0;
	rwptr_reg.bits.rptr = 0;
	rwptr_addr = TOE_GMAC0_DMA_BASE + GMAC_SW_TX_QUEUE0_PTR_REG;
	for (i=0; i<TOE_SW_TXQ_NUM; i++) {
		toe->gmac[0].swtxq[i].rwptr_reg = rwptr_addr;
		toe->gmac[0].swtxq[i].desc_base = desc_buf;
		toe->gmac[0].swtxq[i].total_desc_num = TOE_GMAC0_SWTXQ_DESC_NUM;
		desc_buf += TOE_GMAC0_SWTXQ_DESC_NUM * sizeof(GMAC_TXDESC_T);
		writel(rwptr_reg.bits32, rwptr_addr);
		rwptr_addr+=4;
	}

	/* GMAC-1, SW-TXQ */
	desc_buf = (uint32_t)DMA_MALLOC((TOE_GMAC1_SWTXQ_DESC_NUM * TOE_SW_TXQ_NUM * sizeof(GMAC_TXDESC_T)),
				(dma_addr_t *)&toe->gmac[1].swtxq_desc_base_dma) ;
	toe->gmac[1].swtxq_desc_base = desc_buf;
	if (!desc_buf) {
		printk("%s::DMA_MALLOC fail !\n",__func__);
		return	;
	}
	memset((void *)desc_buf, 0,	TOE_GMAC1_SWTXQ_DESC_NUM * TOE_SW_TXQ_NUM * sizeof(GMAC_TXDESC_T));
	writel((toe->gmac[1].swtxq_desc_base_dma & DMA_Q_BASE_MASK) | TOE_GMAC1_SWTXQ_DESC_POWER,
			TOE_GMAC1_DMA_BASE+ GMAC_SW_TX_QUEUE_BASE_REG);

	/* GMAC1 SW TX Q0-Q5 */
	rwptr_reg.bits.wptr = 0;
	rwptr_reg.bits.rptr = 0;
	rwptr_addr = TOE_GMAC1_DMA_BASE + GMAC_SW_TX_QUEUE0_PTR_REG;
	for (i=0; i<TOE_SW_TXQ_NUM; i++) {
		toe->gmac[1].swtxq[i].rwptr_reg = rwptr_addr;
		toe->gmac[1].swtxq[i].desc_base = desc_buf;
		toe->gmac[1].swtxq[i].total_desc_num = TOE_GMAC1_SWTXQ_DESC_NUM;
		desc_buf += TOE_GMAC1_SWTXQ_DESC_NUM * sizeof(GMAC_TXDESC_T);
		writel(rwptr_reg.bits32, rwptr_addr);
		rwptr_addr+=4;
	}
}

/*----------------------------------------------------------------------
*	toe_init_hwtx_queue
*	(2) Initialize the GMAC 0/1 HW TXQ Queue Descriptor Base Address & size
*		GMAC_HW_TX_QUEUE_BASE_REG(0x0054)
*	(2) Initialize DMA Read/Write pointer for 
*		GMAC 0/1 HW TX Q0-5
*----------------------------------------------------------------------*/
#if defined(CONFIG_SL351x_NAT) || defined(CONFIG_SL351X_BR)
static void toe_init_hwtx_queue(void)
{
	int 				i;
	TOE_INFO_T			*toe;
	DMA_RWPTR_T			rwptr_reg;
	uint32_t 		rwptr_addr;
	uint32_t		desc_buf;
	
	toe = (TOE_INFO_T *)&toe_private_data;
	/* 
	 * GMAC-0, HW-TXQ
	 * The GMAC-0 and GMAC-0 maybe have different descriptor number
	 * so, not use for instruction
	 */
	desc_buf = (uint32_t)DMA_MALLOC((TOE_GMAC0_HWTXQ_DESC_NUM * TOE_HW_TXQ_NUM * sizeof(GMAC_TXDESC_T)),
						(dma_addr_t *)&toe->gmac[0].hwtxq_desc_base_dma) ;
	toe->gmac[0].hwtxq_desc_base = desc_buf;
	if (!desc_buf) {
		printk("%s::DMA_MALLOC fail !\n",__func__);
		return	;
	}
	memset((void *)desc_buf, 0,	TOE_GMAC0_HWTXQ_DESC_NUM * TOE_HW_TXQ_NUM * sizeof(GMAC_TXDESC_T));
	writel((toe->gmac[0].hwtxq_desc_base_dma & DMA_Q_BASE_MASK) | TOE_GMAC0_HWTXQ_DESC_POWER,
			TOE_GMAC0_DMA_BASE+ GMAC_HW_TX_QUEUE_BASE_REG);
	
	/* GMAC0 HW TX Q0-Q5 */
	rwptr_reg.bits.wptr = 0;
	rwptr_reg.bits.rptr = 0;
	rwptr_addr = TOE_GMAC0_DMA_BASE + GMAC_HW_TX_QUEUE0_PTR_REG;
	for (i=0; i<TOE_HW_TXQ_NUM; i++) {
		toe->gmac[0].hwtxq[i].desc_base = desc_buf;
		desc_buf += TOE_GMAC0_HWTXQ_DESC_NUM * sizeof(GMAC_TXDESC_T);
		writel(rwptr_reg.bits32, rwptr_addr);
		rwptr_addr+=4;
	}

	/* GMAC-1, HW-TXQ */
	desc_buf = (uint32_t)DMA_MALLOC((TOE_GMAC1_HWTXQ_DESC_NUM * TOE_HW_TXQ_NUM * sizeof(GMAC_TXDESC_T)),
						(dma_addr_t *)&toe->gmac[1].hwtxq_desc_base_dma) ;
	toe->gmac[1].hwtxq_desc_base = desc_buf;
	if (!desc_buf) {
		printk("%s::DMA_MALLOC fail !\n",__func__);
		return	;
	}
	memset((void *)desc_buf, 0,	TOE_GMAC1_HWTXQ_DESC_NUM * TOE_HW_TXQ_NUM * sizeof(GMAC_TXDESC_T));
	writel((toe->gmac[1].hwtxq_desc_base_dma & DMA_Q_BASE_MASK) | TOE_GMAC1_HWTXQ_DESC_POWER,
			TOE_GMAC1_DMA_BASE+ GMAC_HW_TX_QUEUE_BASE_REG);

	/* GMAC1 HW TX Q0-Q5 */
	rwptr_reg.bits.wptr = 0;
	rwptr_reg.bits.rptr = 0;
	rwptr_addr = TOE_GMAC1_DMA_BASE + GMAC_HW_TX_QUEUE0_PTR_REG;
	for (i=0; i<TOE_HW_TXQ_NUM; i++) {
		toe->gmac[1].hwtxq[i].desc_base = desc_buf;
		desc_buf += TOE_GMAC1_HWTXQ_DESC_NUM * sizeof(GMAC_TXDESC_T);
		writel(rwptr_reg.bits32, rwptr_addr);
		rwptr_addr+=4;
	}
}
#endif

/*----------------------------------------------------------------------
*	toe_init_default_queue
*	(1) Initialize the default 0/1 Queue Header
*		Register: TOE_DEFAULT_Q0_HDR_BASE (0x60002000)
*				  TOE_DEFAULT_Q1_HDR_BASE (0x60002008)
*	(2)	Initialize Descriptors of Default Queue 0/1
*----------------------------------------------------------------------*/
static void toe_init_default_queue(void)
{
	TOE_INFO_T				*toe;
	volatile NONTOE_QHDR_T	*qhdr;
	GMAC_RXDESC_T			*desc_ptr;
	DMA_SKB_SIZE_T			skb_size;

	toe = (TOE_INFO_T *)&toe_private_data;
	desc_ptr = (GMAC_RXDESC_T *)DMA_MALLOC((TOE_DEFAULT_Q0_DESC_NUM * sizeof(GMAC_RXDESC_T)),
											(dma_addr_t *)&toe->gmac[0].default_desc_base_dma);
	if (!desc_ptr) {
		printk("%s::DMA_MALLOC fail !\n",__func__);
		return	;
	}
	memset((void *)desc_ptr, 0, TOE_DEFAULT_Q0_DESC_NUM * sizeof(GMAC_RXDESC_T));
	toe->gmac[0].default_desc_base = (uint32_t)desc_ptr;				
	toe->gmac[0].default_desc_num = TOE_DEFAULT_Q0_DESC_NUM;
	qhdr = (volatile NONTOE_QHDR_T *)TOE_DEFAULT_Q0_HDR_BASE;
	qhdr->word0.base_size = ((uint32_t)toe->gmac[0].default_desc_base_dma & NONTOE_QHDR0_BASE_MASK) | TOE_DEFAULT_Q0_DESC_POWER;
	qhdr->word1.bits32 = 0;
	toe->gmac[0].rx_rwptr.bits32 = 0;
	toe->gmac[0].default_qhdr = (NONTOE_QHDR_T *)qhdr;
	desc_ptr = (GMAC_RXDESC_T *)DMA_MALLOC((TOE_DEFAULT_Q1_DESC_NUM * sizeof(GMAC_RXDESC_T)),
											(dma_addr_t *)&toe->gmac[1].default_desc_base_dma);
	if (!desc_ptr) {
		printk("%s::DMA_MALLOC fail !\n",__func__);
		return	;
	}
	memset((void *)desc_ptr, 0, TOE_DEFAULT_Q1_DESC_NUM * sizeof(GMAC_RXDESC_T));
	toe->gmac[1].default_desc_base = (uint32_t)desc_ptr;
	toe->gmac[1].default_desc_num = TOE_DEFAULT_Q1_DESC_NUM;
	qhdr = (volatile NONTOE_QHDR_T *)TOE_DEFAULT_Q1_HDR_BASE;
	qhdr->word0.base_size = ((uint32_t)toe->gmac[1].default_desc_base_dma & NONTOE_QHDR0_BASE_MASK) | TOE_DEFAULT_Q1_DESC_POWER;
	qhdr->word1.bits32 = 0;
	toe->gmac[1].rx_rwptr.bits32 = 0;
	toe->gmac[1].default_qhdr = (NONTOE_QHDR_T *)qhdr;

	skb_size.bits.hw_skb_size = HW_RX_BUF_SIZE;
	skb_size.bits.sw_skb_size = SW_RX_BUF_SIZE;
	writel(skb_size.bits32, TOE_GLOBAL_BASE + GLOBAL_DMA_SKB_SIZE_REG);
}

/*----------------------------------------------------------------------
*	toe_init_interrupt_queue
*	(1) Initialize the Interrupt Queue Header
*		Register: TOE_INTR_Q_HDR_BASE (0x60002080)
*	(2)	Initialize Descriptors of Interrupt Queues
*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
*	toe_init_interrupt_config
*	Interrupt Select Registers are used to map interrupt to int0 or int1
*	Int0 and int1 are wired to CPU 0/1 GMAC 0/1
* 	Interrupt Device Inteface data are used to pass device info to
*		upper device deiver or store status/statistics
*	ISR handler
*		(1) If status bit ON but masked, the prinf error message (bug issue)
*		(2) If select bits are for me, handle it, else skip to let 
*			the other ISR handles it.
*  Notes:
*		GMACx init routine (for eCOS) or open routine (for Linux)
*       enable the interrupt bits only which are selected for him.
*
*	Default Setting:
*		GMAC0 intr bits ------>	int0 ----> eth0
*		GMAC1 intr bits ------> int1 ----> eth1
*		TOE intr -------------> int0 ----> eth0
*		Classification Intr --> int0 ----> eth0
*		Default Q0 -----------> int0 ----> eth0
*		Default Q1 -----------> int1 ----> eth1
*----------------------------------------------------------------------*/
static void toe_init_interrupt_config(void)
{
	/* clear all status bits */
	writel(0xffffffff, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_0_REG);
	writel(0xffffffff, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_1_REG);
	writel(0xffffffff, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_2_REG);
	writel(0xffffffff, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_3_REG);
	writel(0xffffffff, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_4_REG);

	/* Init select registers */
	writel(0, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_0_REG);
	writel(0, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_1_REG);
	writel(0, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_2_REG);
	writel(0, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_3_REG);
	writel(0, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_4_REG);

	/* disable all interrupt */
	writel(0, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_0_REG);
	writel(0, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);
	writel(0, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_2_REG);
	writel(0, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_3_REG);
	writel(0, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_4_REG);
}

/*----------------------------------------------------------------------
*	toe_init_gmac
*----------------------------------------------------------------------*/
static void toe_init_gmac(struct net_device *dev)
{
	GMAC_INFO_T		*tp = dev->priv;
	TOE_INFO_T		*toe;
	u32 			data;

	if (!gmac_initialized) return;

	if (!tp->existed) return;

	tp->dev = dev;
	tp->flow_control_enable = 1;
	tp->pre_phy_status = LINK_DOWN;
	tp->full_duplex_status = tp->full_duplex_cfg;
	tp->speed_status = tp->speed_status;

	/* get mac address from FLASH */
	gmac_get_mac_address();

	/* set PHY register to start autonegition process */
	gmac_set_phy_status(dev);

	/* GMAC initialization */
	if (toe_gmac_init_chip(dev)) {
		printk ("GMAC %d init fail\n", tp->port_id);
	}

	/* clear statistic counter */
	toe_gmac_clear_counter(dev);

	memset((void *)&tp->ifStatics, 0, sizeof(struct net_device_stats));

	/* -----------------------------------------------------------
	 * Enable GMAC interrupt & disable loopback 
	 * Notes:
	 *		GMACx init routine (for eCOS) or open routine (for Linux)
	 *		enable the interrupt bits only which are selected for him.
	 * ----------------------------------------------------------- */
	toe = (TOE_INFO_T *)&toe_private_data;

	/* Enable Interrupt Bits */
	if (tp->port_id == 0) {
		tp->intr0_selected = GMAC0_TXDERR_INT_BIT	| GMAC0_TXPERR_INT_BIT	|
				GMAC0_RXDERR_INT_BIT		| GMAC0_RXPERR_INT_BIT		|
				GMAC0_SWTQ05_FIN_INT_BIT	| GMAC0_SWTQ05_EOF_INT_BIT	|
				GMAC0_SWTQ04_FIN_INT_BIT	| GMAC0_SWTQ04_EOF_INT_BIT	|
				GMAC0_SWTQ03_FIN_INT_BIT	| GMAC0_SWTQ03_EOF_INT_BIT	|
				GMAC0_SWTQ02_FIN_INT_BIT	| GMAC0_SWTQ02_EOF_INT_BIT	|
				GMAC0_SWTQ01_FIN_INT_BIT	| GMAC0_SWTQ01_EOF_INT_BIT	|
				GMAC0_SWTQ00_FIN_INT_BIT	| GMAC0_SWTQ00_EOF_INT_BIT;

#ifdef GMAX_TX_INTR_DISABLED
		tp->intr0_enabled = 0;
#else
		tp->intr0_enabled = GMAC0_SWTQ00_FIN_INT_BIT | GMAC0_SWTQ00_EOF_INT_BIT;
#endif

		tp->intr1_selected = TOE_IQ_ALL_BITS	| DEFAULT_Q0_INT_BIT	|
				GMAC0_HWTQ03_EOF_INT_BIT	| GMAC0_HWTQ02_EOF_INT_BIT	|
				GMAC0_HWTQ01_EOF_INT_BIT	| GMAC0_HWTQ00_EOF_INT_BIT;
	    tp->intr1_enabled = DEFAULT_Q0_INT_BIT	| TOE_IQ_ALL_BITS;

	    tp->intr2_selected = 0xffffffff;	/* TOE Queue 32-63 FUUL Intr */
	    tp->intr2_enabled  = 0xffffffff;
	    tp->intr3_selected = 0xffffffff;	/* TOE Queue 0-31 FUUL Intr */
	    tp->intr3_enabled  = 0xffffffff;
	    tp->intr4_selected = GMAC0_INT_BITS | CLASS_RX_FULL_INT_BITS |
					HWFQ_EMPTY_INT_BIT | SWFQ_EMPTY_INT_BIT;
	    tp->intr4_enabled  = GMAC0_INT_BITS | SWFQ_EMPTY_INT_BIT;

		data = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_0_REG)
				& ~tp->intr0_selected;
		writel(data, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_0_REG);
		data = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_1_REG)
				& ~tp->intr1_selected;
		writel(data, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_1_REG);
		data = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_2_REG)
				& ~tp->intr2_selected;
		writel(data, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_2_REG);
		data = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_3_REG)
				& ~tp->intr3_selected;
		writel(data, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_3_REG);
		data = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_4_REG)
				& ~tp->intr4_selected;
		writel(data, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_4_REG);
	} else { /* if (tp->port_id == 1) */
		tp->intr0_selected  = GMAC1_TXDERR_INT_BIT	| GMAC1_TXPERR_INT_BIT	|
				GMAC1_RXDERR_INT_BIT		| GMAC1_RXPERR_INT_BIT		|
				GMAC1_SWTQ15_FIN_INT_BIT	| GMAC1_SWTQ15_EOF_INT_BIT	|
				GMAC1_SWTQ14_FIN_INT_BIT	| GMAC1_SWTQ14_EOF_INT_BIT	|
				GMAC1_SWTQ13_FIN_INT_BIT	| GMAC1_SWTQ13_EOF_INT_BIT	|
				GMAC1_SWTQ12_FIN_INT_BIT	| GMAC1_SWTQ12_EOF_INT_BIT	|
				GMAC1_SWTQ11_FIN_INT_BIT	| GMAC1_SWTQ11_EOF_INT_BIT	|
				GMAC1_SWTQ10_FIN_INT_BIT	| GMAC1_SWTQ10_EOF_INT_BIT;
#ifdef GMAX_TX_INTR_DISABLED
		tp->intr0_enabled = 0;
#else
		tp->intr0_enabled = GMAC1_SWTQ10_FIN_INT_BIT | GMAC1_SWTQ10_EOF_INT_BIT;
#endif
		tp->intr1_selected = DEFAULT_Q1_INT_BIT;
		tp->intr1_enabled  = DEFAULT_Q1_INT_BIT;

		tp->intr2_selected = 0;		/* TOE Queue 32-63 FUUL Intr */
		tp->intr2_enabled  = 0;
		tp->intr3_selected = 0;		/* TOE Queue 0-31 FUUL Intr */
		tp->intr3_enabled  = 0;
		tp->intr4_selected = GMAC1_INT_BITS;
		tp->intr4_enabled  = GMAC1_INT_BITS;

		if (toe->gmac[0].existed != GMAC_EXISTED_FLAG) {
			tp->intr1_selected |= TOE_IQ_ALL_BITS |
					GMAC0_HWTQ03_EOF_INT_BIT | GMAC0_HWTQ02_EOF_INT_BIT	|
					GMAC0_HWTQ01_EOF_INT_BIT | GMAC0_HWTQ00_EOF_INT_BIT;
			tp->intr1_enabled  |= TOE_IQ_ALL_BITS;

			tp->intr1_selected |= TOE_CLASS_RX_INT_BITS;
			tp->intr2_selected |= 0xffffffff;	/* TOE Queue 32-63 FUUL Intr */
			tp->intr2_enabled  |= 0xffffffff;
			tp->intr3_selected |= 0xffffffff;	/* TOE Queue 0-31 FUUL Intr */
			tp->intr3_enabled  |= 0xffffffff;
			tp->intr4_selected |= CLASS_RX_FULL_INT_BITS |
					HWFQ_EMPTY_INT_BIT | SWFQ_EMPTY_INT_BIT;
			tp->intr4_enabled  |= SWFQ_EMPTY_INT_BIT;
		}
		data = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_0_REG) |
				tp->intr0_selected;
		writel(data, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_0_REG);
		data = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_1_REG) |
				tp->intr1_selected;
		writel(data, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_1_REG);
		data = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_2_REG) |
				tp->intr2_selected;
		writel(data, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_2_REG);
		data = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_3_REG) |
				tp->intr3_selected;
		writel(data, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_3_REG);
		data = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_4_REG) |
				tp->intr4_selected;
		writel(data, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_SELECT_4_REG);
	}

	/* enable only selected bits */
	gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_ENABLE_0_REG,
			tp->intr0_enabled, tp->intr0_selected);
	gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_ENABLE_1_REG,
			tp->intr1_enabled, tp->intr1_selected);
	gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_ENABLE_2_REG,
			tp->intr2_enabled, tp->intr2_selected);
	gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_ENABLE_3_REG,
			tp->intr3_enabled, tp->intr3_selected);
	gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_ENABLE_4_REG,
			tp->intr4_enabled, tp->intr4_selected);

    /* start DMA process */
	toe_gmac_hw_start(dev);

	/* enable tx/rx register */    
	toe_gmac_enable_tx_rx(dev);

//	toe_gmac_enable_interrupt(tp->irq);

	return;
}

/*----------------------------------------------------------------------
* toe_gmac_sw_reset
*----------------------------------------------------------------------*/
static void toe_gmac_sw_reset(void)
{
	uint32_t	reg_val;
	/* GMAC0 S/W reset */
	reg_val = readl(GMAC_GLOBAL_BASE_ADDR+GLOBAL_RESET_REG) | 0x00000060;
    writel(reg_val,GMAC_GLOBAL_BASE_ADDR+GLOBAL_RESET_REG);
    udelay(100);
    return;
}

/*----------------------------------------------------------------------
*	toe_gmac_init_chip
*----------------------------------------------------------------------*/
static int toe_gmac_init_chip(struct net_device *dev)
{
	GMAC_INFO_T 	*tp = dev->priv;
	GMAC_CONFIG2_T	config2_val;
	GMAC_CONFIG0_T	config0,config0_mask;
	GMAC_CONFIG1_T	config1;
	#if defined(CONFIG_SL351x_NAT) || defined(CONFIG_SL351X_BR)
	GMAC_CONFIG3_T	config3_val;
	#endif
	GMAC_TX_WCR0_T	hw_weigh;
	GMAC_TX_WCR1_T	sw_weigh;
	struct sockaddr sock;
	//GMAC_AHB_WEIGHT_T	ahb_weight, ahb_weight_mask;

	/* set station MAC address1 and address2 */
	memcpy(&sock.sa_data[0], &eth_mac[tp->port_id][0], 6);
	gmac_set_mac_address(dev, (void *)&sock);

	/* set RX_FLTR register to receive all multicast packet */
	gmac_write_reg(tp->base_addr, GMAC_RX_FLTR, 0x00000007,0x0000001f);
	//gmac_write_reg(tp->base_addr, GMAC_RX_FLTR, 0x00000007,0x0000001f);
	//gmac_write_reg(tp->base_addr, GMAC_RX_FLTR,0x00000007,0x0000001f);

	/* set per packet buffer size */
	//	config1.bits32 = 0x002004;	//next version
	/* set flow control threshold */
	config1.bits32 = 0;
	config1.bits.set_threshold = 32 / 2;
	config1.bits.rel_threshold = 32 / 4 * 3;
	gmac_write_reg(tp->base_addr, GMAC_CONFIG1, config1.bits32, 0xffffffff);

	/* set flow control threshold */
	config2_val.bits32 = 0;
	config2_val.bits.set_threshold = TOE_SW_FREEQ_DESC_NUM/2;
	config2_val.bits.rel_threshold = TOE_SW_FREEQ_DESC_NUM*3/4;
	gmac_write_reg(tp->base_addr, GMAC_CONFIG2, config2_val.bits32,0xffffffff);

	#if defined(CONFIG_SL351x_NAT) || defined(CONFIG_SL351X_BR)
	/* set HW free queue flow control threshold */
	config3_val.bits32 = 0;
	config3_val.bits.set_threshold = PAUSE_SET_HW_FREEQ;
	config3_val.bits.rel_threshold = PAUSE_REL_HW_FREEQ;
	gmac_write_reg(tp->base_addr, GMAC_CONFIG3, config3_val.bits32,0xffffffff);
	#endif
	/* set_mcast_filter mask*/
	//gmac_write_reg(tp->base_addr, GMAC_MCAST_FIL0, 0x0, 0xffffffff);
	// gmac_write_reg(tp->base_addr, GMAC_MCAST_FIL1, 0x0, 0xffffffff);

	/* disable TX/RX and disable internal loop back */
	config0.bits32 = 0;
	config0_mask.bits32 = 0;

	//debug_Aaron
	config0.bits.max_len = 2;

	if (tp->flow_control_enable==1) {
		config0.bits.tx_fc_en = 1;	/* enable tx flow control */
		config0.bits.rx_fc_en = 1;	/* enable rx flow control */
		printk("Enable MAC Flow Control...\n");
	} else {
		config0.bits.tx_fc_en = 0;	/* disable tx flow control */
		config0.bits.rx_fc_en = 0;	/* disable rx flow control */
		printk("Disable MAC Flow Control...\n");
	}
	config0.bits.dis_rx = 1;	/* disable rx */
	config0.bits.dis_tx = 1;	/* disable tx */
	config0.bits.loop_back = 0;	/* enable/disable GMAC loopback */
	config0.bits.rx_err_detect = 1;
	config0.bits.rgmii_en = 0;
	config0.bits.rgmm_edge = 1;
	config0.bits.rxc_inv = 0;
	config0.bits.ipv4_rx_chksum = 1;	/* enable H/W to check ip checksum */
	config0.bits.ipv6_rx_chksum = 1;	/* enable H/W to check ip checksum */
	config0.bits.port0_chk_hwq = 1;		/* GaryChen 3/24/2006 2:26PM */
	config0.bits.port1_chk_hwq = 1;		/* GaryChen 3/24/2006 2:26PM */
	config0.bits.port0_chk_toeq = 1;
	config0.bits.port1_chk_toeq = 1;
	config0.bits.port0_chk_classq = 1;
	config0.bits.port1_chk_classq = 1;

	config0_mask.bits.max_len = 7;
	config0_mask.bits.tx_fc_en = 1;
	config0_mask.bits.rx_fc_en = 1;
	config0_mask.bits.dis_rx = 1;
	config0_mask.bits.dis_tx = 1;
	config0_mask.bits.loop_back = 1;
	config0_mask.bits.rgmii_en = 1;
	config0_mask.bits.rgmm_edge = 1;
	config0_mask.bits.rxc_inv = 1;
	config0_mask.bits.ipv4_rx_chksum = 1;
	config0_mask.bits.ipv6_rx_chksum = 1;
	config0_mask.bits.port0_chk_hwq = 1;
	config0_mask.bits.port1_chk_hwq = 1;
	config0_mask.bits.port0_chk_toeq = 1;
	config0_mask.bits.port1_chk_toeq = 1;
	config0_mask.bits.port0_chk_classq = 1;
	config0_mask.bits.port1_chk_classq = 1;
	config0_mask.bits.rx_err_detect = 1;

	#if 0
	config0.bits.dis_rx = 1;  /* disable rx */
	config0.bits.dis_tx = 1;  /* disable tx */
	config0.bits.loop_back = 0; /* enable/disable GMAC loopback */
	config0.bits.txc_inv = 0;
	config0.bits.rgmii_en = 0;
	config0.bits.rgmm_edge = 1;
	config0.bits.rxc_inv = 1;
	config0.bits.ipv4_tss_rx_en = 1;  /* enable H/W to check ip checksum */
	config0.bits.ipv6_tss_rx_en = 1;  /* enable H/W to check ip checksum */

	config0_mask.bits.max_len = 3;
	config0_mask.bits.tx_fc_en = 1;
	config0_mask.bits.rx_fc_en = 1;
	config0_mask.bits.dis_rx = 1;
	config0_mask.bits.dis_tx = 1;
	config0_mask.bits.loop_back = 1;
	config0_mask.bits.rgmii_en = 1;
	config0_mask.bits.rgmm_edge = 1;
	config0_mask.bits.txc_inv = 1;
	config0_mask.bits.rxc_inv = 1;
	config0_mask.bits.ipv4_tss_rx_en = 1;
	config0_mask.bits.ipv6_tss_rx_en = 1;
	#endif

	gmac_write_reg(tp->base_addr, GMAC_CONFIG0, config0.bits32,config0_mask.bits32);

	#if 1
	hw_weigh.bits32 = 0;
	hw_weigh.bits.hw_tq3 = 1;
	hw_weigh.bits.hw_tq2 = 1;
	hw_weigh.bits.hw_tq1 = 1;
	hw_weigh.bits.hw_tq0 = 1;
	gmac_write_reg(tp->dma_base_addr, GMAC_TX_WEIGHTING_CTRL_0_REG, hw_weigh.bits32, 0xffffffff);

	sw_weigh.bits32 = 0;
	sw_weigh.bits.sw_tq5 = 1;
	sw_weigh.bits.sw_tq4 = 1;
	sw_weigh.bits.sw_tq3 = 1;
	sw_weigh.bits.sw_tq2 = 1;
	sw_weigh.bits.sw_tq1 = 1;
	sw_weigh.bits.sw_tq0 = 1;
	gmac_write_reg(tp->dma_base_addr, GMAC_TX_WEIGHTING_CTRL_1_REG, sw_weigh.bits32, 0xffffffff);
	#endif

	#if 0
	ahb_weight.bits32 = 0;
	ahb_weight_mask.bits32 = 0;
	ahb_weight.bits.rx_weight = 1;
	ahb_weight.bits.tx_weight = 1;
	ahb_weight.bits.hash_weight = 1;
	ahb_weight.bits.pre_req = 0x1f;
	ahb_weight.bits.tqDV_threshold = 0;
	ahb_weight_mask.bits.rx_weight = 0x1f;
	ahb_weight_mask.bits.tx_weight = 0x1f;
	ahb_weight_mask.bits.hash_weight = 0x1f;
	ahb_weight_mask.bits.pre_req = 0x1f;
	ahb_weight_mask.bits.tqDV_threshold = 0x1f;
	gmac_write_reg(tp->dma_base_addr, GMAC_AHB_WEIGHT_REG, ahb_weight.bits32, ahb_weight_mask.bits32);
	#endif

	gmac_write_reg(tp->dma_base_addr, GMAC_SPR0, IPPROTO_TCP, 0xffffffff);
	gmac_write_reg(tp->dma_base_addr, GMAC_SPR1, IPPROTO_UDP, 0xffffffff);
	gmac_write_reg(tp->dma_base_addr, GMAC_SPR2, IPPROTO_GRE, 0xffffffff);
	gmac_write_reg(tp->dma_base_addr, GMAC_SPR3, IPPROTO_ESP, 0xffffffff);
	gmac_write_reg(tp->dma_base_addr, GMAC_SPR4, IPPROTO_AH, 0xffffffff);
	gmac_write_reg(tp->dma_base_addr, GMAC_SPR5, 0xff, 0xffffffff);
	gmac_write_reg(tp->dma_base_addr, GMAC_SPR6, 0xff, 0xffffffff);
	gmac_write_reg(tp->dma_base_addr, GMAC_SPR7, 0xff, 0xffffffff);

#ifdef CONFIG_SL351x_NAT
	sl351x_nat_init();
#endif
#ifdef CONFIG_SL351X_BR
	sl351x_br_init();
#endif	

	return (0);
}

/*----------------------------------------------------------------------
*	toe_gmac_enable_tx_rx
*----------------------------------------------------------------------*/
static void
toe_gmac_enable_tx_rx(struct net_device *dev)
{
	GMAC_INFO_T		*tp = dev->priv;
	GMAC_CONFIG0_T	config0,config0_mask;

	/* enable TX/RX */
	config0.bits32 = 0;
	config0_mask.bits32 = 0;
	config0.bits.dis_rx = 0;	/* enable rx */
	config0.bits.dis_tx = 0;	/* enable tx */
	config0_mask.bits.dis_rx = 1;
	config0_mask.bits.dis_tx = 1;

	gmac_write_reg(tp->base_addr, GMAC_CONFIG0, config0.bits32, config0_mask.bits32);
}

/*----------------------------------------------------------------------
*	toe_gmac_disable_rx
*----------------------------------------------------------------------*/
#if 0
static void toe_gmac_disable_rx(struct net_device *dev)
{
	GMAC_INFO_T		*tp = dev->priv;
	GMAC_CONFIG0_T	config0,config0_mask;

	/* enable TX/RX */
	config0.bits32 = 0;
	config0_mask.bits32 = 0;
	config0.bits.dis_rx = 1;	/* disable rx */
//	config0.bits.dis_tx = 1;	/* disable tx */
	config0_mask.bits.dis_rx = 1;
 //	config0_mask.bits.dis_tx = 1;
	gmac_write_reg(GMAC0_BASE, GMAC_CONFIG0, config0.bits32, config0_mask.bits32);
	gmac_write_reg(GMAC1_BASE, GMAC_CONFIG0, config0.bits32, config0_mask.bits32);
}
#endif

/*----------------------------------------------------------------------
*	toe_gmac_enable_rx
*----------------------------------------------------------------------*/
#if 0
static void toe_gmac_enable_rx(struct net_device *dev)
{
	GMAC_INFO_T		*tp = dev->priv;
	GMAC_CONFIG0_T	config0,config0_mask;

	/* enable TX/RX */
	config0.bits32 = 0;
	config0_mask.bits32 = 0;
	config0.bits.dis_rx = 0;	/* enable rx */
//	config0.bits.dis_tx = 0;	/* enable tx */
	config0_mask.bits.dis_rx = 1;
//	config0_mask.bits.dis_tx = 1;
	gmac_write_reg(GMAC0_BASE, GMAC_CONFIG0, config0.bits32, config0_mask.bits32);
	gmac_write_reg(GMAC1_BASE, GMAC_CONFIG0, config0.bits32, config0_mask.bits32);
}
#endif

/*----------------------------------------------------------------------
*	toe_gmac_disable_tx_rx
*----------------------------------------------------------------------*/
static void
toe_gmac_disable_tx_rx(struct net_device *dev)
{
	GMAC_INFO_T		*tp = dev->priv;
	GMAC_CONFIG0_T	config0,config0_mask;

	/* enable TX/RX */
	config0.bits32 = 0;
	config0_mask.bits32 = 0;
	config0.bits.dis_rx = 1;	/* disable rx */
	config0.bits.dis_tx = 1;	/* disable tx */
	config0_mask.bits.dis_rx = 1;
	config0_mask.bits.dis_tx = 1;

	gmac_write_reg(tp->base_addr, GMAC_CONFIG0, config0.bits32, config0_mask.bits32);
}

/*----------------------------------------------------------------------
*	toe_gmac_hw_start
*----------------------------------------------------------------------*/
static void toe_gmac_hw_start(struct net_device *dev)
{
	GMAC_INFO_T				*tp = (GMAC_INFO_T *)dev->priv;
	GMAC_DMA_CTRL_T			dma_ctrl, dma_ctrl_mask;

	/* program dma control register */
	dma_ctrl.bits32 = 0;
	dma_ctrl.bits.rd_enable = 1;
	dma_ctrl.bits.td_enable = 1;
	dma_ctrl.bits.loopback = 0;
	dma_ctrl.bits.drop_small_ack = 0;
	dma_ctrl.bits.rd_prot = 0;
	dma_ctrl.bits.rd_burst_size = 3;
	dma_ctrl.bits.rd_insert_bytes = RX_INSERT_BYTES;
	dma_ctrl.bits.rd_bus = 3;
	dma_ctrl.bits.td_prot = 0;
	dma_ctrl.bits.td_burst_size = 3;
	dma_ctrl.bits.td_bus = 3;

	dma_ctrl_mask.bits32 = 0;
	dma_ctrl_mask.bits.rd_enable = 1;
	dma_ctrl_mask.bits.td_enable = 1;
	dma_ctrl_mask.bits.loopback = 1;
	dma_ctrl_mask.bits.drop_small_ack = 1;
	dma_ctrl_mask.bits.rd_prot = 3;
	dma_ctrl_mask.bits.rd_burst_size = 3;
	dma_ctrl_mask.bits.rd_insert_bytes = 3;
	dma_ctrl_mask.bits.rd_bus = 3;
	dma_ctrl_mask.bits.td_prot = 0x0f;
	dma_ctrl_mask.bits.td_burst_size = 3;
	dma_ctrl_mask.bits.td_bus = 3;

	gmac_write_reg(tp->dma_base_addr, GMAC_DMA_CTRL_REG,
			dma_ctrl.bits32, dma_ctrl_mask.bits32);

	return;
}

/*----------------------------------------------------------------------
*	toe_gmac_hw_stop
*----------------------------------------------------------------------*/
static void toe_gmac_hw_stop(struct net_device *dev)
{
	GMAC_INFO_T			*tp = (GMAC_INFO_T *)dev->priv;
	GMAC_DMA_CTRL_T		dma_ctrl, dma_ctrl_mask;

	/* program dma control register */
	dma_ctrl.bits32 = 0;
	dma_ctrl.bits.rd_enable = 0;
	dma_ctrl.bits.td_enable = 0;

	dma_ctrl_mask.bits32 = 0;
	dma_ctrl_mask.bits.rd_enable = 1;
	dma_ctrl_mask.bits.td_enable = 1;

	gmac_write_reg(tp->dma_base_addr, GMAC_DMA_CTRL_REG,
			dma_ctrl.bits32, dma_ctrl_mask.bits32);
}

/*----------------------------------------------------------------------
*	toe_gmac_clear_counter
*----------------------------------------------------------------------*/
static int toe_gmac_clear_counter (struct net_device *dev)
{
	GMAC_INFO_T	*tp = (GMAC_INFO_T *)dev->priv;

	/* clear counter */
	gmac_read_reg(tp->base_addr, GMAC_IN_DISCARDS);
	gmac_read_reg(tp->base_addr, GMAC_IN_ERRORS);
	gmac_read_reg(tp->base_addr, GMAC_IN_MCAST);
	gmac_read_reg(tp->base_addr, GMAC_IN_BCAST);
	gmac_read_reg(tp->base_addr, GMAC_IN_MAC1);
	gmac_read_reg(tp->base_addr, GMAC_IN_MAC2);
	tp->ifStatics.tx_bytes = 0;
	tp->ifStatics.tx_packets = 0;
	tp->ifStatics.tx_errors = 0;
	tp->ifStatics.rx_bytes = 0;
	tp->ifStatics.rx_packets = 0;
	tp->ifStatics.rx_errors = 0;
	tp->ifStatics.rx_dropped = 0;

	return (0);
}

/*----------------------------------------------------------------------
*	toe_gmac_tx_complete
*----------------------------------------------------------------------*/
static inline void toe_gmac_tx_complete(GMAC_INFO_T *tp, uint32_t tx_qid,
   										struct net_device *dev, int interrupt)
{
	volatile GMAC_TXDESC_T	*curr_desc;
	GMAC_TXDESC_0_T			word0;
	GMAC_TXDESC_1_T			word1;
	uint32_t			desc_count;
//	struct net_device_stats *isPtr = (struct net_device_stats *)&tp->ifStatics;
	GMAC_SWTXQ_T			*swtxq;
	DMA_RWPTR_T				rwptr;

	/* get tx H/W completed descriptor virtual address */
	/* check tx status and accumulate tx statistics */
	swtxq = &tp->swtxq[tx_qid];
#ifdef GMAC_DEBUG
	swtxq->intr_cnt++;
#endif
	for (;;) {
		rwptr.bits32 = readl(swtxq->rwptr_reg);
		if (rwptr.bits.rptr == swtxq->finished_idx)
			break;
		curr_desc = (volatile GMAC_TXDESC_T *)swtxq->desc_base + swtxq->finished_idx;
//		consistent_sync((void *)curr_desc, sizeof(GMAC_TXDESC_T), PCI_DMA_FROMDEVICE);
		word0.bits32 = curr_desc->word0.bits32;
		word1.bits32 = curr_desc->word1.bits32;

		if (word0.bits.status_tx_ok) {
			tp->ifStatics.tx_bytes += word1.bits.byte_count;
			desc_count = word0.bits.desc_count;
#ifdef GMAC_DEBUG
			if (desc_count==0) {
				printk("%s::Desc 0x%x = 0x%x, desc_count=%d\n",
						__func__, (u32)curr_desc, word0.bits32, desc_count);
				while(1);
			}
#endif
			while (--desc_count) {
				word0.bits.status_tx_ok = 0;
				curr_desc->word0.bits32 = word0.bits32;
				swtxq->finished_idx = RWPTR_ADVANCE_ONE(swtxq->finished_idx, swtxq->total_desc_num);
				curr_desc = (GMAC_TXDESC_T *)swtxq->desc_base + swtxq->finished_idx;
				word0.bits32 = curr_desc->word0.bits32;
#ifdef _DUMP_TX_TCP_CONTENT
				if (curr_desc->word0.bits.buffer_size < 16) {
					int a;
					char *datap;
					printk("\t Tx Finished Desc 0x%x Len %d Addr 0x%08x: ", (u32)curr_desc, curr_desc->word0.bits.buffer_size, curr_desc->word2.buf_adr);
					datap = (char *)__va(curr_desc->word2.buf_adr);
					for (a=0; a<8 && a<curr_desc->word0.bits.buffer_size; a++, datap++) {
						printk("0x%02x ", *datap);
					}
					printk("\n");
				}
#endif
			}

			word0.bits.status_tx_ok = 0;
			if (swtxq->tx_skb[swtxq->finished_idx]) {
//				if (interrupt)		/* Modify by Wen for VPN */
				if (swtxq->tx_skb[swtxq->finished_idx]->destructor)
					dev_kfree_skb_any(swtxq->tx_skb[swtxq->finished_idx]);
				else
					dev_kfree_skb(swtxq->tx_skb[swtxq->finished_idx]);
				swtxq->tx_skb[swtxq->finished_idx] = NULL;
			}
			curr_desc->word0.bits32 = word0.bits32;
			swtxq->curr_finished_desc = (GMAC_TXDESC_T *)curr_desc;
#ifdef GMAC_DEBUG
			swtxq->total_finished++;
#endif
			tp->ifStatics.tx_packets++;
			swtxq->finished_idx = RWPTR_ADVANCE_ONE(swtxq->finished_idx, swtxq->total_desc_num);
		} else {
			//tp->ifStatics.tx_errors++;
			//printk("%s::Tx Descriptor is !!!\n",__func__);
			/* wait ready by breaking */
			break;
		}
	}

	if (netif_queue_stopped(dev)) {
		netif_wake_queue(dev);
	}
}

/*----------------------------------------------------------------------
*	gmac_adjust_hdr_location
*----------------------------------------------------------------------*/
static inline void gmac_adjust_hdr_location(struct sk_buff *skb, 
		struct net_device *dev, int *vlan_mtu)
{
	int network_offset = 0;
	int transport_offset = 0;
	struct ethhdr *eth_hdr;
	unsigned short eth_proto;

	eth_hdr = (struct ethhdr *)skb->data;
	eth_proto = eth_hdr->h_proto;
	if (eth_proto == __constant_htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *vlan_eth_hdr;
		int vlan_exist = *vlan_mtu;
		vlan_exist = 1;
		vlan_eth_hdr = (struct vlan_ethhdr *)skb->data;
		network_offset += VLAN_ETH_HLEN;
		eth_proto = vlan_eth_hdr->h_vlan_encapsulated_proto;
	} else network_offset += dev->hard_header_len;

	if (eth_proto == __constant_htons(ETH_P_PPP_SES)) {
		struct pppoe_hdr *pppoe_hdr;
		pppoe_hdr = (struct pppoe_hdr *)(skb->data + network_offset);
		network_offset += sizeof(struct pppoe_hdr) + 2;
		eth_proto == *(u16 *)&pppoe_hdr->tag[0];
	}

	if (eth_proto == __constant_htons(ETH_P_IP)) {
		struct iphdr *ip_hdr;
		ip_hdr = (struct iphdr *)(skb->data + network_offset);
		transport_offset = network_offset + (ip_hdr->ihl<<2);
	}

	if (network_offset != 0)
		skb->nh.raw = skb->data + network_offset;
	if (transport_offset != 0)
		skb->h.raw = skb->data + transport_offset;
}

/*----------------------------------------------------------------------
*	gmac_start_xmit
*----------------------------------------------------------------------*/
static int gmac_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	GMAC_INFO_T *tp= dev->priv;
#ifndef GMAC_USE_TXQ0
	unsigned int tx_qid;
#endif
#if defined(CONFIG_SL351x_NAT) || defined(CONFIG_SL351X_BR)
	NAT_CB_T *nat_cb;
#endif
	DMA_RWPTR_T rwptr;
	volatile GMAC_TXDESC_T *curr_desc;
	int snd_pages = skb_shinfo(skb)->nr_frags + 1;  /* get number of descriptor */
	int frag_id = 0, len, total_len = skb->len;
	struct net_device_stats *isPtr = (struct net_device_stats *)&tp->ifStatics;
	uint32_t free_desc;
	GMAC_SWTXQ_T *swtxq;
	register unsigned long word0, word1, word2, word3;
	unsigned short wptr, rptr;
	struct net_bridge_fdb_entry *br_fdb;
	struct net_bridge_port *br_port;
	struct iphdr *ip_hdr;
	int mpage = snd_pages;
	int vlan_mtu = 0;
#ifdef GMAC_LEN_1_2_ISSUE
	int total_pages;
	total_pages = snd_pages;
#endif

	if (skb == NULL) {
		printk("%s:: skb == NULL\n",__func__);
		return 0;
	}

	/* 
	 * have to adjust skb->nh.raw and skb->h.raw to correct locations 
	 * in some of the cases, since they might be modified to point to
	 * different locations in some of the processes, such as pppoe driver
	 */
	gmac_adjust_hdr_location(skb, dev, &vlan_mtu);
	ip_hdr = skb->nh.iph;
	isPtr = (struct net_device_stats *)&tp->ifStatics;

	/* testing if packet size is over the max TX allows */
	if (skb->len >= 0x10000) {
//		spin_unlock(&tp->tx_mutex);
		isPtr->tx_dropped++;
		printk("%s::[GMAC %d] skb->len %d >= 64K\n", __func__, tp->port_id, skb->len);
		netif_stop_queue(dev);
		return 1;
    }

#ifdef GMAC_USE_TXQ0
	#define tx_qid 	0
#else
	tx_qid = 0;
	
#if defined(CONFIG_SL351x_NAT) || defined(CONFIG_SL351X_BR)
	if (Tantos_switch == 1) {
		tx_qid = 2;
		nat_cb = NAT_SKB_CB(skb);

		if (nat_cb->tag == NAT_CB_TAG) {
			tx_qid = 1;
		}

		if (skb->input_dev) {
			if (strcmp(skb->input_dev->name, "ra1") == 0) {
				tx_qid = 0;
			} else if (strcmp(skb->input_dev->name, "ra0") == 0) {
				tx_qid = 2;
			}
		}
	}
#endif	//defined(CONFIG_SL351x_NAT) || defined(CONFIG_SL351X_BR)
	//	printk("%s::[GMAC %d] tx_qid=%d\n", __func__, tp->port_id, tx_qid);
#endif	//GMAC_USE_TXQ0

	swtxq = &tp->swtxq[tx_qid];

//	spin_lock(&tp->tx_mutex);	
	rwptr.bits32 = readl(swtxq->rwptr_reg);
	wptr = rwptr.bits.wptr;
	rptr = rwptr.bits.rptr;
	// check finished desc or empty BD 
	// cannot check by read ptr of RW PTR register, 
	// because the HW complete to send but the SW may NOT handle it
#ifndef	GMAX_TX_INTR_DISABLED
	if (wptr >= swtxq->finished_idx)
		free_desc = swtxq->total_desc_num - wptr - 1 + swtxq->finished_idx;
	else
		free_desc = swtxq->finished_idx - wptr - 1;

	if (free_desc < snd_pages) {
//		spin_unlock(&tp->tx_mutex);
		isPtr->tx_dropped++;
//		printk("GMAC %d No available descriptor!\n", tp->port_id);
		netif_stop_queue(dev);
		return 1;
    }
#else
	toe_gmac_tx_complete(tp, tx_qid, dev, 0);
	if (wptr >= swtxq->finished_idx)
		free_desc = swtxq->total_desc_num - wptr - 1 + swtxq->finished_idx;
	else 
		free_desc = swtxq->finished_idx - wptr - 1;
	if (free_desc < snd_pages) {
//		spin_unlock(&tp->tx_mutex);
		isPtr->tx_dropped++;
//		printk("GMAC %d No available descriptor!\n", tp->port_id);
		netif_stop_queue(dev);
		return 1;
    }

#if 0
	printk("1: free_desc=%d, wptr=%d, finished_idx=%d\n", free_desc, wptr, swtxq->finished_idx);
	if ((free_desc < (snd_pages << 2)) || 
	    (free_desc < (swtxq->total_desc_num >> 2)))
	{
		printk("2: free_desc = %d\n", free_desc);
		toe_gmac_tx_complete(tp, tx_qid, dev, 0);
		rwptr.bits32 = readl(swtxq->rwptr_reg);
		wptr = rwptr.bits.wptr;
		if (wptr>= swtxq->finished_idx)
			free_desc = swtxq->total_desc_num - wptr -1 + swtxq->finished_idx;
		else
			free_desc = swtxq->finished_idx - wptr - 1;
	}
#endif	
#endif


    while (snd_pages != 0) {
		char *pkt_datap;
		curr_desc = (GMAC_TXDESC_T *)swtxq->desc_base + wptr;
//		consistent_sync((void *)curr_desc, sizeof(GMAC_TXDESC_T), PCI_DMA_FROMDEVICE);
#if 0
//#if (GMAC_DEBUG==1)
    	// if curr_desc->word2.buf_adr !=0 means that the ISR does NOT handle it
    	// if (curr_desc->word2.buf_adr)
    	if (swtxq->tx_skb[wptr]) {
    		printk("Error! Stop due to TX descriptor's buffer is not freed!\n");
    		while(1);
    		dev_kfree_skb(swtxq->tx_skb[wptr]);
    		swtxq->tx_skb[wptr] = NULL;
		}
#endif

		if (frag_id == 0) {
#if 0
			int i;
			pkt_datap = skb->data;
			len = total_len;
			for (i=0; i<skb_shinfo(skb)->nr_frags; i++)
			{
				skb_frag_t* frag = &skb_shinfo(skb)->frags[i];
				len -= frag->size;
			}
#else
			pkt_datap = skb->data;
			len = total_len - skb->data_len;
#endif
		} else {
			skb_frag_t* frag = &skb_shinfo(skb)->frags[frag_id-1];
			pkt_datap = page_address(frag->page) + frag->page_offset;
			len = frag->size;
			if (len > total_len) {
				printk("Fatal Error! Send Frag size %d > Total Size %d!!\n", 
						len, total_len);
			}
		}

		/* set TX descriptor */
		/* copy packet to descriptor buffer address */
		// curr_desc->word0.bits32 = len;    /* total frame byte count */
		word0 = len;
#ifdef CONFIG_SL2312_MPAGE
		/* if this skb is with fast_sock on; i.e, FTP data, 
		   use path MTU instead, jeanson */
		if (skb->sk) {
			/* if the destination is known; normally yes */
			if (skb->dst) {
				if (vlan_mtu == 1) word3 = (dst_mtu(skb->dst)+18) | EOFIE_BIT;
				else word3 = (dst_mtu(skb->dst)+14) | EOFIE_BIT;
			} else {
				if (vlan_mtu == 1) word3 = (dev->mtu+18) | EOFIE_BIT;
				else word3 = (dev->mtu+14) | EOFIE_BIT;
			}
		} else {
			if (vlan_mtu == 1) word3 = (dev->mtu+18) | EOFIE_BIT;
			else word3 = (dev->mtu+14) | EOFIE_BIT;
		}
#else
		if (vlan_mtu == 1) word3 = (dev->mtu+18) | EOFIE_BIT;
		else word3 = (dev->mtu+14) | EOFIE_BIT;
#endif	/* CONFIG_SL2312_MPAGE */

#ifdef DO_HW_CHKSUM
#ifdef CONFIG_CS351X_DUAL_WAN
		if (tp->port_id == GMAC_PORT1 && total_len <= 1518 && ip_hdr && (ip_hdr->frag_off & __constant_htons(0x3fff)))
#else
		if (total_len <= 1514 && ip_hdr && (ip_hdr->frag_off & __constant_htons(0x3fff)))			
#endif  //CONFIG_CS351X_DUAL_WAN			
			word1 = total_len |
					TSS_TCP_CHKSUM_BIT |
					TSS_IP_CHKSUM_BIT  |
					TSS_IPV6_ENABLE_BIT |
					TSS_MTU_ENABLE_BIT  |
					TSS_IP_FIXED_LEN_BIT;
		else {
			if (total_len <= 60) {
				if (memcmp(&skb->data[6],&dev->dev_addr[0],ETH_ALEN)!=0) {
					if (((br_port=rcu_dereference(skb->dev->br_port)) != NULL) 
							&& likely((br_fdb = br_fdb_get(br_port->br, &skb->data[6])) != NULL) 
							&& likely(!(br_fdb->is_local)))
						word1 = total_len | TSS_MTU_ENABLE_BIT;
					else
						word1 = total_len | 
								TSS_UDP_CHKSUM_BIT |
								TSS_TCP_CHKSUM_BIT |
								TSS_IP_CHKSUM_BIT  |
								TSS_IPV6_ENABLE_BIT |
								TSS_MTU_ENABLE_BIT |
								TSS_IP_FIXED_LEN_BIT;
				} else
					word1 = total_len | 
							TSS_UDP_CHKSUM_BIT |
							TSS_TCP_CHKSUM_BIT |
							TSS_IP_CHKSUM_BIT | 
							TSS_IPV6_ENABLE_BIT |
							TSS_MTU_ENABLE_BIT |
							TSS_IP_FIXED_LEN_BIT;
			} else {
				word1 = total_len | 
						TSS_UDP_CHKSUM_BIT |
						TSS_TCP_CHKSUM_BIT |
						TSS_IP_CHKSUM_BIT  |
						TSS_IPV6_ENABLE_BIT |
						TSS_MTU_ENABLE_BIT |
						TSS_IP_FIXED_LEN_BIT;
						/* IP_FIX_LEN can't enable or TSO generates wrong TCP checksum */
				if (mpage > 1 ) word1 &= ~TSS_IP_FIXED_LEN_BIT ;
			}
		}
#else	//DO_HW_CHKSUM
		word1 = total_len | TSS_MTU_ENABLE_BIT;
#endif	//DO_HW_CHKSUM

		word2 = (unsigned long)__pa(pkt_datap);
	
		if (frag_id == 0) word3 |= SOF_BIT;	// SOF
			
		if (snd_pages == 1) {
			word3 |= EOF_BIT;	// EOF
			swtxq->tx_skb[wptr] = skb;
#ifdef CONFIG_SL351x_NAT
			if (nat_cfg.enabled && sl351x_nat_output(skb, tp->port_id))
				word1 |= TSS_IP_FIXED_LEN_BIT;
#endif
#ifdef CONFIG_SL351X_BR
				word1 |= TSS_IP_FIXED_LEN_BIT;
#endif
		} else
			swtxq->tx_skb[wptr] = NULL;
#if 1
#endif


#ifdef _DUMP_TX_TCP_CONTENT
		if (len < 16 && frag_id && skb->h.th
				&& (skb->h.th->source == __constant_htons(445)
					|| skb->h.th->source == __constant_htons(139))) {
			int a;
			char *datap;
			printk("Tx Desc 0x%x Frag %d Len %d [IP-ID 0x%x] 0x%08x: ", (u32)curr_desc, frag_id, len, htons(skb->nh.iph->id), (u32)pkt_datap);
			datap = (char *)pkt_datap;

			for (a=0; a<8 && a<len; a++, datap++)
				printk("0x%02x ", *datap);
			printk("\n");
		}
#endif

#ifdef GMAC_LEN_1_2_ISSUE
		if ((total_pages!=snd_pages) && (len == 1 || len == 2 )
				&& ((u32)pkt_datap & 0x03)) {
			memcpy((void *)&_debug_prefetch_buf[_debug_prefetch_cnt][0],
					pkt_datap, len);
			pkt_datap = (char *)&_debug_prefetch_buf[_debug_prefetch_cnt][0];
			word2 = (unsigned long)__pa(pkt_datap);
			_debug_prefetch_cnt++;
			if (_debug_prefetch_cnt >= _DEBUG_PREFETCH_NUM)
				_debug_prefetch_cnt = 0;
		}
#endif

		consistent_sync((void *)pkt_datap, len, PCI_DMA_TODEVICE);
		wmb();
		curr_desc->word0.bits32 = word0;
		curr_desc->word1.bits32 = word1;
		curr_desc->word2.bits32 = word2;
		curr_desc->word3.bits32 = word3;
		swtxq->curr_tx_desc = (GMAC_TXDESC_T *)curr_desc;
		consistent_sync((void *)curr_desc, sizeof(GMAC_TXDESC_T),
				PCI_DMA_TODEVICE);
#ifdef _DUMP_TX_TCP_CONTENT
		if (len < 16 && frag_id && skb->h.th
				&& (skb->h.th->source == __constant_htons(445)
					|| skb->h.th->source == __constant_htons(139))) {
			int a;
			char *datap;
			printk("\t 0x%08x: ", (u32)pkt_datap);
			datap = (char *)pkt_datap;

			for (a=0; a<8 && a<len; a++, datap++)
				printk("0x%02x ", *datap);
			printk("\n");
		}
#endif
		free_desc--;
		wmb();
		rwptr.bits32 = readl(swtxq->rwptr_reg);
		wptr = RWPTR_ADVANCE_ONE(wptr, swtxq->total_desc_num);
		frag_id++;
		snd_pages--;
	}	

#ifdef GMAC_DEBUG
	swtxq->total_sent++;
#endif
	rwptr.bits32 = readl(swtxq->rwptr_reg);
	SET_WPTR(swtxq->rwptr_reg, wptr);
	dev->trans_start = jiffies;

//#ifdef	GMAX_TX_INTR_DISABLED
//		toe_gmac_tx_complete(tp, tx_qid, dev, 0);
//#endif
	return (0);
}

/*----------------------------------------------------------------------
* gmac_set_mac_address
*----------------------------------------------------------------------*/
static int gmac_set_mac_address(struct net_device *dev, void *addr)
{
	GMAC_INFO_T		*tp= dev->priv;
	struct sockaddr *sock;
	uint32_t		reg_val;
    uint32_t		i;

	sock = (struct sockaddr *) addr;
	
	for (i = 0; i < 6; i++)
		dev->dev_addr[i] = sock->sa_data[i];

	reg_val = dev->dev_addr[0] + (dev->dev_addr[1]<<8) 
			+ (dev->dev_addr[2]<<16) + (dev->dev_addr[3]<<24);
	gmac_write_reg(tp->base_addr, GMAC_STA_ADD0, reg_val, 0xffffffff);
	reg_val = dev->dev_addr[4] + (dev->dev_addr[5]<<8);
	gmac_write_reg(tp->base_addr, GMAC_STA_ADD1, reg_val, 0x0000ffff);
	memcpy(&eth_mac[tp->port_id][0], &dev->dev_addr[0], 6);	

	printk("Storlink %s address = ", dev->name);
	printk("%02X", dev->dev_addr[0]); 
	printk("%02X", dev->dev_addr[1]);
	printk("%02X", dev->dev_addr[2]);
	printk("%02X", dev->dev_addr[3]);
	printk("%02X", dev->dev_addr[4]);
	printk("%02X\n", dev->dev_addr[5]);

    return (0);
}

/*----------------------------------------------------------------------
* gmac_get_mac_address
*	get mac address from FLASH
*----------------------------------------------------------------------*/
static void gmac_get_mac_address(void)
{
#ifdef CONFIG_MTD	
	extern int get_vlaninfo(vlaninfo* vlan);
	static vlaninfo    vlan[2];    

#ifdef CONFIG_BONDING_MODULE
	if (get_vlaninfo(&vlan[0])) {
		if ((memcmp(&eth_mac[0][0], &eth_mac_init[0][0], 6) == 0) ||
			   (memcmp(&eth_mac[0][0], &eth_mac_zero[0], 6) == 0)) {
			memcpy((void *)&eth_mac[0][0], vlan[0].mac, 6);
		}
		if ((memcmp(&eth_mac[1][0], &eth_mac_init[1][0], 6) == 0) ||
				(memcmp(&eth_mac[1][0], &eth_mac_zero[0], 6) == 0)) {
			memcpy((void *)&eth_mac[1][0], vlan[1].mac, 6);
		}
	}//end if (get_vlaninfo(&vlan[0]));

	return;
#endif//CONFIG_BONDING_MODULE

	if (get_vlaninfo(&vlan[0])) {
		memcpy((void *)&eth_mac[0][0], vlan[0].mac, 6);
		memcpy((void *)&eth_mac[1][0], vlan[1].mac, 6);
	}
#else
	uint32_t reg_val;

	reg_val = readl(IO_ADDRESS(SL2312_SECURITY_BASE)+0xac);
	eth_mac[0][4] = (reg_val & 0xff00) >> 8;
	eth_mac[0][5] = reg_val & 0x00ff;
	reg_val = readl(IO_ADDRESS(SL2312_SECURITY_BASE)+0xac);
	eth_mac[1][4] = (reg_val & 0xff00) >> 8;
	eth_mac[1][5] = reg_val & 0x00ff;        
#endif

	return;
}

/*----------------------------------------------------------------------
* mac_stop_txdma
*----------------------------------------------------------------------*/
void mac_stop_txdma(struct net_device *dev)
{
	GMAC_INFO_T				*tp = (GMAC_INFO_T *)dev->priv;
	GMAC_DMA_CTRL_T			dma_ctrl, dma_ctrl_mask;
	GMAC_TXDMA_FIRST_DESC_T	txdma_busy;

	/* wait idle */
	do {
		txdma_busy.bits32 = gmac_read_reg(tp->dma_base_addr,
			GMAC_DMA_TX_FIRST_DESC_REG);
	} while (txdma_busy.bits.td_busy);

	/* program dma control register */
	dma_ctrl.bits32 = 0;
	dma_ctrl.bits.rd_enable = 0;
	dma_ctrl.bits.td_enable = 0;

	dma_ctrl_mask.bits32 = 0;
	dma_ctrl_mask.bits.rd_enable = 1;
	dma_ctrl_mask.bits.td_enable = 1;

	gmac_write_reg(tp->dma_base_addr, GMAC_DMA_CTRL_REG, dma_ctrl.bits32,
			dma_ctrl_mask.bits32);
}

/*----------------------------------------------------------------------
* mac_start_txdma
*----------------------------------------------------------------------*/
void mac_start_txdma(struct net_device *dev)
{
	GMAC_INFO_T			*tp = (GMAC_INFO_T *)dev->priv;
	GMAC_DMA_CTRL_T		dma_ctrl, dma_ctrl_mask;

	/* program dma control register */
	dma_ctrl.bits32 = 0;
	dma_ctrl.bits.rd_enable = 1;
	dma_ctrl.bits.td_enable = 1;

	dma_ctrl_mask.bits32 = 0;
	dma_ctrl_mask.bits.rd_enable = 1;
	dma_ctrl_mask.bits.td_enable = 1;

	gmac_write_reg(tp->dma_base_addr, GMAC_DMA_CTRL_REG, dma_ctrl.bits32,
			dma_ctrl_mask.bits32);
}

/*----------------------------------------------------------------------
* gmac_get_stats
*----------------------------------------------------------------------*/
struct net_device_stats * gmac_get_stats(struct net_device *dev)
{
	GMAC_INFO_T *tp = (GMAC_INFO_T *)dev->priv;
	// uint32_t        flags;
	uint32_t        pkt_drop, pkt_error;

    if (netif_running(dev)) {
		/* read H/W counter */
		// spin_lock_irqsave(&tp->lock,flags);
		pkt_drop = gmac_read_reg(tp->base_addr,GMAC_IN_DISCARDS);
		pkt_error = gmac_read_reg(tp->base_addr,GMAC_IN_ERRORS);
		tp->ifStatics.rx_dropped = tp->ifStatics.rx_dropped + pkt_drop;
		tp->ifStatics.rx_errors = tp->ifStatics.rx_errors + pkt_error;
		//spin_unlock_irqrestore(&tp->lock,flags);
	}
	return &tp->ifStatics;
}

/*----------------------------------------------------------------------
* mac_get_sw_tx_weight
*----------------------------------------------------------------------*/
void mac_get_sw_tx_weight(struct net_device *dev, char *weight)
{
	GMAC_TX_WCR1_T	sw_weigh;
	GMAC_INFO_T		*tp = (GMAC_INFO_T *)dev->priv;

	sw_weigh.bits32 = gmac_read_reg(tp->dma_base_addr,
					GMAC_TX_WEIGHTING_CTRL_1_REG);

	weight[0] = sw_weigh.bits.sw_tq0;
	weight[1] = sw_weigh.bits.sw_tq1;
	weight[2] = sw_weigh.bits.sw_tq2;
	weight[3] = sw_weigh.bits.sw_tq3;
	weight[4] = sw_weigh.bits.sw_tq4;
	weight[5] = sw_weigh.bits.sw_tq5;
}

/*----------------------------------------------------------------------
* mac_set_sw_tx_weight
*----------------------------------------------------------------------*/
void mac_set_sw_tx_weight(struct net_device *dev, char *weight)
{
	GMAC_TX_WCR1_T	sw_weigh;
	GMAC_INFO_T		*tp = (GMAC_INFO_T *)dev->priv;

	sw_weigh.bits32 = 0;
	sw_weigh.bits.sw_tq0 = weight[0];
	sw_weigh.bits.sw_tq1 = weight[1];
	sw_weigh.bits.sw_tq2 = weight[2];
	sw_weigh.bits.sw_tq3 = weight[3];
	sw_weigh.bits.sw_tq4 = weight[4];
	sw_weigh.bits.sw_tq5 = weight[5];

	gmac_write_reg(tp->dma_base_addr, GMAC_TX_WEIGHTING_CTRL_1_REG,
			sw_weigh.bits32, 0xffffffff);
}

/*----------------------------------------------------------------------
* mac_get_hw_tx_weight
*----------------------------------------------------------------------*/
void mac_get_hw_tx_weight(struct net_device *dev, char *weight)
{
	GMAC_TX_WCR0_T	hw_weigh;
	GMAC_INFO_T		*tp = (GMAC_INFO_T *)dev->priv;

	hw_weigh.bits32 = gmac_read_reg(tp->dma_base_addr,
					GMAC_TX_WEIGHTING_CTRL_0_REG);

	weight[0] = hw_weigh.bits.hw_tq0;
	weight[1] = hw_weigh.bits.hw_tq1;
	weight[2] = hw_weigh.bits.hw_tq2;
	weight[3] = hw_weigh.bits.hw_tq3;
}

/*----------------------------------------------------------------------
* mac_set_hw_tx_weight
*----------------------------------------------------------------------*/
void mac_set_hw_tx_weight(struct net_device *dev, char *weight)
{
	GMAC_TX_WCR0_T	hw_weigh;
	GMAC_INFO_T		*tp = (GMAC_INFO_T *)dev->priv;

	hw_weigh.bits32 = 0;
	hw_weigh.bits.hw_tq0 = weight[0];
	hw_weigh.bits.hw_tq1 = weight[1];
	hw_weigh.bits.hw_tq2 = weight[2];
	hw_weigh.bits.hw_tq3 = weight[3];

	gmac_write_reg(tp->dma_base_addr, GMAC_TX_WEIGHTING_CTRL_0_REG,
			hw_weigh.bits32, 0xffffffff);
}

/*----------------------------------------------------------------------
* mac_start_tx_dma
*----------------------------------------------------------------------*/
int mac_start_tx_dma(int mac)
{
	GMAC_DMA_CTRL_T dma_ctrl, dma_ctrl_mask;

	dma_ctrl.bits32 = 0;
	dma_ctrl.bits.td_enable = 1;    

	dma_ctrl_mask.bits32 = 0;
	dma_ctrl_mask.bits.td_enable = 1;

	if (mac == 0)
		gmac_write_reg(TOE_GMAC0_DMA_BASE, GMAC_DMA_CTRL_REG, dma_ctrl.bits32,
				dma_ctrl_mask.bits32);
	else
		gmac_write_reg(TOE_GMAC1_DMA_BASE, GMAC_DMA_CTRL_REG, dma_ctrl.bits32,
				dma_ctrl_mask.bits32);
	return 1;
}

/*----------------------------------------------------------------------
* mac_stop_tx_dma
*----------------------------------------------------------------------*/
int mac_stop_tx_dma(int mac)
{
	GMAC_DMA_CTRL_T dma_ctrl, dma_ctrl_mask;

	dma_ctrl.bits32 = 0;
	dma_ctrl.bits.td_enable = 0;

	dma_ctrl_mask.bits32 = 0;
	dma_ctrl_mask.bits.td_enable = 1;

	if (mac == 0)
		gmac_write_reg(TOE_GMAC0_DMA_BASE, GMAC_DMA_CTRL_REG, dma_ctrl.bits32,
				dma_ctrl_mask.bits32);
	else
		gmac_write_reg(TOE_GMAC1_DMA_BASE, GMAC_DMA_CTRL_REG, dma_ctrl.bits32,
				dma_ctrl_mask.bits32);
	return 1;
}

/*----------------------------------------------------------------------
* mac_read_reg(int mac, uint32_t offset)
*----------------------------------------------------------------------*/
uint32_t mac_read_reg(int mac, uint32_t offset)
{
	switch (mac)
	{
		case 0:
			return gmac_read_reg(TOE_GMAC0_BASE, offset);
		case 1:
			return gmac_read_reg(TOE_GMAC1_BASE, offset);
		default:
			return 0;
	}
}

/*----------------------------------------------------------------------
* mac_write_reg
*----------------------------------------------------------------------*/
void mac_write_reg(int mac, uint32_t offset, unsigned data)
{
	switch (mac)
	{
		case 0:
			gmac_write_reg(GMAC0_BASE, offset, data, 0xffffffff);
			break;
		case 1:
			gmac_write_reg(GMAC1_BASE, offset, data, 0xffffffff);
			break;
	}
}

/*----------------------------------------------------------------------
* mac_read_dma_reg(int mac, uint32_t offset)
*----------------------------------------------------------------------*/
u32 mac_read_dma_reg(int mac, uint32_t offset)
{
	switch (mac)
	{
		case 0:
			return gmac_read_reg(TOE_GMAC0_DMA_BASE, offset);
		case 1:
			return gmac_read_reg(TOE_GMAC1_DMA_BASE, offset);
		default:
			return 0;
	}
}

/*----------------------------------------------------------------------
* mac_write_dma_reg
*----------------------------------------------------------------------*/
void mac_write_dma_reg(int mac, uint32_t offset, u32 data)
{
	switch (mac)
	{
		case 0:
			gmac_write_reg(TOE_GMAC0_DMA_BASE, offset, data, 0xffffffff);
			break;
		case 1:
			gmac_write_reg(TOE_GMAC1_DMA_BASE, offset, data, 0xffffffff);
			break;
	}
}

/*----------------------------------------------------------------------
* ether_crc
*----------------------------------------------------------------------*/
static unsigned const ethernet_polynomial = 0x04c11db7U;
static uint32_t ether_crc (int length, unsigned char *data)
{
	int crc = -1;
	uint32_t i;
	uint32_t crc_val=0;

	while (--length >= 0) {
		unsigned char current_octet = *data++;
		int bit;
		for (bit = 0; bit < 8; bit++, current_octet >>= 1)
			crc = (crc << 1) ^ ((crc < 0) ^ (current_octet & 1) ?
					ethernet_polynomial : 0);
	}
	crc = ~crc;
	for (i=0; i<32; i++) {
		crc_val = crc_val + (((crc << i) & 0x80000000) >> (31-i));
	}
	return crc_val;
}

/*----------------------------------------------------------------------
* mac_set_rx_mode
*----------------------------------------------------------------------*/
void mac_set_rx_mode(int pid, uint32_t data)
{
	uint32_t	base;

	base = (pid == 0) ? GMAC0_BASE : GMAC1_BASE;

	gmac_write_reg(base, GMAC_RX_FLTR, data, 0x0000001f);
	return;
}

/*----------------------------------------------------------------------
* gmac_open
*----------------------------------------------------------------------*/
static int gmac_open(struct net_device *dev)
{
	GMAC_INFO_T  *tp = (GMAC_INFO_T *)dev->priv;
	int    					retval;
	TOE_INFO_T				*toe;

	static int _gmac_opened = 0;		// dhsul

	if (_gmac_opened == 0)
	{
		sl351x_gmac_save_reg();
		_gmac_opened++;
	}
	else
		gmac_reset_task(dev);

	toe = (TOE_INFO_T *)&toe_private_data;

	/* hook ISR */
	retval = request_irq (dev->irq, toe_gmac_interrupt, SA_INTERRUPT,
					dev->name, dev);
	if (retval != 0)
		return retval;

	netif_start_queue(dev);
	toe_init_gmac(dev);

#ifdef CONFIG_SL351x_NAT
	sl351x_nat_add_dev(dev);
#endif

	if (FLAG_SWITCH == 0) {
//		init_waitqueue_head (&tp->thr_wait);
//		init_completion(&tp->thr_exited);

		tp->time_to_die = 0;
		tp->thr_pid = kernel_thread (gmac_phy_thread, dev, CLONE_FS | CLONE_FILES);
		if (tp->thr_pid < 0) {
			printk (KERN_WARNING "%s: unable to start kernel thread\n",dev->name);
		}
		msleep(200);
	}

	tp->operation = 1;
//	netif_start_queue (dev);

	return (0);
}

/*----------------------------------------------------------------------
* gmac_close
*----------------------------------------------------------------------*/
static int gmac_close(struct net_device *dev)
{
	TOE_INFO_T			*toe;
	GMAC_INFO_T 		*tp = dev->priv;
	uint32_t			ret;

	toe = (TOE_INFO_T *)&toe_private_data;

#ifdef CONFIG_SL351x_NAT
	sl351x_nat_del_dev(dev);
#endif
	tp->operation = 0;

	netif_stop_queue(dev);
	mdelay(20);

	/* stop tx/rx packet */
	toe_gmac_disable_tx_rx(dev);
	mdelay(20);

	/* stop the chip's Tx and Rx DMA processes */
	toe_gmac_hw_stop(dev);

	/* disable interrupts by clearing the interrupt mask */
	toe_gmac_disable_interrupt(tp->irq);
	synchronize_irq();
	free_irq(dev->irq,dev);

	if (!FLAG_SWITCH) {
		if (tp->thr_pid >= 0) {
			tp->time_to_die = 1;
			wmb();
			ret = kill_proc (tp->thr_pid, SIGTERM, 1);
			if (ret) {
				printk (KERN_ERR "%s: unable to signal thread\n", dev->name);
				return ret;
			}
			wait_for_completion (&tp->thr_exited);
		}
	}
	return (0);
}

/*----------------------------------------------------------------------
* toe_gmac_fill_free_q
* allocate buffers for free queue.
*----------------------------------------------------------------------*/
static void toe_gmac_fill_free_q(void)
{
	struct sk_buff	*skb;
	volatile DMA_RWPTR_T	fq_rwptr;
	volatile GMAC_RXDESC_T	*fq_desc;
	unsigned long	flags;
#ifdef DEBUG_MEMORY_LEAKAGE	
	unsigned short max_cnt = TOE_SW_FREEQ_DESC_NUM;
	volatile DMA_RWPTR_T	dfq0_rwptr, dfq1_rwptr;
	volatile NONTOE_QHDR_T	*qhdr;
	int	q0_vacant_cnt, q1_vacant_cnt, min_vacant_cnt, fq_cnt;
#else
	unsigned short max_cnt = TOE_SW_FREEQ_DESC_NUM >> 1;
#endif

	spin_lock_irqsave(&gmac_fq_lock, flags);
	fq_rwptr.bits32 = readl(TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);
	rmb();

#ifdef DEBUG_MEMORY_LEAKAGE
	/* number of buffers in software free queue. */
	fq_cnt = (fq_rwptr.bits.wptr - fq_rwptr.bits.rptr + TOE_SW_FREEQ_DESC_NUM) &
			(TOE_SW_FREEQ_DESC_NUM - 1);
	/* number of buffers in default queue 0. */
	qhdr = (NONTOE_QHDR_T*)TOE_DEFAULT_Q0_HDR_BASE;
	dfq0_rwptr.bits32 = qhdr->word1.bits32;
	q0_vacant_cnt = (TOE_DEFAULT_Q0_DESC_NUM - 1 + qhdr->word1.bits.rptr -
			qhdr->word1.bits.wptr) & (TOE_DEFAULT_Q0_DESC_NUM - 1);
	/* number of buffers in default queue 1. */
	qhdr = (NONTOE_QHDR_T*)TOE_DEFAULT_Q1_HDR_BASE;
	dfq1_rwptr.bits32 = qhdr->word1.bits32;
	q1_vacant_cnt = (TOE_DEFAULT_Q1_DESC_NUM - 1 + qhdr->word1.bits.rptr -
			qhdr->word1.bits.wptr) & (TOE_DEFAULT_Q1_DESC_NUM - 1);

	min_vacant_cnt = ((q0_vacant_cnt < q1_vacant_cnt) ? q0_vacant_cnt : q1_vacant_cnt);
	if (min_vacant_cnt > fq_cnt)
		min_vacant_cnt -= fq_cnt;
	else
		min_vacant_cnt = 0;
	//printk("%s::q0 %d, q1 %d, max %x, fq %x\n",
	//	__func__, q0_buf_cnt, q1_buf_cnt, max_buf_cnt, fq_vacant_cnt);
	//max_buf_cnt = ((max_buf_cnt < fq_vacant_cnt) ? max_buf_cnt : fq_vacant_cnt);
	max_cnt = ((max_cnt < min_vacant_cnt) ? max_cnt : min_vacant_cnt);
#endif
	while ((max_cnt--) && ((unsigned short)RWPTR_ADVANCE_ONE(fq_rwptr.bits.wptr,
			TOE_SW_FREEQ_DESC_NUM) != fq_rwptr.bits.rptr)) {
		if ((skb = dev_alloc_skb(SW_RX_BUF_SIZE)) == NULL) {
			printk("%s::skb allocation fail!\n", __func__);
			//while(1);
			break;
		}
		REG32(skb->data) = (uint32_t)skb;
		skb_reserve(skb, SKB_RESERVE_BYTES);
		//fq_rwptr.bits32 = readl(TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);
		fq_rwptr.bits.wptr = RWPTR_ADVANCE_ONE(fq_rwptr.bits.wptr,
				TOE_SW_FREEQ_DESC_NUM);
		fq_desc = (GMAC_RXDESC_T*)toe_private_data.swfq_desc_base+fq_rwptr.bits.wptr;
		fq_desc->word2.buf_adr = (uint32_t)__pa(skb->data);
#ifdef DEBUG_MEMORY_LEAKAGE
		consistent_sync((void*)fq_desc, sizeof(GMAC_RXDESC_T), PCI_DMA_TODEVICE);
		wmb();
		readl((GMAC_RXDESC_T*)toe_private_data.swfq_desc_base+fq_rwptr.bits.wptr);
#endif
		SET_WPTR(TOE_GLOBAL_BASE+GLOBAL_SWFQ_RWPTR_REG, fq_rwptr.bits.wptr);
		wmb();
		toe_private_data.fq_rx_rwptr.bits32 = fq_rwptr.bits32;
	}
	spin_unlock_irqrestore(&gmac_fq_lock, flags);
}

/*----------------------------------------------------------------------
* toe_gmac_interrupt
*----------------------------------------------------------------------*/
static irqreturn_t toe_gmac_interrupt (int irq, void *dev_instance, struct pt_regs *regs)
{
	struct net_device   *dev = (struct net_device *)dev_instance;
	TOE_INFO_T			*toe;
	GMAC_INFO_T 		*tp = (GMAC_INFO_T *)dev->priv;
	uint32_t		status0, status1, status2, status3, status4, data32;

//	struct net_device_stats *isPtr = (struct net_device_stats *)&tp->ifStatics;
	toe = (TOE_INFO_T *)&toe_private_data;

	/* always use NAPI */
	storlink_ctl.napi = 1;

#ifdef CONFIG_SL_NAPI 
if (storlink_ctl.napi == 1) {
	/* disable GMAC interrupt */
	toe_gmac_disable_interrupt(tp->irq);

	//isPtr->interrupts++;
	/* read Interrupt status */
	status0 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_0_REG);
	status1 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_1_REG);
	status2 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_2_REG);
	status3 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_3_REG);
	status4 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_4_REG);
	/* prompt warning if status bit ON but not enabled */
#if 0
	if (status0 & ~tp->intr0_enabled)
		printk("Intr 0 Status error. status = 0x%X, enable = 0x%X\n", 
				status0, tp->intr0_enabled);
	if (status1 & ~tp->intr1_enabled)
		printk("Intr 1 Status error. status = 0x%X, enable = 0x%X\n", 
				status1, tp->intr1_enabled);
	if (status2 & ~tp->intr2_enabled)
		printk("Intr 2 Status error. status = 0x%X, enable = 0x%X\n", 
				status2, tp->intr2_enabled);
	if (status3 & ~tp->intr3_enabled)
		printk("Intr 3 Status error. status = 0x%X, enable = 0x%X\n", 
				status3, tp->intr3_enabled);
	if (status4 & ~tp->intr4_enabled)
		printk("Intr 4 Status error. status = 0x%X, enable = 0x%X\n", 
				status4, tp->intr4_enabled);
#endif

	if (status0)
		writel(status0 & tp->intr0_enabled,
				TOE_GLOBAL_BASE+GLOBAL_INTERRUPT_STATUS_0_REG);
	if (status1)
		writel(status1 & tp->intr1_enabled,
				TOE_GLOBAL_BASE+GLOBAL_INTERRUPT_STATUS_1_REG);
	if (status2)
		writel(status2 & tp->intr2_enabled,
				TOE_GLOBAL_BASE+GLOBAL_INTERRUPT_STATUS_2_REG);
	if (status3)
		writel(status3 & tp->intr3_enabled,
				TOE_GLOBAL_BASE+GLOBAL_INTERRUPT_STATUS_3_REG);
	if (status4)
		writel(status4 & tp->intr4_enabled,
				TOE_GLOBAL_BASE+GLOBAL_INTERRUPT_STATUS_4_REG);

	/* handle freeq interrupt first */
	if (status4 & tp->intr4_enabled) {
		if ((status4 & SWFQ_EMPTY_INT_BIT)
				&& (tp->intr4_enabled & SWFQ_EMPTY_INT_BIT)) {
			//unsigned long data = REG32(TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);
			//gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_ENABLE_4_REG,
			//tp->intr4_enabled & ~SWFQ_EMPTY_INT_BIT, SWFQ_EMPTY_INT_BIT);

//			if (toe->gmac[0].dev && netif_running(toe->gmac[0].dev))
//				toe_gmac_handle_default_rxq(toe->gmac[0].dev,&toe->gmac[0]);
//			if (toe->gmac[1].dev && netif_running(toe->gmac[1].dev))
//				toe_gmac_handle_default_rxq(toe->gmac[1].dev,&toe->gmac[1]);
			printk("\nNAPI free_q empty INT\n");
			//toe_gmac_fill_free_q();

			tp->sw_fq_empty_cnt++;

			/*	이부분을 막으니 연속해서 이 intr 발생한다....
			 */
			/* disable freeq interrupt */
			data32 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_4_REG);
			data32 &= ~SWFQ_EMPTY_INT_BIT;
			writel(data32, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_4_REG);
		}
	}

	/* Interrupt Status 1 */
	if (status1 & tp->intr1_enabled) {
#define G1_INTR0_BITS	(GMAC1_HWTQ13_EOF_INT_BIT | GMAC1_HWTQ12_EOF_INT_BIT | GMAC1_HWTQ11_EOF_INT_BIT | GMAC1_HWTQ10_EOF_INT_BIT)
#define G0_INTR0_BITS	(GMAC0_HWTQ03_EOF_INT_BIT | GMAC0_HWTQ02_EOF_INT_BIT | GMAC0_HWTQ01_EOF_INT_BIT | GMAC0_HWTQ00_EOF_INT_BIT)
		/*
		 * Handle GMAC 0/1 HW Tx queue 0-3 EOF events. Only count TOE,
		 * Classification, and default queues interrupts are handled by ISR
		 * because they should pass packets to upper layer
		 */
		if (tp->port_id == 0) {
#ifndef	INTERRUPT_SELECT
			if (netif_running(dev) && (status1 & G0_INTR0_BITS)
					&& (tp->intr1_enabled & G0_INTR0_BITS)) {
				if (status1 & GMAC0_HWTQ03_EOF_INT_BIT)
					tp->hwtxq[3].eof_cnt++;
				if (status1 & GMAC0_HWTQ02_EOF_INT_BIT)
					tp->hwtxq[2].eof_cnt++;
				if (status1 & GMAC0_HWTQ01_EOF_INT_BIT)
					tp->hwtxq[1].eof_cnt++;
				if (status1 & GMAC0_HWTQ00_EOF_INT_BIT)
					tp->hwtxq[0].eof_cnt++;
			}
#endif	//INTERRUPT_SELECT			
			if (netif_running(dev) && (status1 & DEFAULT_Q0_INT_BIT)
					&& (tp->intr1_enabled & DEFAULT_Q0_INT_BIT)) {
				tp->poll_bits |= DEFAULT_Q0_INT_BIT;
				if (likely(netif_rx_schedule_prep(dev))) {
					/* disable default queue#0 interrupt */
					data32 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);
//					data32 &= ~(DEFAULT_Q0_INT_BIT|TOE_IQ_ALL_BITS|TOE_CLASS_RX_INT_BITS);
//					data32 &= ~tp->intr1_enabled;
					data32 &= ~DEFAULT_Q0_INT_BIT;
					writel(data32, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);
					__netif_rx_schedule(dev);
       			} else {
					/* poll has been scheduled  */
					/* disable default queue#0 interrupt */
					data32 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);
					data32 &= ~DEFAULT_Q0_INT_BIT;
					writel(data32, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);
				}
			}
		}
		if (tp->port_id == 1) {
#ifndef	INTERRUPT_SELECT			
			if (netif_running(dev) && (status1 & G1_INTR0_BITS)
					&& (tp->intr1_enabled & G1_INTR0_BITS)) {
				if (status1 & GMAC1_HWTQ13_EOF_INT_BIT)
					tp->hwtxq[3].eof_cnt++;
				if (status1 & GMAC1_HWTQ12_EOF_INT_BIT)
					tp->hwtxq[2].eof_cnt++;
				if (status1 & GMAC1_HWTQ11_EOF_INT_BIT)
					tp->hwtxq[1].eof_cnt++;
				if (status1 & GMAC1_HWTQ10_EOF_INT_BIT)
					tp->hwtxq[0].eof_cnt++;
			}
#endif	//INTERRUPT_SELECT

			if (netif_running(dev) && (status1 & DEFAULT_Q1_INT_BIT)
					&& (tp->intr1_enabled & DEFAULT_Q1_INT_BIT)) {
//				tp->poll_bits |= status1;
				tp->poll_bits |= DEFAULT_Q1_INT_BIT;
				if (likely(netif_rx_schedule_prep(dev))) {
					/* disable default queue#1 rx interrupt */
					data32 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);
					data32 &= ~DEFAULT_Q1_INT_BIT;
					writel(data32, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);
					__netif_rx_schedule(dev);
				} else {
					/* disable default queue#1 rx interrupt */
					data32 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);
					data32 &= ~DEFAULT_Q1_INT_BIT;
					writel(data32, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);
				}
			}
		} 
	}//end of if (status1 & tp->intr1_enabled)	

	/* Interrupt Status 0 */
	if (status0 & tp->intr0_enabled) {
#define ERR_INTR_BITS	(GMAC0_TXDERR_INT_BIT | GMAC0_TXPERR_INT_BIT |	\
						 GMAC1_TXDERR_INT_BIT | GMAC1_TXPERR_INT_BIT |	\
						 GMAC0_RXDERR_INT_BIT | GMAC0_RXPERR_INT_BIT |	\
						 GMAC1_RXDERR_INT_BIT | GMAC1_RXPERR_INT_BIT)

#ifndef	INTERRUPT_SELECT
		if (status0 &  ERR_INTR_BITS) {
			if ((status0 & GMAC0_TXDERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC0_TXDERR_INT_BIT)) {
				tp->txDerr_cnt[0]++;
				printk("GMAC0 TX AHB Bus Error!\n");
			}
			if ((status0 & GMAC0_TXPERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC0_TXPERR_INT_BIT)) {
				tp->txPerr_cnt[0]++;
				printk("GMAC0 Tx Descriptor Protocol Error!\n");
			}
			if ((status0 & GMAC1_TXDERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC1_TXDERR_INT_BIT)) {
				tp->txDerr_cnt[1]++;
				printk("GMAC1 Tx AHB Bus Error!\n");
			}
			if ((status0 & GMAC1_TXPERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC1_TXPERR_INT_BIT)) {
				tp->txPerr_cnt[1]++;
				printk("GMAC1 Tx Descriptor Protocol Error!\n");
			}
			
			if ((status0 & GMAC0_RXDERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC0_RXDERR_INT_BIT)) {
				tp->RxDerr_cnt[0]++;
				printk("GMAC0 Rx AHB Bus Error!\n");
			}
			if ((status0 & GMAC0_RXPERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC0_RXPERR_INT_BIT)) {
				tp->RxPerr_cnt[0]++;
				printk("GMAC0 Rx Descriptor Protocol Error!\n");
			}
			if ((status0 & GMAC1_RXDERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC1_RXDERR_INT_BIT)) {
				tp->RxDerr_cnt[1]++;
				printk("GMAC1 Rx AHB Bus Error!\n");
			}
			if ((status0 & GMAC1_RXPERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC1_RXPERR_INT_BIT)) {
				tp->RxPerr_cnt[1]++;
				printk("GMAC1 Rx Descriptor Protocol Error!\n");
			}
		}
#endif	//INTERRUPT_SELECT			
#ifndef	GMAX_TX_INTR_DISABLED
		if (tp->port_id == 1 &&	netif_running(dev)
				&& (((status0 & GMAC1_SWTQ10_FIN_INT_BIT)
						&& (tp->intr0_enabled & GMAC1_SWTQ10_FIN_INT_BIT))
					|| ((status0 & GMAC1_SWTQ10_EOF_INT_BIT)
							&& (tp->intr0_enabled & GMAC1_SWTQ10_EOF_INT_BIT))))
			toe_gmac_tx_complete(&toe_private_data.gmac[1], 0, dev, 1);
	
		if (tp->port_id == 0 &&	netif_running(dev)
				&& (((status0 & GMAC0_SWTQ00_FIN_INT_BIT)
						&& (tp->intr0_enabled & GMAC0_SWTQ00_FIN_INT_BIT))
					|| ((status0 & GMAC0_SWTQ00_EOF_INT_BIT)
							&& (tp->intr0_enabled & GMAC0_SWTQ00_EOF_INT_BIT))))
			toe_gmac_tx_complete(&toe_private_data.gmac[0], 0, dev, 1);
#endif		
	}
	
	/* Interrupt Status 4 */
#ifndef	INTERRUPT_SELECT
	if (status4 & tp->intr4_enabled) {
#define G1_INTR4_BITS		(0xff000000)
#define G0_INTR4_BITS		(0x00ff0000)

		if (tp->port_id == 0) {
			if ((status4 & G0_INTR4_BITS)
					&& (tp->intr4_enabled & G0_INTR4_BITS)) {
				if (status4 & GMAC0_RESERVED_INT_BIT)
					printk("GMAC0_RESERVED_INT_BIT is ON\n");
				if (status4 & GMAC0_MIB_INT_BIT)
					tp->mib_full_cnt++;
				if (status4 & GMAC0_RX_PAUSE_ON_INT_BIT)
					tp->rx_pause_on_cnt++;
				if (status4 & GMAC0_TX_PAUSE_ON_INT_BIT)
					tp->tx_pause_on_cnt++;
				if (status4 & GMAC0_RX_PAUSE_OFF_INT_BIT)
					tp->rx_pause_off_cnt++;
				if (status4 & GMAC0_TX_PAUSE_OFF_INT_BIT)
					tp->rx_pause_off_cnt++;
				if (status4 & GMAC0_RX_OVERRUN_INT_BIT)
					tp->rx_overrun_cnt++;
				if (status4 & GMAC0_STATUS_CHANGE_INT_BIT)
					tp->status_changed_cnt++;
			}
		}
		if (tp->port_id == 1) {
			if ((status4 & G1_INTR4_BITS)
					&& (tp->intr4_enabled & G1_INTR4_BITS)) {
				if (status4 & GMAC1_RESERVED_INT_BIT)
					printk("GMAC1_RESERVED_INT_BIT is ON\n");
				if (status4 & GMAC1_MIB_INT_BIT)
					tp->mib_full_cnt++;
				if (status4 & GMAC1_RX_PAUSE_ON_INT_BIT) {
					printk("Gmac pause on\n");
					tp->rx_pause_on_cnt++;
				}
				if (status4 & GMAC1_TX_PAUSE_ON_INT_BIT) {
					printk("Gmac pause on\n");
					tp->tx_pause_on_cnt++;
				}
				if (status4 & GMAC1_RX_PAUSE_OFF_INT_BIT) {
					printk("Gmac pause off\n");
					tp->rx_pause_off_cnt++;
				}
				if (status4 & GMAC1_TX_PAUSE_OFF_INT_BIT) {
					printk("Gmac pause off\n");
					tp->rx_pause_off_cnt++;
				}
				if (status4 & GMAC1_RX_OVERRUN_INT_BIT) {
					//printk("Gmac Rx Overrun \n");
					tp->rx_overrun_cnt++;
				}
				if (status4 & GMAC1_STATUS_CHANGE_INT_BIT)
					tp->status_changed_cnt++;
			}
		}
	}
#endif //Interrupt Status 4 INTERRUPT_SELECT

	toe_gmac_enable_interrupt(tp->irq);
	return	IRQ_RETVAL(1);
}	//end of (if (storlink_ctl.napi == 1))
else
{
#endif	//endif CONFIG_SL_NAPI

	/* disable GMAC interrupt */
    toe_gmac_disable_interrupt(tp->irq);

//	isPtr->interrupts++;
	/* read Interrupt status */
	status0 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_0_REG);
	status1 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_1_REG);
	status2 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_2_REG);
	status3 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_3_REG);
	status4 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_4_REG);
	/* prompt warning if status bit ON but not enabled */
#if 0	
	if (status0 & ~tp->intr0_enabled)
		printk("Intr 0 Status error. status = 0x%X, enable = 0x%X\n", 
				status0, tp->intr0_enabled);
	if (status1 & ~tp->intr1_enabled)
		printk("Intr 1 Status error. status = 0x%X, enable = 0x%X\n", 
				status1, tp->intr1_enabled);
	if (status2 & ~tp->intr2_enabled)
		printk("Intr 2 Status error. status = 0x%X, enable = 0x%X\n", 
				status2, tp->intr2_enabled);
	if (status3 & ~tp->intr3_enabled)
		printk("Intr 3 Status error. status = 0x%X, enable = 0x%X\n", 
				status3, tp->intr3_enabled);
	if (status4 & ~tp->intr4_enabled)
		printk("Intr 4 Status error. status = 0x%X, enable = 0x%X\n", 
				status4, tp->intr4_enabled);
#endif

	if (status0) 
		writel(status0 & tp->intr0_enabled, TOE_GLOBAL_BASE+GLOBAL_INTERRUPT_STATUS_0_REG);
	if (status1) 
		writel(status1 & tp->intr1_enabled, TOE_GLOBAL_BASE+GLOBAL_INTERRUPT_STATUS_1_REG);
	if (status2) 
		writel(status2 & tp->intr2_enabled, TOE_GLOBAL_BASE+GLOBAL_INTERRUPT_STATUS_2_REG);
	if (status3) 
		writel(status3 & tp->intr3_enabled, TOE_GLOBAL_BASE+GLOBAL_INTERRUPT_STATUS_3_REG);
	if (status4) 
		writel(status4 & tp->intr4_enabled, TOE_GLOBAL_BASE+GLOBAL_INTERRUPT_STATUS_4_REG);
	
	/* handle freeq interrupt first */
	if (status4 & tp->intr4_enabled) {
		if ((status4 & SWFQ_EMPTY_INT_BIT)
				&& (tp->intr4_enabled & SWFQ_EMPTY_INT_BIT)) {
			// unsigned long data = REG32(TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);
			//gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_ENABLE_4_REG,
			//	tp->intr4_enabled & ~SWFQ_EMPTY_INT_BIT, SWFQ_EMPTY_INT_BIT);

			//gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_STATUS_4_REG,
			//	SWFQ_EMPTY_INT_BIT, SWFQ_EMPTY_INT_BIT);
//			printk("\nSWFQ_EMPTY_INT_BIT  freeq int\n");
			if (toe->gmac[0].dev && netif_running(toe->gmac[0].dev))
				toe_gmac_handle_default_rxq(toe->gmac[0].dev,&toe->gmac[0]);
			if (toe->gmac[1].dev && netif_running(toe->gmac[1].dev))
				toe_gmac_handle_default_rxq(toe->gmac[1].dev,&toe->gmac[1]);
			printk("\nfreeq int\n");
			//toe_gmac_fill_free_q();
			tp->sw_fq_empty_cnt++;

			gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_STATUS_4_REG,
					status4, SWFQ_EMPTY_INT_BIT);
		}
	}

	/* Interrupt Status 1 */
	if (status1 & tp->intr1_enabled) {
		#define G1_INTR0_BITS	(GMAC1_HWTQ13_EOF_INT_BIT | GMAC1_HWTQ12_EOF_INT_BIT | GMAC1_HWTQ11_EOF_INT_BIT | GMAC1_HWTQ10_EOF_INT_BIT)
		#define G0_INTR0_BITS	(GMAC0_HWTQ03_EOF_INT_BIT | GMAC0_HWTQ02_EOF_INT_BIT | GMAC0_HWTQ01_EOF_INT_BIT | GMAC0_HWTQ00_EOF_INT_BIT)
		/* Handle GMAC 0/1 HW Tx queue 0-3 EOF events. Only count TOE,
		 * Classification, and default queues interrupts are handled by ISR
		 * because they should pass packets to upper layer
		 */
		if (tp->port_id == 0) {
#ifndef	INTERRUPT_SELECT
			if (netif_running(dev) && (status1 & G0_INTR0_BITS)
					&& (tp->intr1_enabled & G0_INTR0_BITS)) {
				if (status1 & GMAC0_HWTQ03_EOF_INT_BIT)
					tp->hwtxq[3].eof_cnt++;
				if (status1 & GMAC0_HWTQ02_EOF_INT_BIT)
					tp->hwtxq[2].eof_cnt++;
				if (status1 & GMAC0_HWTQ01_EOF_INT_BIT)
					tp->hwtxq[1].eof_cnt++;
				if (status1 & GMAC0_HWTQ00_EOF_INT_BIT)
					tp->hwtxq[0].eof_cnt++;
#endif	//INTERRUPT_SELECT
#ifndef	INTERRUPT_SELECT
			}
#endif	//INTERRUPT_SELECT
			if (netif_running(dev) && (status1 & DEFAULT_Q0_INT_BIT)
					&& (tp->intr1_enabled & DEFAULT_Q0_INT_BIT)) {
				tp->default_q_intr_cnt++;
				toe_gmac_handle_default_rxq(dev, tp);
			}
		}
		if (tp->port_id == 1) {
#ifndef	INTERRUPT_SELECT
			if (netif_running(dev) && (status1 & G1_INTR0_BITS)
					&& (tp->intr1_enabled & G1_INTR0_BITS)) {
				if (status1 & GMAC1_HWTQ13_EOF_INT_BIT)
					tp->hwtxq[3].eof_cnt++;
				if (status1 & GMAC1_HWTQ12_EOF_INT_BIT)
					tp->hwtxq[2].eof_cnt++;
				if (status1 & GMAC1_HWTQ11_EOF_INT_BIT)
					tp->hwtxq[1].eof_cnt++;
				if (status1 & GMAC1_HWTQ10_EOF_INT_BIT)
					tp->hwtxq[0].eof_cnt++;
#endif	//INTERRUPT_SELECT
#ifndef	INTERRUPT_SELECT
			}
#endif	//INTERRUPT_SELECT
			if (netif_running(dev) && (status1 & DEFAULT_Q1_INT_BIT)
					&& (tp->intr1_enabled & DEFAULT_Q1_INT_BIT)) {
				tp->default_q_intr_cnt++;
				toe_gmac_handle_default_rxq(dev, tp);
			}
		}
	}

	/* Interrupt Status 0 */
	if (status0 & tp->intr0_enabled) {
#define ERR_INTR_BITS	(GMAC0_TXDERR_INT_BIT | GMAC0_TXPERR_INT_BIT |	\
						 GMAC1_TXDERR_INT_BIT | GMAC1_TXPERR_INT_BIT |	\
						 GMAC0_RXDERR_INT_BIT | GMAC0_RXPERR_INT_BIT |	\
						 GMAC1_RXDERR_INT_BIT | GMAC1_RXPERR_INT_BIT)
#ifndef	INTERRUPT_SELECT
		if (status0 &  ERR_INTR_BITS) {
			if ((status0 & GMAC0_TXDERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC0_TXDERR_INT_BIT)) {
				tp->txDerr_cnt[0]++;
				printk("GMAC0 TX AHB Bus Error!\n");
			}
			if ((status0 & GMAC0_TXPERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC0_TXPERR_INT_BIT)) {
				tp->txPerr_cnt[0]++;
				printk("GMAC0 Tx Descriptor Protocol Error!\n");
			}
			if ((status0 & GMAC1_TXDERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC1_TXDERR_INT_BIT)) {
				tp->txDerr_cnt[1]++;
				printk("GMAC1 Tx AHB Bus Error!\n");
			}
			if ((status0 & GMAC1_TXPERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC1_TXPERR_INT_BIT)) {
				tp->txPerr_cnt[1]++;
				printk("GMAC1 Tx Descriptor Protocol Error!\n");
			}
			
			if ((status0 & GMAC0_RXDERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC0_RXDERR_INT_BIT)) {
				tp->RxDerr_cnt[0]++;
				printk("GMAC0 Rx AHB Bus Error!\n");
			}
			if ((status0 & GMAC0_RXPERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC0_RXPERR_INT_BIT)) {
				tp->RxPerr_cnt[0]++;
				printk("GMAC0 Rx Descriptor Protocol Error!\n");
			}
			if ((status0 & GMAC1_RXDERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC1_RXDERR_INT_BIT)) {
				tp->RxDerr_cnt[1]++;
				printk("GMAC1 Rx AHB Bus Error!\n");
			}
			if ((status0 & GMAC1_RXPERR_INT_BIT)
					&& (tp->intr0_enabled & GMAC1_RXPERR_INT_BIT)) {
				tp->RxPerr_cnt[1]++;
				printk("GMAC1 Rx Descriptor Protocol Error!\n");
			}
		}
#endif	//#ifndef INTERRUPT_SELECT	
#ifndef	GMAX_TX_INTR_DISABLED
		if (tp->port_id == 1 &&	netif_running(dev)
				&& (((status0 & GMAC1_SWTQ10_FIN_INT_BIT)
						&& (tp->intr0_enabled & GMAC1_SWTQ10_FIN_INT_BIT))
					|| ((status0 & GMAC1_SWTQ10_EOF_INT_BIT)
							&& (tp->intr0_enabled & GMAC1_SWTQ10_EOF_INT_BIT))))
			toe_gmac_tx_complete(&toe_private_data.gmac[1], 0, dev, 1);

		if (tp->port_id == 0 &&	netif_running(dev)
				&& (((status0 & GMAC0_SWTQ00_FIN_INT_BIT)
						&& (tp->intr0_enabled & GMAC0_SWTQ00_FIN_INT_BIT))
					|| ((status0 & GMAC0_SWTQ00_EOF_INT_BIT)
							&& (tp->intr0_enabled & GMAC0_SWTQ00_EOF_INT_BIT))))
			toe_gmac_tx_complete(&toe_private_data.gmac[0], 0, dev, 1);
#endif		
		/* clear enabled status bits */
	}
	/* Interrupt Status 4 */
#ifndef	INTERRUPT_SELECT
	if (status4 & tp->intr4_enabled) {
#define G1_INTR4_BITS		(0xff000000)
#define G0_INTR4_BITS		(0x00ff0000)

		if (tp->port_id == 0) {
			if ((status4 & G0_INTR4_BITS)
					&& (tp->intr4_enabled & G0_INTR4_BITS)) {
				if (status4 & GMAC0_RESERVED_INT_BIT)
					printk("GMAC0_RESERVED_INT_BIT is ON\n");
				if (status4 & GMAC0_MIB_INT_BIT)
					tp->mib_full_cnt++;
				if (status4 & GMAC0_RX_PAUSE_ON_INT_BIT)
					tp->rx_pause_on_cnt++;
				if (status4 & GMAC0_TX_PAUSE_ON_INT_BIT)
					tp->tx_pause_on_cnt++;
				if (status4 & GMAC0_RX_PAUSE_OFF_INT_BIT)
					tp->rx_pause_off_cnt++;
				if (status4 & GMAC0_TX_PAUSE_OFF_INT_BIT)
					tp->rx_pause_off_cnt++;
				if (status4 & GMAC0_RX_OVERRUN_INT_BIT)
					tp->rx_overrun_cnt++;
				if (status4 & GMAC0_STATUS_CHANGE_INT_BIT)
					tp->status_changed_cnt++;
			}
		}
		if (tp->port_id == 1) {
			if ((status4 & G1_INTR4_BITS)
					&& (tp->intr4_enabled & G1_INTR4_BITS)) {
				if (status4 & GMAC1_RESERVED_INT_BIT)
					printk("GMAC1_RESERVED_INT_BIT is ON\n");
				if (status4 & GMAC1_MIB_INT_BIT)
					tp->mib_full_cnt++;
				if (status4 & GMAC1_RX_PAUSE_ON_INT_BIT) {
					//printk("Gmac pause on\n");
					tp->rx_pause_on_cnt++;
				}
				if (status4 & GMAC1_TX_PAUSE_ON_INT_BIT) {
					//printk("Gmac pause on\n");
					tp->tx_pause_on_cnt++;
				}
				if (status4 & GMAC1_RX_PAUSE_OFF_INT_BIT) {
					//printk("Gmac pause off\n");
					tp->rx_pause_off_cnt++;
				}
				if (status4 & GMAC1_TX_PAUSE_OFF_INT_BIT) {
					//printk("Gmac pause off\n");
					tp->rx_pause_off_cnt++;
				}
				if (status4 & GMAC1_RX_OVERRUN_INT_BIT) {
					//printk("Gmac Rx Overrun \n");
					tp->rx_overrun_cnt++;
				}
				if (status4 & GMAC1_STATUS_CHANGE_INT_BIT)
					tp->status_changed_cnt++;
			}
		}
#if 0
		if ((status4 & SWFQ_EMPTY_INT_BIT)
				&& (tp->intr4_enabled & SWFQ_EMPTY_INT_BIT)) {
			//unsigned long data = REG32(TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);
//			mac_stop_rxdma(tp->sc);
			gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_ENABLE_4_REG,
					tp->intr4_enabled & ~SWFQ_EMPTY_INT_BIT, SWFQ_EMPTY_INT_BIT);

			gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_STATUS_4_REG,
					SWFQ_EMPTY_INT_BIT, SWFQ_EMPTY_INT_BIT);
			toe_gmac_fill_free_q();
			tp->sw_fq_empty_cnt++;

			gmac_write_reg(TOE_GLOBAL_BASE, GLOBAL_INTERRUPT_STATUS_4_REG, status4,
					SWFQ_EMPTY_INT_BIT);
#if 0
			if (netif_running(dev))
				toe_gmac_handle_default_rxq(dev, tp);
			printk("SWFQ_EMPTY_INT_BIT is ON!\n");	// should not be happened
#endif
		}
#endif
	}
#endif	//INTERRUPT_SELECT
	toe_gmac_enable_interrupt(tp->irq);
	//printk("gmac_interrupt complete!\n\n");
//	return IRQ_RETVAL(handled);
	return	IRQ_RETVAL(1);
#ifdef CONFIG_SL_NAPI  
}
#endif
}

/*----------------------------------------------------------------------
*	toe_gmac_handle_default_rxq
*	(1) Get rx Buffer for default Rx queue
*	(2) notify or call upper-routine to handle it
*	(3) get a new buffer and insert it into SW free queue
*	(4) Note: The SW free queue Read-Write Pointer should be locked when accessing
*----------------------------------------------------------------------*/
static inline void toe_gmac_handle_default_rxq(struct net_device *dev, GMAC_INFO_T *tp)
//static void toe_gmac_handle_default_rxq(struct net_device *dev, GMAC_INFO_T *tp)
{
	TOE_INFO_T *toe;
    GMAC_RXDESC_T *curr_desc;
	struct sk_buff *skb;
    DMA_RWPTR_T rwptr;
	uint32_t pkt_size, desc_count, good_frame, chksum_status, rx_status;
	int max_cnt;
#ifdef CONFIG_SL351x_NAT
	struct iphdr *ip_hdr;
#endif
	struct net_device_stats *isPtr = (struct net_device_stats *)&tp->ifStatics;

	rwptr.bits32 = readl(&tp->default_qhdr->word1);
#if 0
	if (rwptr.bits.rptr != tp->rx_rwptr.bits.rptr) { 
		mac_stop_txdma((struct net_device *)tp->dev);
		printk("Default Queue HW RD ptr (0x%x) != SW RD Ptr (0x%x)\n",
				rwptr.bits32, tp->rx_rwptr.bits.rptr);
		while(1);
	}
#endif
	toe = (TOE_INFO_T *)&toe_private_data;
	max_cnt = DEFAULT_RXQ_MAX_CNT;
	while ((--max_cnt) && rwptr.bits.rptr != rwptr.bits.wptr) {
    	curr_desc = (GMAC_RXDESC_T *)tp->default_desc_base + rwptr.bits.rptr;
//		consistent_sync(curr_desc, sizeof(GMAC_RXDESC_T), PCI_DMA_FROMDEVICE);
#ifdef GMAC_DEBUG
		tp->default_q_cnt++;
#endif
		tp->rx_curr_desc = (uint32_t)curr_desc;
		rx_status = curr_desc->word0.bits.status;
		chksum_status = curr_desc->word0.bits.chksum_status;
#ifdef GMAC_DEBUG
		tp->rx_status_cnt[rx_status]++;
		tp->rx_chksum_cnt[chksum_status]++;
#endif
		pkt_size = curr_desc->word1.bits.byte_count;	/* total byte count in a frame*/
		desc_count = curr_desc->word0.bits.desc_count;	/* get descriptor count per frame */
		good_frame=1;
		if ((curr_desc->word0.bits32 & (GMAC_RXDESC_0_T_derr | GMAC_RXDESC_0_T_perr))
				|| (pkt_size < 60)
			    || (chksum_status & 0x4)
				|| rx_status) {
			good_frame = 0;
#ifdef GMAC_DEBUG
			if (curr_desc->word0.bits32 & GMAC_RXDESC_0_T_derr)
				printk("%s::derr (GMAC-%d)!!!\n", __func__, tp->port_id);
			if (curr_desc->word0.bits32 & GMAC_RXDESC_0_T_perr)
				printk("%s::perr (GMAC-%d)!!!\n", __func__, tp->port_id);
#endif
			if (rx_status) {
				if (rx_status == 4 || rx_status == 7)
					isPtr->rx_crc_errors++;
//				printk("%s::Status=%d (GMAC-%d)!!!\n", __func__, rx_status, tp->port_id);
			}
//			if (chksum_status)
//				printk("%s::Checksum Status=%d (GMAC-%d)!!!\n", __func__, chksum_status, tp->port_id);
			skb = (struct sk_buff *)(REG32(__va(curr_desc->word2.buf_adr) - SKB_RESERVE_BYTES));
			dev_kfree_skb_irq(skb);
		}
		if (good_frame) {
#ifdef GMAC_DEBUG
			if (curr_desc->word0.bits.drop)
				printk("%s::Drop (GMAC-%d)!!!\n", __func__, tp->port_id);
#endif
//			if (chksum_status)
//				printk("%s::Checksum Status=%d (GMAC-%d)!!!\n", __func__, chksum_status, tp->port_id);
				
	    	/* get frame information from the first descriptor of the frame */
			isPtr->rx_packets++;
			skb = (struct sk_buff *)(REG32(__va(curr_desc->word2.buf_adr - SKB_RESERVE_BYTES)));
			if (!skb) {
				printk("Fatal Error!!skb==NULL\n");
				goto next_rx;
			}
			tp->curr_rx_skb = skb;
			// consistent_sync((void *)__va(curr_desc->word2.buf_adr), pkt_size, PCI_DMA_FROMDEVICE);

			//curr_desc->word2.buf_adr = 0;

			skb_reserve (skb, RX_INSERT_BYTES);	/* 16 byte align the IP fields. */
			skb_put(skb, pkt_size);
			skb->dev = dev;
			if (chksum_status == RX_CHKSUM_IP_UDP_TCP_OK) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
#ifdef CONFIG_SL351x_NAT
				if (nat_cfg.enabled && curr_desc->word3.bits.l3_offset 
						&& curr_desc->word3.bits.l4_offset) {
					ip_hdr = (struct iphdr *)&(skb->data[curr_desc->word3.bits.l3_offset]);
					sl351x_nat_input(skb, tp->port_id, 
							(void *)curr_desc->word3.bits.l3_offset,
							(void *)curr_desc->word3.bits.l4_offset);
				}
#endif
#ifdef CONFIG_SL351X_BR
				sl351x_br_input(skb,tp->port_id);
#endif
			} else if (chksum_status == RX_CHKSUM_IP_OK_ONLY) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
#ifdef CONFIG_SL351x_NAT
				if (nat_cfg.enabled && curr_desc->word3.bits.l3_offset
						&& curr_desc->word3.bits.l4_offset) {
					ip_hdr = (struct iphdr *)&(skb->data[curr_desc->word3.bits.l3_offset]);
					if ((ip_hdr->protocol == IPPROTO_UDP)
							|| (ip_hdr->protocol == IPPROTO_GRE)) {
						sl351x_nat_input(skb, tp->port_id,
								(void *)curr_desc->word3.bits.l3_offset,
							  	(void *)curr_desc->word3.bits.l4_offset);
					}
				}
#endif
#ifdef CONFIG_SL351X_BR
				sl351x_br_input(skb,tp->port_id); 
#endif	
			} else {
#ifdef CONFIG_SL351X_BR				
				sl351x_br_input(skb,tp->port_id);  
#endif
			}

			skb->protocol = eth_type_trans(skb,dev); /* set skb protocol */
			netif_rx(skb);  /* socket rx */
			dev->last_rx = jiffies;
			isPtr->rx_bytes += pkt_size;
		}

next_rx:
		/* advance one for Rx default Q 0/1 */
		rwptr.bits.rptr = RWPTR_ADVANCE_ONE(rwptr.bits.rptr, tp->default_desc_num);
		SET_RPTR(&tp->default_qhdr->word1, rwptr.bits.rptr);
		tp->rx_rwptr.bits32 = rwptr.bits32;
//		toe_gmac_fill_free_q();
	}
	toe_gmac_fill_free_q();
}

/*----------------------------------------------------------------------
* gmac_get_phy_vendor
*----------------------------------------------------------------------*/
static uint32_t gmac_get_phy_vendor(int phy_addr)
{
	uint32_t	reg_val;
	reg_val=(mii_read(phy_addr, 0x02) << 16) + mii_read(phy_addr,0x03);
	return reg_val;
}    

/*----------------------------------------------------------------------
* gmac_set_phy_status
*----------------------------------------------------------------------*/
void gmac_set_phy_status(struct net_device *dev)
{
	GMAC_INFO_T *tp = dev->priv;
	GMAC_STATUS_T  status;
	uint32_t reg_val, ability, wan_port_id;
	uint32_t i = 0;

	if((tp->port_id == GMAC_PORT1) && (Giga_switch == 1))
	{
		toe_gmac_enable_tx_rx(dev);
		netif_wake_queue(dev);
		set_bit(__LINK_STATE_START, &dev->state);

		/* Force GMAC 1 to 1000 Full */
		gmac_write_reg(tp->base_addr, GMAC_STATUS, 0x7d, 0x0000007f);
		return ;
	}
	if((tp->port_id == GMAC_PORT1) && (Tantos_switch == 1))
	{
		toe_gmac_enable_tx_rx(dev);
		netif_wake_queue(dev);
		set_bit(__LINK_STATE_START, &dev->state);

		/* Force GMAC 1 to 100 Full */
		gmac_write_reg(tp->base_addr, GMAC_STATUS, 0x1b, 0x0000007f);
		return ;
	}


#ifdef __ORIGINAL__
		reg_val = gmac_get_phy_vendor(tp->phy_addr);
			printk("GMAC-%d Addr %d Vendor ID: 0x%08x\n", tp->port_id, tp->phy_addr, reg_val);
#else
{
	int i;

	for(i = 0; i < 2; i++)
	  {
		reg_val = gmac_get_phy_vendor(i);

		if(reg_val == 0x02430c54)
		  {
			tp->phy_addr = i;
			printk("GMAC-%d Addr %d Vendor ID: 0x%08x\n", tp->port_id, tp->phy_addr, reg_val);
			break;
		  }
		else
			printk("PHY Addr %d Not Detected.. continue. \n", i);
	  }
}
#endif
	switch (tp->phy_mode)
	{
		case GMAC_PHY_GMII:
			/* advertisement 100M full duplex, pause capable on */
			mii_write(tp->phy_addr,0x04,0x05e1);
#ifdef CONFIG_SL3516_ASIC
			/* advertise 1000M full/half duplex */
			mii_write(tp->phy_addr,0x09,0x0300);
#else
			/* advertise no 1000M full/half duplex */
			mii_write(tp->phy_addr,0x09,0x0000);
#endif
			break;

		case GMAC_PHY_RGMII_100:
			/* advertisement 100M full duplex, pause capable on */
			mii_write(tp->phy_addr,0x04,0x05e1);
			/* advertise no 1000M */
			mii_write(tp->phy_addr,0x09,0x0000);
			break;

		case GMAC_PHY_RGMII_1000:
			/* advertisement 100M full duplex, pause capable on */
			mii_write(tp->phy_addr,0x04,0x05e1);
#ifdef CONFIG_SL3516_ASIC
 			/* advertise 1000M full/half duplex */
			mii_write(tp->phy_addr,0x09,0x0300);
#else
			/* advertise no 1000M full/half duplex */
			mii_write(tp->phy_addr,0x09,0x0000);
#endif
			break;

		case GMAC_PHY_MII:
		default:
			/* advertisement 100M full duplex, pause capable on */
			mii_write(tp->phy_addr,0x04,0x05e1);
			/* advertise no 1000M */
			mii_write(tp->phy_addr,0x09,0x0000);
			break;
	}

#if defined(ICPLUS_PHY) || defined(REALTEK_PHY) || defined(CONFIG_RTL8366SR_PHY)
	printk(" IC PLUS or RealTek Phy select .\n");
#else
 #ifndef STORLINK_PHY
		mii_write(tp->phy_addr,0x18,0x0041);	/* Phy active LED */
 #endif
#endif

#ifndef STORLINK_PHY		/* Marvell phy do reset phy */
	if (tp->auto_nego_cfg)
	{
		reg_val = 0x1200 | (1 << 15);
		/* Enable and Restart Auto-Negotiation */
		mii_write(tp->phy_addr,0x00,reg_val);
		mdelay(500);
		reg_val &= ~(1 << 15);
		mii_write(tp->phy_addr, 0x00, reg_val);
	}
	else
	{
		reg_val = 0;
		reg_val |= (tp->full_duplex_cfg) ? (1 << 8) : 0;
		reg_val |= (tp->speed_cfg == GMAC_SPEED_1000) ? (1 << 6) : 0;
		reg_val |= (tp->speed_cfg == GMAC_SPEED_100) ? (1 << 13) : 0;

		mii_write(tp->phy_addr, 0x00, reg_val);
		mdelay(100);

		reg_val |= (1 << 15);	/* Reset PHY; */
		mii_write(tp->phy_addr, 0x00, reg_val);
	}
#endif

	status.bits32 = 0;

	/* set PHY operation mode */
	status.bits.mii_rmii = tp->phy_mode;
	status.bits.reserved = 1;
	mdelay(100);

	while (((reg_val=mii_read(tp->phy_addr, 0x01)) & 0x04) != 0x04)
	{
		msleep(100);
		i++;
		if (i > 30)
			break;
	}

	if (i > 30)
	{
		tp->pre_phy_status = LINK_DOWN;
		status.bits.link = LINK_DOWN;
		clear_bit(__LINK_STATE_START, &dev->state);
		printk(" Link-Down(0x%04x)", reg_val);
		netif_carrier_off(dev);
		netif_stop_queue(dev);

		if (Giga_switch || Tantos_switch)
		{
			wan_port_id = 1;
			storlink_ctl.link[wan_port_id] = 0;
		}
		else
		{
			storlink_ctl.link[ tp->port_id] = 0;
		}
	}
	else
	{
		tp->pre_phy_status = LINK_UP;
		status.bits.link = LINK_UP;
		set_bit(__LINK_STATE_START, &dev->state);
		printk(" Link-Up(0x%04x)",reg_val);
		netif_carrier_on(dev);

		if (Giga_switch || Tantos_switch)
		{
			wan_port_id = 1;
			storlink_ctl.link[ wan_port_id] = 1;
		}
		else
		{
			storlink_ctl.link[ tp->port_id] = 1;
		}
	}
	//value = mii_read(PHY_ADDR, 0x05);

	ability = (mii_read(tp->phy_addr, 0x05) & 0x05E0) >> 5;

#ifdef	__ORIGINAL__
	reg_val = mii_read(tp->phy_addr, 0x0A);
#else
	reg_val = 0;
#endif

	if ((reg_val & 0x0800) == 0x0800)
	{
		status.bits.duplex = 1;
		status.bits.speed = 2;
		if (status.bits.mii_rmii == GMAC_PHY_RGMII_100)
			status.bits.mii_rmii = GMAC_PHY_RGMII_1000;

		printk(" 1000M/Full");
	}
	else if ((reg_val & 0x0400) == 0x0400)
	{
		status.bits.duplex = 0;
		status.bits.speed = 2;
		if (status.bits.mii_rmii == GMAC_PHY_RGMII_100)
			status.bits.mii_rmii = GMAC_PHY_RGMII_1000;

		printk(" 1000M/Half");
	}
	else
	{
#ifdef CONFIG_SL3516_ASIC
		if (status.bits.mii_rmii == GMAC_PHY_RGMII_1000)
			status.bits.mii_rmii = GMAC_PHY_RGMII_100;
#endif
		if ((ability & 0x08) == 0x08)			/* 100M full duplex */
		{
			status.bits.duplex = 1;
			status.bits.speed = 1;
			printk(" 100M/Full");
		}
		else if ((ability & 0x04) == 0x04)		/* 100M half duplex */
		{
			status.bits.duplex = 0;
			status.bits.speed = 1;
			printk(" 100M/Half");

		}
		else if ((ability & 0x02) == 0x02)		/* 10M full duplex */
		{
			status.bits.duplex = 1;
			status.bits.speed = 0;
			printk(" 10M/Full");
		}
		else if ((ability & 0x01) == 0x01)		/* 10M half duplex */
		{
			status.bits.duplex = 0;
			status.bits.speed = 0;
			printk(" 10M/Half");
		}
	}
	if ((ability & 0x20) == 0x20)
	{
		tp->flow_control_enable = 1;
		printk(" Flow-Control-Enable");
	}
	else
	{
		tp->flow_control_enable = 0;
		printk(" Flow-Control-Disable");
	}

	tp->full_duplex_status = status.bits.duplex;
	tp->speed_status = status.bits.speed;

	if (!tp->auto_nego_cfg)
	{
		status.bits.duplex = tp->full_duplex_cfg;
		status.bits.speed = tp->speed_cfg;
	}

//	/* According GUI teams request,link status become ture */
//	if(Giga_switch || Tantos_switch) {
//				wan_port_id = 1;
//				storlink_ctl.link[ wan_port_id] = 1;
//	}	else {
//				storlink_ctl.link[ tp->port_id] = 1;
//	}

	printk("\n");

	toe_gmac_disable_tx_rx(dev);
	mdelay(10);
	gmac_write_reg(tp->base_addr, GMAC_STATUS, status.bits32, 0x0000007f);
	toe_gmac_enable_tx_rx(dev);
}

/*----------------------------------------------------------------------
* gmac_phy_thread
*----------------------------------------------------------------------*/
static int gmac_phy_thread (void *data)
{
	struct net_device   *dev = data;
	GMAC_INFO_T *tp = dev->priv;
	unsigned long       timeout;

	daemonize("%s", dev->name);
	allow_signal(SIGTERM);

	while (1) {
	    timeout = next_tick;
		do {
			timeout = interruptible_sleep_on_timeout (&tp->thr_wait, timeout);
		} while (!signal_pending (current) && (timeout > 0));

		if (signal_pending (current)) {
//			spin_lock_irq(&current->sigmask_lock);
			flush_signals(current);
//			spin_unlock_irq(&current->sigmask_lock);
		}

		if (tp->time_to_die) break;

		//printk("%s : Polling MAC %d PHY Status...\n",__func__, tp->port_id);
		rtnl_lock ();
		if (tp->auto_nego_cfg){
				if ((Tantos_switch != 1) || (Giga_switch != 1))
					gmac_get_phy_status(dev);
        }
		rtnl_unlock ();
	}
	complete_and_exit (&tp->thr_exited, 0);
}

/*----------------------------------------------------------------------
* gmac_get_switch_status
*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
* gmac_get_phy_status
*----------------------------------------------------------------------*/
void
gmac_get_phy_status(struct net_device *dev)
{
	GMAC_INFO_T *tp = dev->priv;
	GMAC_CONFIG0_T	config0,config0_mask;
	GMAC_STATUS_T   status, old_status;
	uint32_t    reg_val,ability,wan_port_id;

#ifdef PHY_WORKAROUND
	uint32_t	re_poll_counter = 3;
#endif	

	old_status.bits32 = status.bits32 = gmac_read_reg(tp->base_addr, GMAC_STATUS);

#ifdef PHY_WORKAROUND
phy_status:
#endif
	/* read PHY status register */
	reg_val = mii_read(tp->phy_addr, 0x01);
	if ((reg_val & 0x0024) == 0x0024)
	{
		/* link is established and auto_negotiate process completed */

		ability = (mii_read(tp->phy_addr, 0x05) & 0x05E0) >> 5;

		/* read PHY Auto-Negotiation Link Partner Ability Register */
#ifdef CONFIG_SL3516_ASIC
 #ifdef	__ORIGINAL__
		reg_val = mii_read(tp->phy_addr, 0x0A);
 #else
		reg_val = 0;
 #endif

 		if ((reg_val & 0x0800) == 0x0800) 
		{
			status.bits.duplex = 1;
			status.bits.speed = 2;
			if (status.bits.mii_rmii == GMAC_PHY_RGMII_100)
				status.bits.mii_rmii = GMAC_PHY_RGMII_1000;
		}
 		else if ((reg_val & 0x0400) == 0x0400) 
		{
			status.bits.duplex = 0;
			status.bits.speed = 2;
			if (status.bits.mii_rmii == GMAC_PHY_RGMII_100)
				status.bits.mii_rmii = GMAC_PHY_RGMII_1000;
		} else
#endif //CONFIG_SL3516_ASIC
		{
#ifdef CONFIG_SL3516_ASIC
			if (status.bits.mii_rmii == GMAC_PHY_RGMII_1000)
			status.bits.mii_rmii = GMAC_PHY_RGMII_100;
#endif
			if ((ability & 0x08) == 0x08)			/* 100M full duplex */
			{
				status.bits.duplex = 1;
				status.bits.speed = 1;
			}
			else if ((ability & 0x04) == 0x04)		/* 100M half duplex */
			{
				status.bits.duplex = 0;
				status.bits.speed = 1;
			}
			else if ((ability & 0x02) == 0x02)		/* 10M full duplex */
			{
				status.bits.duplex = 1;
				status.bits.speed = 0;
			}
			else if ((ability & 0x01) == 0x01)		/* 10M half duplex */
			{
				status.bits.duplex = 0;
				status.bits.speed = 0;
			}
		}

		status.bits.link = LINK_UP;		/* link up */

		if (Giga_switch == 1)
		{
			wan_port_id = 1;
			storlink_ctl.link[wan_port_id] = 1;
		}
		else
		{
			storlink_ctl.link[tp->port_id] = 1;
		}

		if ((ability & 0x20) == 0x20)
		{
			if (tp->flow_control_enable == 0)
			{
				config0.bits32 = 0;
				config0_mask.bits32 = 0;
				config0.bits.tx_fc_en = 1;	/* enable tx flow control */
				config0.bits.rx_fc_en = 1;	/* enable rx flow control */
				config0_mask.bits.tx_fc_en = 1;
				config0_mask.bits.rx_fc_en = 1;
				gmac_write_reg(tp->base_addr, GMAC_CONFIG0, config0.bits32, config0_mask.bits32);
				printk("GMAC-%d Flow Control Enable.\n", tp->port_id);
			}
			tp->flow_control_enable = 1;
		}
		else
		{
			if (tp->flow_control_enable == 1)
			{
				config0.bits32 = 0;
				config0_mask.bits32 = 0;
				config0.bits.tx_fc_en = 0;	/* disable tx flow control */
				config0.bits.rx_fc_en = 0;	/* disable rx flow control */
				config0_mask.bits.tx_fc_en = 1;
				config0_mask.bits.rx_fc_en = 1;
				gmac_write_reg(tp->base_addr, GMAC_CONFIG0, config0.bits32, config0_mask.bits32);
				printk("GMAC-%d Flow Control Disable.\n", tp->port_id);
			}
			tp->flow_control_enable = 0;
		}

		if (tp->pre_phy_status == LINK_DOWN)
		{
			printk("GMAC-%d LINK_UP......\n", tp->port_id);
			tp->pre_phy_status = LINK_UP;
			netif_carrier_on(dev);
		}
	}
	else	/* link down or auto negotiate not complete yet. */
	{
 #ifdef PHY_WORKAROUND
		re_poll_counter--;
		if (re_poll_counter == 0)
			goto phy_status_down;
		else
			goto phy_status;

phy_status_down:	
 #endif

		status.bits.link = LINK_DOWN;	/* link down */
		if (Giga_switch == 1)
		{
			wan_port_id = 1;
			storlink_ctl.link[ wan_port_id] = 0;
		}
		else
		{
			storlink_ctl.link[ tp->port_id] = 0;
		}
		if (tp->pre_phy_status == LINK_UP)
		{
			printk("GMAC-%d LINK_Down......\n",tp->port_id);
			tp->pre_phy_status = LINK_DOWN;
			netif_carrier_off(dev);
		}
	}

	tp->full_duplex_status = status.bits.duplex;
	tp->speed_status = status.bits.speed;
	if (!tp->auto_nego_cfg)
	{
		status.bits.duplex = tp->full_duplex_cfg;
		status.bits.speed = tp->speed_cfg;
	}

//	/* According GUI teams request,link status become ture */
//	if (Giga_switch || Tantos_switch) {
//		wan_port_id = 1;
//		storlink_ctl.link[ wan_port_id] = 1;
//	} else {
//		storlink_ctl.link[ tp->port_id] = 1;
//	}

//printk("old_status.bits32=%x status.bits32=%x \n", old_status.bits32, status.bits32);
	if (old_status.bits32 != status.bits32)
	{
		netif_stop_queue(dev);
		toe_gmac_disable_tx_rx(dev);
		clear_bit(__LINK_STATE_START, &dev->state);

		printk("GMAC-%d Change Status Bits 0x%x-->0x%x\n", tp->port_id, old_status.bits32, status.bits32);
		mdelay(10);		/* let GMAC consume packet */

		gmac_write_reg(tp->base_addr, GMAC_STATUS, status.bits32, 0x0000007f);

		if (status.bits.link == LINK_UP)
		{
			toe_gmac_enable_tx_rx(dev);
			netif_wake_queue(dev);
			set_bit(__LINK_STATE_START, &dev->state);
		}
	}
}

/***************************************/
/* define GPIO module base address     */
/***************************************/
#define GPIO_BASE_ADDR  (IO_ADDRESS(SL2312_GPIO_BASE))
#define GPIO_BASE_ADDR1  (IO_ADDRESS(SL2312_GPIO_BASE1))

/* define GPIO pin for MDC/MDIO */
#ifdef CONFIG_SL3516_ASIC

#define H_MDC_PIN           21
#define H_MDIO_PIN          22
#define G_MDC_PIN           21
#define G_MDIO_PIN          22

#define H_MDC_PIN_c         21	/* 3516A3 Vitess */
#define H_MDIO_PIN_c        22	/* 3516A3 Vitess */
#define G_MDC_PIN_c         21	/* 3516A3 Vitess */
#define G_MDIO_PIN_c        22	/* 3516A3 Vitess */

#endif	//CONFIG_SL3516_ASIC

//#define GPIO_MDC             0x80000000
//#define GPIO_MDIO            0x00400000

static uint32_t GPIO_MDC = 0;
static uint32_t GPIO_MDIO = 0;
static uint32_t GPIO_MDC_PIN = 0;
static uint32_t GPIO_MDIO_PIN = 0;

/* For PHY test definition!! */
#define LPC_EECK		0x02
#define LPC_EDIO		0x04
#define LPC_GPIO_SET		3
#define LPC_BASE_ADDR		IO_ADDRESS(IT8712_IO_BASE)
#define inb_gpio(x)		inb(LPC_BASE_ADDR + IT8712_GPIO_BASE + x)
#define outb_gpio(x, y)		outb(y, LPC_BASE_ADDR + IT8712_GPIO_BASE + x)

enum GPIO_REG
{
    GPIO_DATA_OUT   = 0x00,
    GPIO_DATA_IN    = 0x04,
    GPIO_PIN_DIR    = 0x08,
    GPIO_BY_PASS    = 0x0c,
    GPIO_DATA_SET   = 0x10,
    GPIO_DATA_CLEAR = 0x14,
};
/***********************/
/*    MDC : GPIO[31]   */
/*    MDIO: GPIO[22]   */
/***********************/

/***************************************************
 * All the commands should have the frame structure:
 *<PRE><ST><OP><PHYAD><REGAD><TA><DATA><IDLE>
 ****************************************************/

/*****************************************************************
 * Inject a bit to NWay register through CSR9_MDC,MDIO
 * write data into mii PHY
 *****************************************************************/
void mii_serial_write(char bit_MDO)
{
#ifdef CONFIG_SL2312_LPC_IT8712
	unsigned char iomode,status;

	iomode = LPCGetConfig(LDN_GPIO, 0xc8 + LPC_GPIO_SET);
	iomode |= (LPC_EECK|LPC_EDIO) ;				/* Set EECK,EDIO,EECS output */
	LPCSetConfig(LDN_GPIO, 0xc8 + LPC_GPIO_SET, iomode);

	if (bit_MDO) {
		status = inb_gpio( LPC_GPIO_SET);
		status |= LPC_EDIO ;		/* EDIO high */
		outb_gpio(LPC_GPIO_SET, status);
	} else {
		status = inb_gpio( LPC_GPIO_SET);
		status &= ~(LPC_EDIO) ;		/* EDIO low */
		outb_gpio(LPC_GPIO_SET, status);
	}

	status |= LPC_EECK ;		/* EECK high */
	outb_gpio(LPC_GPIO_SET, status);

	status &= ~(LPC_EECK) ;		/* EECK low */
	outb_gpio(LPC_GPIO_SET, status);
#else
	uint32_t addr;
	uint32_t value;

	addr = GPIO_BASE_ADDR + GPIO_PIN_DIR;
	/* set MDC/MDIO Pin to output */
	value = readl(addr) | GPIO_MDC | GPIO_MDIO;
	writel(value,addr);
	if (bit_MDO) {
		addr = (GPIO_BASE_ADDR + GPIO_DATA_SET);
		writel(GPIO_MDIO, addr);		/* set MDIO to 1 */

		addr = (GPIO_BASE_ADDR + GPIO_DATA_SET);
		writel(GPIO_MDC, addr);		/* set MDC to 1 */

		addr = (GPIO_BASE_ADDR + GPIO_DATA_CLEAR);
		writel(GPIO_MDC, addr);		/* set MDC to 0 */
	} else {
		addr = (GPIO_BASE_ADDR + GPIO_DATA_CLEAR);
		writel(GPIO_MDIO,addr);		/* set MDIO to 0 */

		addr = (GPIO_BASE_ADDR + GPIO_DATA_SET);
		writel(GPIO_MDC,addr);		/* set MDC to 1 */

		addr = (GPIO_BASE_ADDR + GPIO_DATA_CLEAR);
		writel(GPIO_MDC,addr);		/* set MDC to 0 */
	}
#endif
}

/**********************************************************************
 * read a bit from NWay register through CSR9_MDC,MDIO
 * read data from mii PHY
 *********************************************************************/
uint32_t mii_serial_read(void)
{
#ifdef CONFIG_SL2312_LPC_IT8712
	unsigned char iomode,status;
	uint32_t value ;

	iomode = LPCGetConfig(LDN_GPIO, 0xc8 + LPC_GPIO_SET);
	iomode &= ~(LPC_EDIO);		/* Set EDIO input */
	iomode |= (LPC_EECK);		/* Set EECK,EECS output */
	LPCSetConfig(LDN_GPIO, 0xc8 + LPC_GPIO_SET, iomode);

	status = inb_gpio( LPC_GPIO_SET);
	status |= LPC_EECK ;		/* EECK high */
	outb_gpio(LPC_GPIO_SET, status);

	status &= ~(LPC_EECK);		/* EECK low */
	outb_gpio(LPC_GPIO_SET, status);

	value = inb_gpio(LPC_GPIO_SET);

	value = value>>2;
	value &= 0x01;

	return value;
#else
	uint32_t *addr;
	uint32_t value;

	addr = (uint32_t *)(GPIO_BASE_ADDR + GPIO_PIN_DIR);

	/* set MDC to output and MDIO to input */
	value = readl(addr) & ~GPIO_MDIO; /* 0xffbfffff; */
	writel(value, addr);

	addr = (uint32_t *)(GPIO_BASE_ADDR + GPIO_DATA_SET);
	writel(GPIO_MDC, addr); /* set MDC to 1 */

	addr = (uint32_t *)(GPIO_BASE_ADDR + GPIO_DATA_CLEAR);
	writel(GPIO_MDC,addr); /* set MDC to 0 */

	addr = (uint32_t *)(GPIO_BASE_ADDR + GPIO_DATA_IN);
	value = readl(addr);
	value = (value & (1<<GPIO_MDIO_PIN)) >> GPIO_MDIO_PIN;

	return(value);
#endif
}

/***************************************
* preamble + ST
***************************************/
void mii_pre_st(void)
{
	unsigned char i;

	for(i=0; i<32; i++)		/* PREAMBLE */
		mii_serial_write(1);
	mii_serial_write(0);	/* ST */
	mii_serial_write(1);
}
 
/******************************************
* Read MII register
* phyad -> physical address
* regad -> register address
***************************************** */
uint32_t
mii_read(unsigned char phyad,unsigned char regad)
{
	uint32_t i,value;
	uint32_t bit;

	local_irq_disable();


	if (c_GPIO)
	{
		if (phyad == GPHY_ADDR)
		{
			GPIO_MDC_PIN  = G_MDC_PIN_c;			/* assigned MDC pin for giga PHY */
			GPIO_MDIO_PIN = G_MDIO_PIN_c;			/* assigned MDIO pin for giga PHY */
		}
		else
		{
			GPIO_MDC_PIN  = H_MDC_PIN_c;			/* assigned MDC pin for 10/100 PHY */
			GPIO_MDIO_PIN = H_MDIO_PIN_c;			/* assigned MDIO pin for 10/100 PHY */
		}
	}
	else
	{
		if (phyad == GPHY_ADDR)
		{
			GPIO_MDC_PIN  = G_MDC_PIN;				/* assigned MDC pin for giga PHY */
			GPIO_MDIO_PIN = G_MDIO_PIN;				/* assigned MDIO pin for giga PHY */
		}
		else			// ASTEL
		{
			GPIO_MDC_PIN  = H_MDC_PIN;				/* assigned MDC pin for 10/100 PHY */
			GPIO_MDIO_PIN = H_MDIO_PIN;				/* assigned MDIO pin for 10/100 PHY */
		}
	}

	GPIO_MDC  = (1<<GPIO_MDC_PIN);
	GPIO_MDIO = (1<<GPIO_MDIO_PIN);

	mii_pre_st();				/* PRE+ST */
	mii_serial_write(1);		/* OP */
	mii_serial_write(0);

	for (i=0; i<5; i++)			/* PHYAD */
	{
		bit= ((phyad>>(4-i)) & 0x01) ? 1 : 0;
		mii_serial_write(bit);
	}

	for (i=0; i<5; i++)			/* REGAD */
	{
		bit= ((regad>>(4-i)) & 0x01) ? 1 : 0;
		mii_serial_write(bit);
	}

	mii_serial_read();			/* TA_Z */

//	mii_serial_read();			// TA_0 turn around
//	if ((bit=mii_serial_read()) !=0) {	/* TA_0 */
//		return(0);
//	}

	value = 0;
	for (i=0; i<16; i++)		/* READ DATA */
	{
		bit = mii_serial_read();
		value += (bit<<(15-i));
	}

	mii_serial_write(0);		/* dummy clock */
	mii_serial_write(0);		/* dummy clock */

	//printk("%s::phy_addr=0x%x reg_addr=0x%x value=0x%x \n", 
	//		__func__, phyad, regad, value);

//printk(" R(%x,%x:%x) ", phyad, regad, value);

	local_irq_enable();

	return(value);
}


/******************************************
* Write MII register
* phyad -> physical address
* regad -> register address
* value -> value to be write
***************************************** */
void
mii_write(unsigned char phyad,unsigned char regad,uint32_t value)
{
	uint32_t i;
	char bit;

return;		// ! __ORIGINAL__


#ifndef STORLINK_PHY
#endif

	if (c_GPIO)
	{
		if (phyad == GPHY_ADDR)
		{
			GPIO_MDC_PIN  = G_MDC_PIN_c;	/* assigned MDC pin for giga PHY */
			GPIO_MDIO_PIN = G_MDIO_PIN_c;	/* assigned MDIO pin for giga PHY */
		}
		else
		{
			GPIO_MDC_PIN  = H_MDC_PIN_c;	/* assigned MDC pin for 10/100 PHY */
			GPIO_MDIO_PIN = H_MDIO_PIN_c;	/* assigned MDIO pin for 10/100 PHY */
		}
	}
	else
	{
		if (phyad == GPHY_ADDR)
		{
			GPIO_MDC_PIN  = G_MDC_PIN;		/* assigned MDC pin for giga PHY */
			GPIO_MDIO_PIN = G_MDIO_PIN;		/* assigned MDIO pin for giga PHY */
		}
		else
		{
			GPIO_MDC_PIN  = H_MDC_PIN;		/* assigned MDC pin for 10/100 PHY */
			GPIO_MDIO_PIN = H_MDIO_PIN;		/* assigned MDIO pin for 10/100 PHY */
		}
	}

	GPIO_MDC  = (1<<GPIO_MDC_PIN);
	GPIO_MDIO = (1<<GPIO_MDIO_PIN);

	mii_pre_st();			/* PRE+ST */
	mii_serial_write(0);	/* OP */
	mii_serial_write(1);
	for (i=0; i<5; i++) {	/* PHYAD */
		bit= ((phyad>>(4-i)) & 0x01) ? 1 : 0;
		mii_serial_write(bit);
	}

	for (i=0; i<5; i++) {	/* REGAD */
		bit= ((regad>>(4-i)) & 0x01) ? 1 : 0;
		mii_serial_write(bit);
	}

	mii_serial_write(1);	/* TA_1 */
	mii_serial_write(0);	/* TA_0 */

	for (i=0; i<16; i++) {	/* OUT DATA */
		bit = ((value>>(15-i)) & 0x01) ? 1 : 0;
		mii_serial_write(bit);
	}
	mii_serial_write(0);	/* dumy clock */
	mii_serial_write(0);	/* dumy clock */
}

EXPORT_SYMBOL(mii_read);
EXPORT_SYMBOL(mii_write);

/*----------------------------------------------------------------------
* gmac_set_rx_mode
*----------------------------------------------------------------------*/
static void gmac_set_rx_mode(struct net_device *dev)
{
	GMAC_RX_FLTR_T      filter;
	uint32_t        mc_filter[2];	/* Multicast hash filter */
	int                 bit_nr;
	uint32_t        i;
	GMAC_INFO_T 		*tp = dev->priv;

//	printk("%s : dev->flags = %x \n",__func__,dev->flags);
//	dev->flags |= IFF_ALLMULTI;  /* temp */
	filter.bits32 = 0;
	filter.bits.error = 0;
	if (dev->flags & IFF_PROMISC) {
		filter.bits.error = 1;
		filter.bits.promiscuous = 1;
		filter.bits.broadcast = 1;
		filter.bits.multicast = 1;
		filter.bits.unicast = 1;
		mc_filter[1] = mc_filter[0] = 0xffffffff;
	} else if (dev->flags & IFF_ALLMULTI) {
//		filter.bits.promiscuous = 1;
		filter.bits.broadcast = 1;
		filter.bits.multicast = 1;
		filter.bits.unicast = 1;
		mc_filter[1] = mc_filter[0] = 0xffffffff;
	} else {
		struct dev_mc_list *mclist;
//		filter.bits.promiscuous = 1;
		filter.bits.broadcast = 1;
		filter.bits.multicast = 1;
		filter.bits.unicast = 1;
		mc_filter[1] = mc_filter[0] = 0;
		for (i = 0, mclist = dev->mc_list; mclist && i < dev->mc_count; 
				i++, mclist = mclist->next) {
			bit_nr = ether_crc(ETH_ALEN,mclist->dmi_addr) & 0x0000003f;
			if (bit_nr < 32) {
					mc_filter[0] = mc_filter[0] | (1<<bit_nr);
			} else {
					mc_filter[1] = mc_filter[1] | (1<<(bit_nr-32));
			}
		}
	}
	gmac_write_reg(tp->base_addr,GMAC_RX_FLTR,filter.bits32,0xffffffff);
//	gmac_write_reg(tp->base_addr,GMAC_MCAST_FIL0,mc_filter[0],0xffffffff);
//	gmac_write_reg(tp->base_addr,GMAC_MCAST_FIL1,mc_filter[1],0xffffffff);
	return;
}

#ifdef CONFIG_SL_NAPI
/*----------------------------------------------------------------------
* gmac_rx_poll
*----------------------------------------------------------------------*/
static inline int gmac_rx_poll(struct net_device *dev, int *budget) 
{ 
	TOE_INFO_T *toe;
	GMAC_RXDESC_T *curr_desc;
	struct sk_buff *skb;
	DMA_RWPTR_T rwptr;
	uint32_t pkt_size, desc_count, good_frame, chksum_status, rx_status;
	int rx_pkts_num = 0, max_pkts_num;
	int quota = min(dev->quota, *budget);
	int real_quota = quota;
	GMAC_INFO_T *tp = (GMAC_INFO_T *)dev->priv;
	unsigned long flags;
#ifdef CONFIG_SL351x_NAT
	struct iphdr *ip_hdr;
#endif

	if (((tp->port_id == 0) && (tp->poll_bits & DEFAULT_Q0_INT_BIT)) ||
			((tp->port_id == 1) && (tp->poll_bits & DEFAULT_Q1_INT_BIT))) {
		struct net_device_stats *isPtr = (struct net_device_stats *)&tp->ifStatics;

		rwptr.bits32 = readl(&tp->default_qhdr->word1);
#if 0
		if (rwptr.bits.rptr != tp->rx_rwptr.bits.rptr) { 
			mac_stop_txdma((struct net_device *)tp->dev);
			printk("Default Queue HW RD ptr (0x%x) != SW RD Ptr (0x%x)\n",
					rwptr.bits32, tp->rx_rwptr.bits.rptr);
			while(1);
		}
#endif
		toe = (TOE_INFO_T *)&toe_private_data;

		while ((rwptr.bits.rptr != rwptr.bits.wptr) && (rx_pkts_num < quota)) {
			curr_desc = (GMAC_RXDESC_T *)tp->default_desc_base + rwptr.bits.rptr;
#ifdef GMAC_DEBUG
			tp->default_q_cnt++;
#endif
			tp->rx_curr_desc = (uint32_t)curr_desc;
			rx_status = curr_desc->word0.bits.status;
			chksum_status = curr_desc->word0.bits.chksum_status;
#ifdef GMAC_DEBUG
			tp->rx_status_cnt[rx_status]++;
			tp->rx_chksum_cnt[chksum_status]++;
#endif
			/*total byte count in a frame*/
			pkt_size = curr_desc->word1.bits.byte_count;
			/* get descriptor count per frame */
			desc_count = curr_desc->word0.bits.desc_count;
			good_frame=1;
			if ((curr_desc->word0.bits32 & (GMAC_RXDESC_0_T_derr | GMAC_RXDESC_0_T_perr))
					|| (pkt_size < 60)
					|| (chksum_status & 0x4)
					|| rx_status ) {

				good_frame = 0;
#ifdef GMAC_DEBUG
				if (curr_desc->word0.bits32 & GMAC_RXDESC_0_T_derr)
					printk("%s::derr (GMAC-%d)!!!\n", __func__, tp->port_id);
				if (curr_desc->word0.bits32 & GMAC_RXDESC_0_T_perr)
					printk("%s::perr (GMAC-%d)!!!\n", __func__, tp->port_id);
#endif
				if (rx_status != 0) {
					if (rx_status == 4 || rx_status == 7)
						isPtr->rx_crc_errors++;
#ifdef GMAC_DEBUG
					printk("%s::Status=%d (GMAC-%d)!!!\n", __func__, rx_status, tp->port_id);
#endif
				}
#ifdef GMAC_DEBUG
				if (chksum_status)
					printk("%s::Checksum Status=%d (GMAC-%d)!!!\n", __func__,
							chksum_status, tp->port_id);
#endif
				skb = (struct sk_buff *)(REG32(__va(curr_desc->word2.buf_adr) - SKB_RESERVE_BYTES));
				dev_kfree_skb_any(skb);
			}
			if (good_frame) {
#ifdef GMAC_DEBUG
				if (curr_desc->word0.bits.drop)
					printk("%s::Drop (GMAC-%d)!!!\n", __func__, tp->port_id);
				if (chksum_status)
					printk("%s::Checksum Status=%d (GMAC-%d)!!!\n", __func__,
							chksum_status, tp->port_id);
#endif
				/* get frame information from the first descriptor of the frame */
				isPtr->rx_packets++;
				//consistent_sync((void *)__va(curr_desc->word2.buf_adr),
				//		pkt_size, PCI_DMA_FROMDEVICE);
				skb = (struct sk_buff *)(REG32(__va(curr_desc->word2.buf_adr)
										- SKB_RESERVE_BYTES));
				tp->curr_rx_skb = skb;
		//		curr_desc->word2.buf_adr = 0;
				/* 2 byte align the IP fields. */
				skb_reserve (skb, RX_INSERT_BYTES);
#ifdef GMAC_DEBUG
				if ((skb->tail+pkt_size) > skb->end) {
					printk("%s::-->Fail skb->len=%d," __func__, skb->len);
					printk("pkt_size= %d,skb->head=0x%x,", pkt_size, skb->head);
					printk("skb->tail= 0x%x, skb->end= 0x%x\n", skb->tail, skb->end);
				}
#endif
				skb_put(skb, pkt_size);
				skb->dev = dev;
				if (chksum_status == RX_CHKSUM_IP_UDP_TCP_OK) {
					skb->ip_summed = CHECKSUM_UNNECESSARY;
#ifdef CONFIG_SL351x_NAT
					if (nat_cfg.enabled
							&& curr_desc->word3.bits.l3_offset
							&& curr_desc->word3.bits.l4_offset) {
						sl351x_nat_input(skb, tp->port_id,
								(void *)curr_desc->word3.bits.l3_offset,
					  			(void *)curr_desc->word3.bits.l4_offset);
					}
#endif
#ifdef CONFIG_SL351X_BR
					sl351x_br_input(skb,tp->port_id);
#endif
				} else if (chksum_status == RX_CHKSUM_IP_OK_ONLY) {
					skb->ip_summed = CHECKSUM_UNNECESSARY;
#ifdef CONFIG_SL351x_NAT
					if (nat_cfg.enabled && curr_desc->word3.bits.l3_offset
							&& curr_desc->word3.bits.l4_offset) {
						ip_hdr = (struct iphdr *)&(skb->data[curr_desc->word3.bits.l3_offset]);
						if ((ip_hdr->protocol == IPPROTO_UDP)
								|| (ip_hdr->protocol == IPPROTO_GRE)) {
							sl351x_nat_input(skb, tp->port_id,
									(void *)curr_desc->word3.bits.l3_offset,
									(void *)curr_desc->word3.bits.l4_offset);
						}
					}
#endif
#ifdef CONFIG_SL351X_BR
					sl351x_br_input(skb,tp->port_id);
#endif
				} else {
#ifdef CONFIG_SL351X_BR
					sl351x_br_input(skb,tp->port_id);
#endif
				}
				skb->protocol = eth_type_trans(skb,dev); /* set skb protocol */
				netif_receive_skb(skb);	/* socket rx for NAPI */

				dev->last_rx = jiffies;
				isPtr->rx_bytes += pkt_size;
			}
			/* advance one for Rx default Q 0/1 */
			rwptr.bits.rptr = RWPTR_ADVANCE_ONE(rwptr.bits.rptr, tp->default_desc_num);
			SET_RPTR(&tp->default_qhdr->word1, rwptr.bits.rptr);
			tp->rx_rwptr.bits32 = rwptr.bits32;
			rx_pkts_num++;
			//toe_gmac_fill_free_q();
		}
		quota = real_quota - rx_pkts_num;
	} 
	max_pkts_num = rx_pkts_num;

	toe_gmac_fill_free_q();

	dev->quota -= max_pkts_num;
	*budget -= max_pkts_num;

	//if (rwptr.bits.rptr == rwptr.bits.wptr)
	if (max_pkts_num == 0) {
		uint32_t data32;

		/* Receive descriptor is empty now */
		netif_rx_complete(dev);
		local_irq_save(flags);

		/* enable GMAC-0 rx interrupt
		 * class-Q & TOE-Q are implemented in future
		 */
		data32 = readl(TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);
		if (tp->port_id == 0) {
//			if (Giga_switch == 1) {
				data32 |= DEFAULT_Q0_INT_BIT;
				tp->poll_bits &= ~DEFAULT_Q0_INT_BIT;
#endif
//			} else {
//				data32 |= DEFAULT_Q0_INT_BIT;
//				tp->poll_bits &= ~DEFAULT_Q0_INT_BIT;
//			}
		} else {
//			if (Giga_switch == 1) {
				data32 |= DEFAULT_Q1_INT_BIT;
				tp->poll_bits &= ~DEFAULT_Q1_INT_BIT;
//			} else {
//				data32 |= DEFAULT_Q1_INT_BIT;
//				tp->poll_bits &= ~DEFAULT_Q1_INT_BIT;
//			}
		}
		writel(data32, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_ENABLE_1_REG);

		local_irq_restore(flags);
		return 0;
	} else {
		return 1;
	}   
}

/*----------------------------------------------------------------------
* gmac_tx_timeout
*----------------------------------------------------------------------*/
void gmac_tx_timeout(struct net_device *dev)
{
	GMAC_INFO_T *tp = (GMAC_INFO_T *)dev->priv;

	printk(KERN_INFO "%s: TX timeout", dev->name);
	schedule_work(&tp->tx_timeout_task);

#if 0
	if (tp->operation && storlink_ctl.link[tp->port_id]) {
		netif_wake_queue(dev);
	}
#endif
}

/*----------------------------------------------------------------------
* gmac_change_mtu -- Change the Maximum Transfer Unit
* @netdev: network interface device structure
* @new_mtu: new value for maximum frame size
*
* Returns 0 on success, negative on failure
*----------------------------------------------------------------------*/
static int gmac_change_mtu(struct net_device *dev, int new_mtu)
{
	GMAC_INFO_T		*tp = (GMAC_INFO_T *)dev->priv;
	int max_frame = new_mtu + ENET_HEADER_SIZE + ETHERNET_FCS_SIZE;
	GMAC_STATUS_T	status, old_status;

	old_status.bits32 = status.bits32 = gmac_read_reg(tp->base_addr, GMAC_STATUS);

	if ((max_frame < MINIMUM_ETHERNET_FRAME_SIZE)
			|| (max_frame > MAX_JUMBO_FRAME_SIZE)) {
		printk("Invalid MTU setting\n");
		return -EINVAL;
	}

	dev->mtu = new_mtu;
	if (new_mtu > 1500) {
		printk("GMAC-%d MTU must <= 1500 \n", tp->port_id);
		return -EINVAL;
	} else {
		printk("GMAC-%d Change MTU = %d\n", tp->port_id, new_mtu);
	}
	if (!netif_running(dev))
		goto out;

	if (gmac_close(dev))
		printk(KERN_ERR "%s: Fatal error on stopping device\n", dev->name);

	if (gmac_open(dev))
		printk(KERN_ERR "%s: Fatal error on opening device\n", dev->name);		
out:
	return 0;
}

/*----------------------------------------------------------------------
* mac_set_rule_reg
*----------------------------------------------------------------------*/
int mac_set_rule_reg(int mac, int rule, int enabled, u32 reg0, u32 reg1, u32 reg2)
{
	int total_key_dwords;

	total_key_dwords = 1;

	if (reg0 & MR_L2_BIT) {
		if (reg0 & MR_DA_BIT) total_key_dwords += 2;
		if (reg0 & MR_SA_BIT) total_key_dwords += 2;
		if ((reg0 & MR_DA_BIT) && ( reg0 & MR_SA_BIT)) total_key_dwords--;
		if (reg0 & (MR_PPPOE_BIT | MR_VLAN_BIT)) total_key_dwords++;
	}
	if (reg0 & MR_L3_BIT) {
		if (reg0 & (MR_IP_HDR_LEN_BIT | MR_TOS_TRAFFIC_BIT | MR_SPR_BITS))
			total_key_dwords++;
		if (reg0 & MR_FLOW_LABLE_BIT) total_key_dwords++;
		if ((reg0 & MR_IP_VER_BIT) == 0) {	/* IPv4 */
			if (reg1 & 0xff000000) total_key_dwords += 1;
			if (reg1 & 0x00ff0000) total_key_dwords += 1;
		} else {
			if (reg1 & 0xff000000) total_key_dwords += 4;
			if (reg1 & 0x00ff0000) total_key_dwords += 4;
		}
	}
	if (reg0 & MR_L4_BIT) {
		if (reg1 & 0x0000f000) total_key_dwords += 1;
		if (reg1 & 0x00000f00) total_key_dwords += 1;
		if (reg1 & 0x000000f0) total_key_dwords += 1;
		if (reg1 & 0x0000000f) total_key_dwords += 1;
		if (reg2 & 0xf0000000) total_key_dwords += 1;
		if (reg2 & 0x0f000000) total_key_dwords += 1;
	}
	if (reg0 & MR_L7_BIT) {
		if (reg2 & 0x00f00000) total_key_dwords += 1;
		if (reg2 & 0x000f0000) total_key_dwords += 1;
		if (reg2 & 0x0000f000) total_key_dwords += 1;
		if (reg2 & 0x00000f00) total_key_dwords += 1;
		if (reg2 & 0x000000f0) total_key_dwords += 1;
		if (reg2 & 0x0000000f) total_key_dwords += 1;
	}

	if (total_key_dwords > HASH_MAX_KEY_DWORD)
		return -1;

	if (total_key_dwords == 0 && enabled)
		return -2;

	mac_set_rule_enable_bit(mac, rule, 0);
	if (enabled) {
		mac_set_MRxCRx(mac, rule, 0, reg0);
		mac_set_MRxCRx(mac, rule, 1, reg1);
		mac_set_MRxCRx(mac, rule, 2, reg2);
		mac_set_rule_action(mac, rule, total_key_dwords);
		mac_set_rule_enable_bit(mac, rule, enabled);
	} else {
		mac_set_rule_action(mac, rule, 0);
	}
	return total_key_dwords;
}

/*----------------------------------------------------------------------
* mac_get_rule_enable_bit
*----------------------------------------------------------------------*/
int mac_get_rule_enable_bit(int mac, int rule)
{
	switch (rule)
	{
		case 0:
			return ((mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG0) >> 15) & 1);
		case 1:
			return ((mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG0) >> 31) & 1);
		case 2:
			return ((mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG1) >> 15) & 1);
		case 3:
			return ((mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG1) >> 31) & 1);
		default:
			return 0;
	}
}

/*----------------------------------------------------------------------
* mac_set_rule_enable_bit
*----------------------------------------------------------------------*/
void mac_set_rule_enable_bit(int mac, int rule, int data)
{
	u32 reg;
	
	if (data & ~1) return;
		
	switch (rule)
	{
		case 0:
			reg = (mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG0) & ~(1<<15))
					| (data << 15);
			mac_write_dma_reg(mac, GMAC_HASH_ENGINE_REG0, reg);
			break;
		case 1:
			reg = (mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG0) & ~(1<<31))
					| (data << 31);
			mac_write_dma_reg(mac, GMAC_HASH_ENGINE_REG0, reg);
			break;
		case 2:
			reg = (mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG1) & ~(1<<15))
					| (data << 15);
			mac_write_dma_reg(mac, GMAC_HASH_ENGINE_REG1, reg);
			break;
		case 3:
			reg = (mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG1) & ~(1<<31))
					| (data << 31);
			mac_write_dma_reg(mac, GMAC_HASH_ENGINE_REG1, reg);
	}
}

/*----------------------------------------------------------------------
* mac_set_rule_action
*----------------------------------------------------------------------*/
int mac_set_rule_action(int mac, int rule, int data)
{
	u32 reg;
	
	if (data > 32) return -1;
	
	if (data)
		data = (data << 6) | (data + HASH_ACTION_DWORDS); 
	switch (rule)
	{
		case 0: 
			reg = (mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG0) & ~(0x7ff));
			mac_write_dma_reg(mac, GMAC_HASH_ENGINE_REG0, reg | data);
			break;
		case 1:
			reg = (mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG0) & ~(0x7ff<<16));
			mac_write_dma_reg(mac, GMAC_HASH_ENGINE_REG0, reg | (data << 16));
			break;
		case 2:
			reg = (mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG1) & ~(0x7ff));
			mac_write_dma_reg(mac, GMAC_HASH_ENGINE_REG1,  reg | data);
			break;
		case 3:
			reg = (mac_read_dma_reg(mac, GMAC_HASH_ENGINE_REG1) & ~(0x7ff<<16));
			mac_write_dma_reg(mac, GMAC_HASH_ENGINE_REG1, reg | (data << 16));
			break;
		default:
			return -1;
	}

	return 0;
}
/*----------------------------------------------------------------------
* mac_get_MRxCRx
*----------------------------------------------------------------------*/
int mac_get_MRxCRx(int mac, int rule, int ctrlreg)
{
	int reg;

	switch (rule)
	{
		case 0: reg = GMAC_MR0CR0 + ctrlreg * 4; break;
		case 1: reg = GMAC_MR1CR0 + ctrlreg * 4; break;
		case 2: reg = GMAC_MR2CR0 + ctrlreg * 4; break;
		case 3: reg = GMAC_MR3CR0 + ctrlreg * 4; break;
		default: return 0;
	}
	return mac_read_dma_reg(mac, reg);
}

/*----------------------------------------------------------------------
* mac_set_MRxCRx
*----------------------------------------------------------------------*/
void mac_set_MRxCRx(int mac, int rule, int ctrlreg, u32 data)
{
	int reg;

	switch (rule)
	{
		case 0: reg = GMAC_MR0CR0 + ctrlreg * 4; break;
		case 1: reg = GMAC_MR1CR0 + ctrlreg * 4; break;
		case 2: reg = GMAC_MR2CR0 + ctrlreg * 4; break;
		case 3: reg = GMAC_MR3CR0 + ctrlreg * 4; break;
		default: return;
	}
	mac_write_dma_reg(mac, reg, data);
}

/*----------------------------------------------------------------------
* mac_set_rule_priority
*----------------------------------------------------------------------*/
void mac_set_rule_priority(int mac, int p0, int p1, int p2, int p3)
{
	int 			i;
	GMAC_MRxCR0_T	reg[4];

	for (i=0; i<4; i++)
		reg[i].bits32 = mac_get_MRxCRx(mac, i, 0);

	reg[0].bits.priority = p0;
	reg[1].bits.priority = p1;
	reg[2].bits.priority = p2;
	reg[3].bits.priority = p3;

	for (i=0; i<4; i++)
		mac_set_MRxCRx(mac, i, 0, reg[i].bits32);
}

/*----------------------------------------------------------------------
* gmac_netdev_ioctl
*----------------------------------------------------------------------*/
static int gmac_netdev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	int 				rc = 0;
	unsigned char		*hwa = rq->ifr_ifru.ifru_hwaddr.sa_data;

#ifdef br_if_ioctl
	struct ethtool_cmd	ecmd;	/* br_if.c will call this ioctl */
	GMAC_INFO_T 		*tp = dev->priv;
#endif

#ifdef 	CONFIG_SL351x_NAT
	if (cmd == SIOCDEVSL351x)
		return sl351x_nat_ioctl(dev, rq, cmd);
#else
	if (cmd == SIOCDEVSL351x) {
		return sl351x_gmac_ioctl(dev, rq, cmd);
	}
#endif

#ifndef CONFIG_BONDING_MODULE
	if (!netif_running(dev)) {
	    printk("Before changing the H/W address,please down the device.\n");
		return -EINVAL;
    }
#endif //CONFIG_BONDING_MODULE

	switch (cmd) {
		case SIOCETHTOOL:
#ifdef br_if_ioctl	/* br_if.c will call this ioctl */
			memset((void *) &ecmd, 0, sizeof (ecmd));
			ecmd.supported =
                		SUPPORTED_Autoneg | SUPPORTED_TP | SUPPORTED_MII |
				SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full |
				SUPPORTED_100baseT_Half | SUPPORTED_100baseT_Full;
			ecmd.port = PORT_TP;
			ecmd.transceiver = XCVR_EXTERNAL;
			ecmd.phy_address = tp->phy_addr;
			switch (tp->speed_status) {
				case GMAC_SPEED_10: ecmd.speed = SPEED_10; break;
				case GMAC_SPEED_100: ecmd.speed = SPEED_100; break;
				case GMAC_SPEED_1000: ecmd.speed = SPEED_1000; break;
				default: ecmd.speed = SPEED_10; break;
			}
			ecmd.duplex = tp->full_duplex_status ? DUPLEX_FULL : DUPLEX_HALF;
			ecmd.advertising = ADVERTISED_TP;
			ecmd.advertising |= ADVERTISED_Autoneg;
			ecmd.autoneg = AUTONEG_ENABLE;
			if (copy_to_user(rq->ifr_data, &ecmd, sizeof (ecmd)))
				return -EFAULT;
#endif

			break;

		case SIOCSIFHWADDR:
			gmac_set_mac_address(dev,hwa);
			break;

		case SIOCGMIIPHY:	/* Get the address of the PHY in use. */
			break;

		case SIOCGMIIREG:	/* Read the specified MII register. */
			break;

		case SIOCSMIIREG:	/* Write the specified MII register */
			break;

		default:
			rc = -EOPNOTSUPP;
			break;
	}

	return rc;
}

/*----------------------------------------------------------------------
* dm_long_1
*	gmac read mem -b 0xc1ff4740 -l 8 -4
*	
*	0xc1ff4740: E5D24001 E5D21004 - E59D302C E1A05000 
*	0xc1ff4750: E5D20005 E0643003 - E1A05435 E1814400 
*----------------------------------------------------------------------*/
void dm_long_1(u32 location, int length)
{
	u32		*start_p, *curr_p, *end_p;
	u32		*datap, data;
	int		i;
		
	start_p = (u32 *)location;
	end_p = (u32 *)location + length;
	curr_p = (u32 *)((u32)location & 0xfffffff0);
	datap = (u32 *)location;
	while (curr_p < end_p) {
		printk("0x%08x: ",(u32)curr_p & 0xfffffff0);
		for (i=0; i<4; i++) {
			if (curr_p < start_p || curr_p >= end_p)
				printk("         ");
			else {
				data = *datap;
				printk("%08X ", data);
			}
			if (i==1) printk("- ");

			curr_p++;
			datap++;
		}
		printk("\n");
	} 
}

/*----------------------------------------------------------------------
* dm_byte
*	gmac read mem -b 0xc1ff4740 -l 64 -1
*	
*	0xc1ff4740: 01 40 D2 E5 04 10 D2 E5 - 2C 30 9D E5 00 50 A0 E1 .@......,0...P..
*	0xc1ff4750: 05 00 D2 E5 03 30 64 E0 - 35 54 A0 E1 00 44 81 E1 .....0d.5T...D..
*	0xc1ff4760: 0F 00 54 E3 04 B0 A0 91 - 2C 30 8D E5 01 60 86 92 ..T.....,0...`..
*	0xc1ff4770: 70 B9 08 95 04 80 88 92 - 20 20 8D E5 56 00 00 9A p.......  ..V...
*
*----------------------------------------------------------------------*/
void dm_byte(u32 location, int length)
{
	u8		*start_p, *end_p, *curr_p;
	u8		*datap, data;
	int		i;

	start_p = (u8 *)location;
	end_p = (u8 *)start_p + length;
	curr_p=(u8 *)((u32)location & 0xfffffff0);
	datap = (u8 *)location;

	while (curr_p < end_p) {
		u8 *p1, *p2;
		printk("0x%08x: ",(u32)curr_p & 0xfffffff0);
		p1 = curr_p;
		p2 = datap;
		/* dump data */
		for (i=0; i<16; i++) {
			if (curr_p < start_p || curr_p >= end_p)
				printk("         ");
			else {
				data = *datap;
				printk("%02X ", data);
			}
			if (i == 7) printk("- ");
			curr_p++;
			datap++;
		}
		/* dump ascii */
		curr_p = p1;
		datap = p2;
		for (i=0; i<16; i++) {
			if (curr_p < start_p || curr_p >= end_p)
				printk(".");
			else {
				data = *datap;
				if (data<0x20 || data>0x7f || data==0x25)
					printk(".");
				else printk("%c", data);;
			}
			curr_p++;
			datap++;
		}
		printk("\n");
	}
}

/*----------------------------------------------------------------------
* dm_short
*	 gmac read mem -b 0xc1ff4740 -l 24 -2
*
*	0xc1ff4740: 4001 E5D2 1004 E5D2 - 302C E59D 5000 E1A0 
*	0xc1ff4750: 0005 E5D2 3003 E064 - 5435 E1A0 4400 E181 
*	0xc1ff4760: 000F E354 B004 91A0 - 302C E58D 6001 9286 
*
*----------------------------------------------------------------------*/
void dm_short(u32 location, int length)
{
	u16		*start_p, *curr_p, *end_p;
	u16		*datap, data;
	int		i;

	start_p = (u16 *)location;
	end_p =  (u16 *)location + length;
	curr_p = (u16 *)((u32)location & 0xfffffff0);
	datap = (u16 *)location;

	while (curr_p < end_p) {
		printk("0x%08x: ",(u32)curr_p & 0xfffffff0);
		for (i=0; i<8; i++) {
			if (curr_p < start_p || curr_p >= end_p)
				printk("         ");
			else {
				data = *datap;
				printk("%04X ", data);
			}
			if (i==3) printk("- ");
			curr_p++;
			datap++;
		}
		printk("\n");
	}
}

//#ifdef SL351x_GMAC_WORKAROUND
#define GMAC_TX_STATE_OFFSET	0x60
#define GMAC_RX_STATE_OFFSET	0x64
#define GMAC_POLL_HANGED_NUM	200
#define GMAC_RX_HANGED_STATE	0x4b2000
#define GMAC_RX_HANGED_MASK		0xdff000
#define GMAC_TX_HANGED_STATE	0x34012
#define GMAC_TX_HANGED_MASK		0xfffff
#define TOE_GLOBAL_REG_SIZE		(0x78/sizeof(u32))
#define TOE_DMA_REG_SIZE		(0xd0/sizeof(u32))
#define TOE_GMAC_REG_SIZE		(0x30/sizeof(u32))
#define GMAC0_RX_HANG_BIT		(1 << 0)
#define GMAC0_TX_HANG_BIT		(1 << 1)
#define GMAC1_RX_HANG_BIT		(1 << 2)
#define GMAC1_TX_HANG_BIT		(1 << 3)

int		gmac_in_do_workaround;
#if 0
int		debug_cnt, poll_max_cnt;
#endif
u32		gmac_workaround_cnt[4];
u32		toe_global_reg[TOE_GLOBAL_REG_SIZE];
u32		toe_dma_reg[GMAC_VNUM][TOE_DMA_REG_SIZE];			/* 111228-dhsul-lt */
u32		toe_gmac_reg[GMAC_VNUM][TOE_GMAC_REG_SIZE];			/* 111228-dhsul-lt */
u32		gmac_short_frame_workaround_cnt[2];

static void sl351x_gmac_release_buffers(void);
static void sl351x_gmac_release_swtx_q(void);
static void sl351x_gmac_release_rx_q(void);
#ifdef _TOEQ_CLASSQ_READY_
static void sl351x_gmac_release_class_q(void);
static void sl351x_gmac_release_toe_q(void);
static void sl351x_gmac_release_intr_q(void);
#endif
static void sl351x_gmac_release_sw_free_q(void);
static void sl351x_gmac_release_hw_free_q(void);
#ifdef CONFIG_SL351x_NAT
static void sl351x_gmac_release_hwtx_q(void);
u32     sl351x_nat_workaround_cnt;
#endif


/*----------------------------------------------------------------------
*	gmac_reset_task()
* 	Actual routine to reset the adapter when a timeout on Tx has occurred
*----------------------------------------------------------------------*/
static void
gmac_reset_task(struct net_device *dev)
{
	int 			i;
	TOE_INFO_T		*toe;
	GMAC_INFO_T		*tp;

	volatile DMA_RWPTR_T	fq_rwptr;		// dhsul

	if (gmac_in_do_workaround)
		return;

	gmac_in_do_workaround = 1;

	printk("gmac_reset_task: start\n");		// dhsul

	toe = (TOE_INFO_T *)&toe_private_data;

	for (i=0; i<GMAC_NUM; i++)
	{
		tp = (GMAC_INFO_T *)&toe->gmac[i];

		if (tp->operation)
		{
			printk("gmac_reset_task: 1-%d\n", i);		// dhsul

			netif_stop_queue(tp->dev);
			clear_bit(__LINK_STATE_START, &tp->dev->state);
			toe_gmac_disable_interrupt(tp->irq);
			toe_gmac_disable_tx_rx(tp->dev);
			toe_gmac_hw_stop(tp->dev);

			printk("gmac_reset_task: 2-%d\n", i);		// dhsul
		}
	}

	/* clear all status bits */
	writel(0xffffffff, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_0_REG);
	writel(0xffffffff, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_1_REG);
	writel(0xffffffff, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_2_REG);
	writel(0xffffffff, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_3_REG);
	writel(0xffffffff, TOE_GLOBAL_BASE + GLOBAL_INTERRUPT_STATUS_4_REG);

	fq_rwptr.bits32 = readl(TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);		// dhsul

	if (fq_rwptr.bits.wptr != 0 || fq_rwptr.bits.rptr != 0)					// dhsul
	{
		sl351x_gmac_release_buffers();
		sl351x_gmac_save_reg();
	}

	toe_gmac_sw_reset();
	sl351x_gmac_restore_reg();

	if (toe->gmac[0].default_qhdr->word1.bits32)
	{
		printk("gmac_reset_task: 3\n");		// dhsul

		sl351x_gmac_release_rx_q();
		writel(0, &toe->gmac[0].default_qhdr->word1);

		printk("gmac_reset_task: 4\n");		// dhsul
	}

	if (toe->gmac[1].default_qhdr->word1.bits32)
	{
		printk("gmac_reset_task: 5\n");		// dhsul

		sl351x_gmac_release_rx_q();
		writel(0, &toe->gmac[1].default_qhdr->word1);

		printk("gmac_reset_task: 6\n");		// dhsul
	}

	gmac_initialized = 1;

	for (i=0; i<GMAC_NUM; i++)
	{
		tp = (GMAC_INFO_T *)&toe->gmac[i];
 		if (tp->operation)
		{
			printk("gmac_reset_task: 7-%d\n", i);		// dhsul

			toe_gmac_enable_interrupt(tp->irq);
			toe_gmac_hw_start(tp->dev);
			toe_gmac_enable_tx_rx(tp->dev);
			netif_wake_queue(tp->dev);
			set_bit(__LINK_STATE_START, &tp->dev->state);

			printk("gmac_reset_task: 8-%d\n", i);		// dhsul
		}
	}

	printk("gmac_reset_task: done\n");		// dhsul

	gmac_in_do_workaround = 0;
}

/*----------------------------------------------------------------------
*	get_free_desc_cnt
*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
* 	sl351x_gmac_release_buffers
*----------------------------------------------------------------------*/
static void sl351x_gmac_release_buffers(void)
{
	/* Free buffers & Descriptors in all SW Tx Queues */
	sl351x_gmac_release_swtx_q();

	/* Free buffers in Default Rx Queues */
	sl351x_gmac_release_rx_q();

#ifdef _TOEQ_CLASSQ_READY_
	/* Free buffers in Classification Queues */
	sl351x_gmac_release_class_q();

	/* Free buffers in TOE Queues */
	sl351x_gmac_release_toe_q();

	/* Free buffers in Interrupt Queues */
	sl351x_gmac_release_intr_q();
#endif

	/* Free buffers & descriptors in SW free queue */
	sl351x_gmac_release_sw_free_q();

	/* Free buffers & descriptors in HW free queue */
	sl351x_gmac_release_hw_free_q();

#ifdef CONFIG_SL351x_NAT
	/* Free buffers & descriptors in HW free queue */
	sl351x_gmac_release_hwtx_q();
#endif
}

/*----------------------------------------------------------------------
* 	sl351x_gmac_release_swtx_q
*----------------------------------------------------------------------*/
static void sl351x_gmac_release_swtx_q(void)
{
	int				i, j;
	GMAC_TXDESC_T	*curr_desc;
	int				desc_count;
	TOE_INFO_T		*toe;
	GMAC_INFO_T		*tp;
	GMAC_SWTXQ_T	*swtxq;
	DMA_RWPTR_T		rwptr;

	int c = 0;

	toe = (TOE_INFO_T *)&toe_private_data;
	tp = (GMAC_INFO_T *)&toe->gmac[0];
	for (i=0; i<GMAC_NUM; i++, tp++)
	{
		if (!tp->existed)
			continue;
		swtxq = (GMAC_SWTXQ_T *)&tp->swtxq[0];
		for (j=0; j<TOE_SW_TXQ_NUM; j++, swtxq++)
		{
			for (c=0; c<100000; c++)					// dhsul-lt
			{
				rwptr.bits32 = readl(swtxq->rwptr_reg);
				if (rwptr.bits.rptr == swtxq->finished_idx)
					break;
				curr_desc = (GMAC_TXDESC_T *)swtxq->desc_base + swtxq->finished_idx;
				// if (curr_desc->word0.bits.status_tx_ok)
				{
					desc_count = curr_desc->word0.bits.desc_count;
					if (desc_count > 0)
					{
						while (--desc_count)
						{
							curr_desc->word0.bits.status_tx_ok = 0;
							swtxq->finished_idx = RWPTR_ADVANCE_ONE(swtxq->finished_idx, swtxq->total_desc_num);
							curr_desc = (GMAC_TXDESC_T *)swtxq->desc_base + swtxq->finished_idx;
						}
					}

					curr_desc->word0.bits.status_tx_ok = 0;
					if (swtxq->tx_skb[swtxq->finished_idx])
					{
						dev_kfree_skb_irq(swtxq->tx_skb[swtxq->finished_idx]);
						swtxq->tx_skb[swtxq->finished_idx] = NULL;
					}
				}
				swtxq->finished_idx = RWPTR_ADVANCE_ONE(swtxq->finished_idx, swtxq->total_desc_num);
			}
			writel(0, swtxq->rwptr_reg);
			swtxq->finished_idx = 0;

			printk(" %d ", c);	// dhsul-lt
		}
	}
}

/*----------------------------------------------------------------------
* 	sl351x_gmac_release_rx_q
*----------------------------------------------------------------------*/
static void sl351x_gmac_release_rx_q(void)
{
	int				i;
	TOE_INFO_T		*toe;
	GMAC_INFO_T		*tp;
	DMA_RWPTR_T		rwptr;
	volatile GMAC_RXDESC_T	*curr_desc;
	struct sk_buff			*skb;

	toe = (TOE_INFO_T *)&toe_private_data;
	tp = (GMAC_INFO_T *)&toe->gmac[0];
	for (i=0; i<GMAC_NUM; i++, tp++) {
		if (!tp->existed) continue;
		rwptr.bits32 = readl(&tp->default_qhdr->word1);
		while (rwptr.bits.rptr != rwptr.bits.wptr) {
			curr_desc = (GMAC_RXDESC_T *)tp->default_desc_base + rwptr.bits.rptr;
			skb = (struct sk_buff *)(REG32(__va(curr_desc->word2.buf_adr) - SKB_RESERVE_BYTES));
			dev_kfree_skb_irq(skb);
			rwptr.bits.rptr = RWPTR_ADVANCE_ONE(rwptr.bits.rptr, tp->default_desc_num);
			SET_RPTR(&tp->default_qhdr->word1, rwptr.bits.rptr);
			rwptr.bits32 = readl(&tp->default_qhdr->word1);
		}  // while
		writel(0, &tp->default_qhdr->word1);
		tp->rx_rwptr.bits32 = 0;
	} // for
}

/*----------------------------------------------------------------------
* 	sl351x_gmac_release_class_q
*----------------------------------------------------------------------*/
#ifdef _TOEQ_CLASSQ_READY_
static void sl351x_gmac_release_class_q(void)
{
	int				i;
	TOE_INFO_T		*toe;
	CLASSQ_INFO_T	*classq;
	DMA_RWPTR_T		rwptr;
	volatile GMAC_RXDESC_T	*curr_desc;
	struct sk_buff			*skb;

	toe = (TOE_INFO_T *)&toe_private_data;
	classq = (CLASSQ_INFO_T *)&toe->classq[0];
	for (i=0; i<TOE_CLASS_QUEUE_NUM; i++, classq++) {
		rwptr.bits32 = readl(&classq->qhdr->word1);
		while (rwptr.bits.rptr != rwptr.bits.wptr) {
			curr_desc = (GMAC_RXDESC_T *)classq->desc_base + rwptr.bits.rptr;
			skb = (struct sk_buff *)(REG32(__va(curr_desc->word2.buf_adr) - SKB_RESERVE_BYTES));
			dev_kfree_skb_irq(skb);
			rwptr.bits.rptr = RWPTR_ADVANCE_ONE(rwptr.bits.rptr, classq->desc_num);
			SET_RPTR(&classq->qhdr->word1, rwptr.bits.rptr);
			rwptr.bits32 = readl(&classq->qhdr->word1);
		}  // while
		writel(0, &classq->qhdr->word1);
		classq->rwptr.bits32 = 0;
	} // for
}
#endif

/*----------------------------------------------------------------------
* 	sl351x_gmac_release_toe_q
*----------------------------------------------------------------------*/
#ifdef _TOEQ_CLASSQ_READY_
static void sl351x_gmac_release_toe_q(void)
{
	int				i;
	TOE_INFO_T		*toe;
	TOEQ_INFO_T		*toeq_info;
	TOE_QHDR_T		*toe_qhdr;
	DMA_RWPTR_T		rwptr;
	volatile GMAC_RXDESC_T	*curr_desc;
	uint32_t	rptr, wptr;
	GMAC_RXDESC_T	*toe_curr_desc;
	struct sk_buff			*skb;

	toe = (TOE_INFO_T *)&toe_private_data;
	toe_qhdr = (TOE_QHDR_T *)TOE_TOE_QUE_HDR_BASE;
	for (i=0; i<TOE_TOE_QUEUE_NUM; i++, toe_qhdr++) {
		toeq_info = (TOEQ_INFO_T *)&toe->toeq[i];
		wptr = toe_qhdr->word1.bits.wptr;
		rptr = toe_qhdr->word1.bits.rptr;
		while (rptr != wptr) {
			toe_curr_desc = (GMAC_RXDESC_T *)toeq_info->desc_base + rptr;
			skb = (struct sk_buff *)(REG32(__va(toe_curr_desc->word2.buf_adr) - SKB_RESERVE_BYTES));
			dev_kfree_skb_irq(skb);
			rptr = RWPTR_ADVANCE_ONE(rptr, toeq_info->desc_num);
			SET_RPTR(&toe_qhdr->word1.bits32, rptr);
			wptr = toe_qhdr->word1.bits.wptr;
			rptr = toe_qhdr->word1.bits.rptr;
		}
		toe_qhdr->word1.bits32 = 0;
		toeq_info->rwptr.bits32 = 0;
	}
}
#endif

/*----------------------------------------------------------------------
* 	sl351x_gmac_release_intr_q
*----------------------------------------------------------------------*/
#ifdef _TOEQ_CLASSQ_READY_
static void sl351x_gmac_release_intr_q(void)
{
}
#endif

/*----------------------------------------------------------------------
 * 	sl351x_gmac_release_sw_free_q
 *		#define RWPTR_ADVANCE_ONE(x, max)	((x == (max -1)) ? 0 : x+1)
 *----------------------------------------------------------------------*/
static void sl351x_gmac_release_sw_free_q(void)
{
	TOE_INFO_T				*toe;
	volatile DMA_RWPTR_T	fq_rwptr;

#ifdef	__DHSUL_ASTEL_ALLOC_SKB__
	volatile GMAC_RXDESC_T	*fq_desc;
#endif

	toe = (TOE_INFO_T *)&toe_private_data;
	fq_rwptr.bits32 = readl(TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);

#ifndef	__DHSUL_ASTEL_ALLOC_SKB__

	printk("sl351x_gmac_release_sw_free_q(0): bits32=%08x wptr=%x rptr=%x \n", fq_rwptr.bits32, fq_rwptr.bits.wptr, fq_rwptr.bits.rptr);		// dhsul

#else

 #ifdef	__DHSUL_ASTEL__
	while ((unsigned short)RWPTR_ADVANCE_ONE(fq_rwptr.bits.wptr, TOE_SW_FREEQ_DESC_NUM) != fq_rwptr.bits.rptr)
 #else
	/*	120116-dhsul
	 *		H/W에서 잘못되었을 경우 영원히 while loop에서 빠져나오지 못한다.
	 *		그래서 한번만 수행하게 if 문으로 변경한다 ....
	 */
	if ((unsigned short)RWPTR_ADVANCE_ONE(fq_rwptr.bits.wptr, TOE_SW_FREEQ_DESC_NUM) != fq_rwptr.bits.rptr)
 #endif
	{
		struct sk_buff *skb;

		/////////////////////////////////////////
		printk("sl351x_gmac_release_sw_free_q(1): bits32=%08x wptr=%x rptr=%x \n", fq_rwptr.bits32, fq_rwptr.bits.wptr, fq_rwptr.bits.rptr);		// dhsul
		/////////////////////////////////////////

		/* allocate socket buffer */
		if ((skb = dev_alloc_skb(SW_RX_BUF_SIZE))==NULL)
		{
			printk("%s::skb buffer allocation fail !\n",__func__);
			while(1);
		}
		// *(uint32_t *)(skb->data) = (uint32_t)skb;
		REG32(skb->data) = (unsigned long)skb;
		skb_reserve(skb, SKB_RESERVE_BYTES);

		fq_rwptr.bits.wptr = RWPTR_ADVANCE_ONE(fq_rwptr.bits.wptr, TOE_SW_FREEQ_DESC_NUM);

		fq_desc = (volatile GMAC_RXDESC_T *)toe->swfq_desc_base + fq_rwptr.bits.wptr;
		fq_desc->word2.buf_adr = (uint32_t)__pa(skb->data);

		SET_WPTR(TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG, fq_rwptr.bits.wptr);

		fq_rwptr.bits32 = readl(TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);

		/////////////////////////////////////////
		printk("sl351x_gmac_release_sw_free_q(2): bits32=%08x wptr=%x rptr=%x \n", fq_rwptr.bits32, fq_rwptr.bits.wptr, fq_rwptr.bits.rptr);		// dhsul
		/////////////////////////////////////////
	}

#endif		// ! __DHSUL_ASTEL_ALLOC_SKB__

	toe->fq_rx_rwptr.bits.wptr = TOE_SW_FREEQ_DESC_NUM - 1;
	toe->fq_rx_rwptr.bits.rptr = 0;
	writel(toe->fq_rx_rwptr.bits32, TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);

	fq_rwptr.bits32 = readl(TOE_GLOBAL_BASE + GLOBAL_SWFQ_RWPTR_REG);
	printk("sl351x_gmac_release_sw_free_q(3): bits32=%08x wptr=%x rptr=%x \n", fq_rwptr.bits32, fq_rwptr.bits.wptr, fq_rwptr.bits.rptr);		// dhsul
}

/*----------------------------------------------------------------------
* 	sl351x_gmac_release_hw_free_q
*----------------------------------------------------------------------*/
static void sl351x_gmac_release_hw_free_q(void)
{
	DMA_RWPTR_T			rwptr_reg;

#ifdef CONFIG_SL351x_NAT
	int					i;
	TOE_INFO_T			*toe;
	GMAC_RXDESC_T		*desc_ptr;
	uint32_t		buf_ptr;

	toe = (TOE_INFO_T *)&toe_private_data;
	desc_ptr = (GMAC_RXDESC_T *)toe->hwfq_desc_base;
	buf_ptr = (uint32_t)toe->hwfq_buf_base_dma;
	for (i=0; i<TOE_HW_FREEQ_DESC_NUM; i++) {
		desc_ptr->word0.bits.buffer_size = HW_RX_BUF_SIZE;
		desc_ptr->word1.bits.sw_id = i;
		desc_ptr->word2.buf_adr = (uint32_t)buf_ptr;
   		desc_ptr++;
   		buf_ptr += HW_RX_BUF_SIZE;
	}
#endif
	rwptr_reg.bits.wptr = TOE_HW_FREEQ_DESC_NUM - 1;
	rwptr_reg.bits.rptr = 0;
	writel(rwptr_reg.bits32, TOE_GLOBAL_BASE + GLOBAL_HWFQ_RWPTR_REG);
}

/*----------------------------------------------------------------------
* 	sl351x_gmac_release_hw_free_q
*----------------------------------------------------------------------*/
#ifdef CONFIG_SL351x_NAT
static void sl351x_gmac_release_hwtx_q(void)
{
	int				i;
	uint32_t	rwptr_addr;

	rwptr_addr = TOE_GMAC0_DMA_BASE + GMAC_HW_TX_QUEUE0_PTR_REG;
	for (i=0; i<TOE_HW_TXQ_NUM; i++) {
		writel(0, rwptr_addr);
		rwptr_addr+=4;
	}
	rwptr_addr = TOE_GMAC1_DMA_BASE + GMAC_HW_TX_QUEUE0_PTR_REG;
	for (i=0; i<TOE_HW_TXQ_NUM; i++) {
		writel(0, rwptr_addr);
		rwptr_addr+=4;
	}
}
#endif

/*----------------------------------------------------------------------
* 	sl351x_gmac_save_reg
*----------------------------------------------------------------------*/
void sl351x_gmac_save_reg(void)
{
	int	i;
	volatile u32	*destp;
	uint32_t	srce_addr;

	srce_addr = TOE_GLOBAL_BASE;
	destp = (volatile u32 *)toe_global_reg;
	for (i=0; i<TOE_GLOBAL_REG_SIZE; i++, destp++, srce_addr+=4)
		*destp = readl(srce_addr);

	srce_addr = TOE_GMAC0_DMA_BASE;
	destp = (volatile u32 *)&toe_dma_reg[0][0];
	for (i=0; i<TOE_DMA_REG_SIZE; i++, destp++, srce_addr+=4) {
		if (srce_addr ==  (TOE_GMAC0_DMA_BASE+0x38))
			srce_addr = (TOE_GMAC0_DMA_BASE+0x50);
		if (srce_addr ==  (TOE_GMAC0_DMA_BASE+0x58))
			srce_addr = (TOE_GMAC0_DMA_BASE+0x70);

		*destp = readl(srce_addr);
	}
	srce_addr = TOE_GMAC1_DMA_BASE;
	destp = (volatile u32 *)&toe_dma_reg[1][0];
	for (i=0; i<TOE_DMA_REG_SIZE; i++, destp++, srce_addr+=4) {
		if (srce_addr ==  (TOE_GMAC0_DMA_BASE+0x38))
			srce_addr = (TOE_GMAC0_DMA_BASE+0x50);
		if (srce_addr ==  (TOE_GMAC0_DMA_BASE+0x58))
			srce_addr = (TOE_GMAC0_DMA_BASE+0x70);

		*destp = readl(srce_addr);
	}

	srce_addr = TOE_GMAC0_BASE;
	destp = (volatile u32 *)&toe_gmac_reg[0][0];
	for (i=0; i<TOE_GMAC_REG_SIZE; i++, destp++, srce_addr+=4)
		*destp = readl(srce_addr);

	srce_addr = TOE_GMAC1_BASE;
	destp = (volatile u32 *)&toe_gmac_reg[1][0];
	for (i=0; i<TOE_GMAC_REG_SIZE; i++, destp++, srce_addr+=4)
		*destp = readl(srce_addr);
}

/*----------------------------------------------------------------------
* 	sl351x_gmac_restore_reg
*----------------------------------------------------------------------*/
void sl351x_gmac_restore_reg(void)
{
	int	i;
	volatile u32	*srcep;
	uint32_t	dest_addr;

	srcep = (volatile u32 *)&toe_dma_reg[0][0];
	dest_addr = TOE_GMAC0_DMA_BASE;
	for (i=0; i<TOE_DMA_REG_SIZE; i++, dest_addr+=4, srcep++) {
		if (dest_addr == (TOE_GMAC0_DMA_BASE+0x38))
			dest_addr = (TOE_GMAC0_DMA_BASE+0x50);
		if (dest_addr == (TOE_GMAC0_DMA_BASE+0x58))
			dest_addr = (TOE_GMAC0_DMA_BASE+0x70);

		writel(*srcep, dest_addr);
		// gmac_write_reg(dest_addr, 0, *srcep, 0xffffffff);
	}
	srcep = (volatile u32 *)&toe_dma_reg[1][0];
	dest_addr = TOE_GMAC1_DMA_BASE;
	for (i=0; i<TOE_DMA_REG_SIZE; i++, dest_addr+=4, srcep++) {
		if (dest_addr == (TOE_GMAC0_DMA_BASE+0x38))
			dest_addr = (TOE_GMAC0_DMA_BASE+0x50);
		if (dest_addr == (TOE_GMAC0_DMA_BASE+0x58))
			dest_addr = (TOE_GMAC0_DMA_BASE+0x70);

		writel(*srcep, dest_addr);
		// gmac_write_reg(dest_addr, 0, *srcep, 0xffffffff);
	}

	srcep = (volatile u32 *)&toe_gmac_reg[0][0];
	dest_addr = TOE_GMAC0_BASE;
	for (i=0; i<TOE_GMAC_REG_SIZE; i++, dest_addr+=4, srcep++)
		writel(*srcep, dest_addr);

	srcep = (volatile u32 *)&toe_gmac_reg[1][0];
	dest_addr = TOE_GMAC1_BASE;
	for (i=0; i<TOE_GMAC_REG_SIZE; i++, dest_addr+=4, srcep++)
		writel(*srcep, dest_addr);

	srcep = (volatile u32 *)toe_global_reg;
	dest_addr = TOE_GLOBAL_BASE;
	for (i=0; i<TOE_GLOBAL_REG_SIZE; i++, dest_addr+=4, srcep++)
		writel(*srcep, dest_addr);
}

#ifdef CONFIG_SL351x_NAT
/*----------------------------------------------------------------------
 *	sl351x_nat_workaround_init
 *----------------------------------------------------------------------*/
#define NAT_WORKAROUND_DESC_POWER	(6)
#define NAT_WORKAROUND_DESC_NUM		(2 << NAT_WORKAROUND_DESC_POWER)
dma_addr_t sl351x_nat_workaround_desc_dma;
void sl351x_nat_workaround_init(void)
{
	uint32_t	desc_buf;

	desc_buf = (uint32_t)DMA_MALLOC((NAT_WORKAROUND_DESC_NUM * sizeof(GMAC_RXDESC_T)),
				(dma_addr_t *)&sl351x_nat_workaround_desc_dma);
	memset((void *)desc_buf, 0, NAT_WORKAROUND_DESC_NUM * sizeof(GMAC_RXDESC_T));

	/* DMA Queue Base & Size */
	writel((sl351x_nat_workaround_desc_dma & DMA_Q_BASE_MASK) | NAT_WORKAROUND_DESC_POWER,
			TOE_GLOBAL_BASE + 0x4080);
	writel(0, TOE_GLOBAL_BASE + 0x4084);
}

/*----------------------------------------------------------------------
 *	sl351x_nat_workaround_handler
 *----------------------------------------------------------------------*/
#endif // CONFIG_SL351x_NAT

//#endif // SL351x_GMAC_WORKAROUND
