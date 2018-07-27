/***********************************************************************
 * Copyright (c) 2008-2009 Cortina Systems, Inc.
 * All Rights Reserved.
 * ---------------------------------------------------------------------
 * Copyright 2007-2008 StorLink Semiconductors, Inc.  All rights reserved.
 * ---------------------------------------------------------------------
 * Name:		sl351x_ipsec.c
 * Description:	IPSEC-VPN implementation by using classification queue
 *				and HW Crypto Engine, VPN environment variables are 
 *				set up by setkey, racoon, and GUI.  What this level is
 *				handling is the transaction of encrypting/decrypting
 *				given VPN packets.
 *				3 flags / modes are provided.
 *				1) CONFIG_CRYPTO_BATCH: process packet by batch. Performance
 *						is better. (Turn it on!!)
 *					If turn off: process packet 1 by 1.
 *				2) CONFIG_SL351X_IPSEC_REUSE_SKB: this mode is to re-use the 
 *						memory that's been allocated for the received skb.  
 *						Default is "OFF." Due to some safety issues, it's 
 *						better to turn it off.
 * Note:	NAPI mode for classification queue has been merged into sl351x_gmac.
 *			The performance with NAPI mode enabled is more tested, and should 
 *			run faster than usual interrupt mode.
 * sysctl: /proc/sys/net/ipv4/storlink_hw_vpn
 *				bit 0 (1): enable(1) / disable(0)
 *				bit 1 (2): WAN port is PPPoE(1) / not(0)-enable this if PPPoE 
 *							is used
 *				bit 2 (4): TX transmission will go through NF_HOOK to be
 *							verified by NetFilter rules (FORWARD).
 *				bit 4 (16): print out all of those debugging message
 * History:
 *
 * ------------------------------------------------------------
 * Wen Hsu: 
 *------------------------------------------------- */
#define CONFIG_SL_NAPI			1	/* NAPI mode support */

/*******************
 * Mode Selections 
 ******************/
#define CONFIG_CRYPTO_BATCH
//#define SL351X_IPSEC_DEBUG
//#define CONFIG_SL351X_IPSEC_REUSE_SKB

#include <linux/config.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/sysctl_storlink.h>
#include <linux/scatterlist.h>
#include <linux/skbuff.h>
#include <linux/sysctl.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/arp.h>
#include <net/xfrm.h>
#include <net/ah.h>
#include <linux/if_pppox.h>
#include <asm/arch/sl2312_ipsec.h>
#include <asm/arch/sl351x_gmac.h>
#include <asm/arch/sl351x_hash_cfg.h>
#include <asm/arch/sl351x_ipsec.h>
#include <asm/arch/sl351x_nat_cfg.h>
#include "/source/kernel/linux/net/bridge/br_private.h"
#include <linux/ppp_defs.h>
#include <linux/if_vlan.h>
#include "/source/kernel/linux/net/8021q/vlan.h"

/************************
 * Constant Definition  *
 ************************/
#define		IP_HEADER_SIZE		sizeof(struct iphdr)
#define		IPSEC_TIMER_PERIOD	(10)

/************************
 * Variable Declaration *
 ************************/
struct IPSEC_VPN_TUNNEL_CONFIG ipsec_tunnel[MAX_IPSEC_TUNNEL];
struct IPSEC_VPN_IP_PAIR_CONFIG ipsec_pair[MAX_IPSEC_TUNNEL];
static int class_rule_initialized = 0;
static DEFINE_RWLOCK(ipsec_tunnel_lock);
static int IPSEC_VPN_TUNNEL_HW_NUM = 0;
#ifdef CONFIG_CRYPTO_BATCH
struct IPSEC_PACKET_S CRYPTO_QUEUE[CRYPTO_QUEUE_SIZE];
static int current_crypto_loc = 0;
static int current_crypto_used = 0;
static int crypto_queue_count = 0;
#endif
short ipsec_tunnel_id_table[HASH_TOTAL_ENTRIES];
static unsigned long count_encrypted = 0;
static unsigned long count_decrypted = 0;
static int packet_error = 0;
static int crypto_error = 0;
short ipsec_hash_timer_table[HASH_TOTAL_ENTRIES];
static struct timer_list ipsec_timer_obj;
//LIST_HEAD(ipsec_timeout_list);

/************************
 * Function Declaration *
 ************************/
int sl351x_ipsec_init(void);
void ipsec_init_class_queue(void);
void sl351x_ipsec_check_gmac_rx(struct sk_buff *skb, int port, void *l3off, void *l4off);
int sl351x_ipsec_check_gmac_tx(struct sk_buff *skb, int port);
int ipsec_handle_class_queue(struct net_device * dev, GMAC_INFO_T *tp, 
		int budget);
void ipsec_finish_callback(struct IPSEC_PACKET_S *ipsec_ptr);
int ipsec_gmac_process(struct sk_buff *skb, unsigned int sw_id);
int ipsec_gmac_callback(struct sk_buff *skb, struct IPSEC_PACKET_S * ipsec_ptr, 
		struct sk_buff *old_skb,int flag_polling);
int ipsec_handle_skb(struct sk_buff *skb, unsigned int sw_id, 
		unsigned int clone_flag, unsigned int l3_offset);
int ipsec_handle_skb_finish(void);
void ipsec_vpn_tunnel_start(void);
static int skb_send_to_kernel(struct sk_buff *skb);
static int vpn_sysctl_info(ctl_table *ctl, int write, struct file * filp,
		void __user *buffer, size_t *lenp, loff_t *ppos);
static void ipsec_hash_timer_func(u32 data);
extern int mac_set_rule_reg(int mac, int rule, int enabled, u32, u32, u32);
extern void gmac_write_reg(unsigned int base, unsigned int offset, 
		unsigned int data, unsigned int bit_mask);
extern void *pskb_put(struct sk_buff *skb, struct sk_buff *tail, int len);
extern int skb_cow_data(struct sk_buff *skb, int tailbits, 
		struct sk_buff **trailer);
extern void hash_dump_entry(int index);
extern int sl351x_ipsec_route_cache(struct sk_buff *skb, u32 daddr, u32 saddr,
		u8 tos);

static struct ctl_table_header *vpn_table_header;
#define VPN_INFO_BUFFER_SIZE 8*MAX_IPSEC_TUNNEL
static int vpn_info[VPN_INFO_BUFFER_SIZE];

// /proc/sys/dev/vpn/vpn_pair
static ctl_table vpn_table[] = {
	{
		.ctl_name       = NET_VPN_Pair,
		.procname       = "vpn_pair",
		.data           = vpn_info,
		.maxlen         = 9*MAX_IPSEC_TUNNEL*sizeof(int),
		.mode           = 0644,
		.proc_handler   = &vpn_sysctl_info,
	},
	{ .ctl_name = 0 }
};

static ctl_table vpn_dir_table[] = {
	{
		.ctl_name       = NET_VPN,
		.procname       = "vpn",
		.maxlen         = 0,
		.mode           = 0555,
		.child          = vpn_table,
	},
	{ .ctl_name = 0 }
};

static ctl_table vpn_net_table[] = {
	{
		.ctl_name       = CTL_NET,
		.procname       = "net",
		.maxlen         = 0,
		.mode           = 0555,
		.child          = vpn_dir_table,
	},
	{ .ctl_name = 0 }
};

/*--------------------------------------------------------------------------
 * sl351x_ipsec_init()
 * Description: setup matching fields of classification queue for sl351x_ipsec
 * Status: Matching rules should work now. Problem is for GMAC0 (WAN port), 
 * 		   I've not defined the SPR for ESP and AH. (but it still works for 
 * 		   some reasons).
 *-------------------------------------------------------------------------*/
int sl351x_ipsec_init(void)
{
	GMAC_MRxCR0_T   mrxcr0;
	GMAC_MRxCR1_T   mrxcr1;
	GMAC_MRxCR2_T   mrxcr2;
	int result;

	if (class_rule_initialized)
		return 0;

	class_rule_initialized = 1;
	printk("%s::Setting up Matching rule\n", __func__);

	/* Setting up matching rule for IPsec VPN Acceleration */
	mrxcr0.bits32 = 0;
	mrxcr1.bits32 = 0;
	mrxcr2.bits32 = 0;
	mrxcr0.bits.port = 1;
	mrxcr0.bits.l3 = 1;
	mrxcr0.bits.l4 = 0;
	mrxcr0.bits.sprx = 0x18;		/* up for ESP/AH */
	/* enable SPR3 for ESP. SPR4 for AH initialized in sl351x_gmac.c*/
	mrxcr1.bits.sip = 1;
	mrxcr1.bits.dip = 1;
#ifdef CONFIG_CS351X_DUAL_WAN
	mrxcr0.bits.l2 = 1;
	mrxcr0.bits.vlan = 1;
#endif
	mrxcr0.bits.pppoe = 0;
	mrxcr0.bits.priority = IPSEC_WAN_PRIORITY;

	result = mac_set_rule_reg(GMAC_PORT0, WAN_RULE_ID, 1, 
				mrxcr0.bits32, mrxcr1.bits32, mrxcr2.bits32);
	if (result < 0) {
		printk("%s: set WAN port rule fail\r\n", __func__);
		return ERR_MATCH_RULE;
	}

	result = mac_set_rule_reg(GMAC_PORT1, WAN_RULE_ID, 1, 
				mrxcr0.bits32, mrxcr1.bits32, mrxcr2.bits32);
	if (result < 0) {
		printk("%s: set WAN port rule fail\r\n", __func__);
		return ERR_MATCH_RULE;
	}

	storlink_ctl.hw_vpn = SYSCTL_VPN_ENABLE;
#ifdef CONFIG_CRYPTO_BATCH
	memset(CRYPTO_QUEUE, 0, CRYPTO_QUEUE_SIZE*sizeof(struct IPSEC_PACKET_S));
	current_crypto_loc = 0;
#endif
	/* initialization of pair structure*/
	memset(ipsec_pair, 0, MAX_IPSEC_TUNNEL*sizeof(struct IPSEC_VPN_IP_PAIR_CONFIG));
	vpn_table_header = register_sysctl_table(vpn_net_table, 1);

	/* initialization of timer */
	init_timer(&ipsec_timer_obj);
	ipsec_timer_obj.expires = jiffies + (IPSEC_TIMER_PERIOD * HZ);
	ipsec_timer_obj.data = (unsigned long)&ipsec_timer_obj;
	ipsec_timer_obj.function = (void *)&ipsec_hash_timer_func;
	add_timer(&ipsec_timer_obj);
	memset(ipsec_hash_timer_table, 0x0, HASH_TOTAL_ENTRIES * sizeof(short));

	/* initialization of the tunnel id table on hash index */
	memset(ipsec_tunnel_id_table, 0x0, HASH_TOTAL_ENTRIES*sizeof(short));

	return 1;
}

/*--------------------------------------------------------------*
 * ipsec_adjust_hdr_location()
 * description: to adjust the IP hdr location and store in skb->nh.iph
 *------------------------------------------------------------*/
static inline int ipsec_adjust_hdr_location(struct sk_buff *skb)
{
	int network_offset = 0;
	struct ethhdr *eth_hdr;
	unsigned short eth_proto;

	eth_hdr = (struct ethhdr *)skb->data;
	eth_proto = eth_hdr->h_proto;
	if (eth_proto == __constant_htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *vlan_eth_hdr;
		vlan_eth_hdr = (struct vlan_ethhdr *)skb->data;
		network_offset += VLAN_ETH_HLEN;
		eth_proto = vlan_eth_hdr->h_vlan_encapsulated_proto;
	} else network_offset += ETH_HLEN;

	if (eth_proto == __constant_htons(ETH_P_PPP_SES)) {
		struct pppoe_hdr *pppoe_hdr;
		pppoe_hdr = (struct pppoe_hdr *)(skb->data + network_offset);
		network_offset += sizeof(struct pppoe_hdr) + 2;
		eth_proto == *(u16 *)&pppoe_hdr->tag[0];
	}

	if (eth_proto == __constant_htons(ETH_P_IP)) {
		struct iphdr *ip_hdr;
		ip_hdr = (struct iphdr *)(skb->data + network_offset);
	}

	if (network_offset != 0)
		skb->nh.raw = skb->data + network_offset;

	return network_offset;
}

/*-----------------------------------------------------------------
 * ipsec_init_class_queue
 * Description: to initialize class queue that's going be used for
 *				this module
 *				only need 2 class queues, (#0 and #1), but still enables
 *				all 12 class queues
 *----------------------------------------------------------------*/
void ipsec_init_class_queue(void)
{
	TOE_INFO_T		*toe = &toe_private_data;
	NONTOE_QHDR_T	*qhdr;
	GMAC_RXDESC_T	*desc_ptr;
	int		i;

	qhdr = (NONTOE_QHDR_T*)TOE_CLASS_Q_HDR_BASE;
	desc_ptr = (GMAC_RXDESC_T*)DMA_MALLOC((TOE_CLASS_QUEUE_NUM * 
			TOE_CLASS_DESC_NUM * sizeof(GMAC_RXDESC_T)), 
			(dma_addr_t*)&toe->class_desc_base_dma);

	if (!desc_ptr) {
		printk("%s::DMA_MALLOC classificaiton queue fail!\n", __func__);
		return;
	}
	memset((void*)desc_ptr, 0, TOE_CLASS_QUEUE_NUM * TOE_CLASS_DESC_NUM *
		sizeof(GMAC_RXDESC_T));
	toe->class_desc_base = (unsigned int)desc_ptr;
	toe->class_desc_num = TOE_CLASS_DESC_NUM;

	for (i=0; i<TOE_CLASS_QUEUE_NUM; i++, qhdr++) {
		qhdr->word0.base_size = (((unsigned int)toe->class_desc_base_dma + 
				i*(TOE_CLASS_DESC_NUM) * sizeof(GMAC_RXDESC_T)) & 
				NONTOE_QHDR0_BASE_MASK)	| TOE_CLASS_DESC_POWER;
		qhdr->word1.bits32 = 0;
	}
}

/* --------------------------------------------------------------------------*
 * ipsec_vpn_find_and_verify_path
 * Description: to find and verify if the given tx/rx sip/dip+spi pairs should 
 * 				be accelerated
 * --------------------------------------------------------------------------*/
static inline struct IPSEC_VPN_TUNNEL_CONFIG * ipsec_vpn_find_and_verify_path(
		unsigned int rx_sip, unsigned int rx_dip, unsigned int tx_sip,
		unsigned int tx_dip, unsigned int spi, unsigned short mode)
{
	struct IPSEC_VPN_TUNNEL_CONFIG *tunnel_ptr;
	int count;

	tunnel_ptr = ipsec_tunnel;
	count = 0;
	
	while ((tunnel_ptr != NULL) && (count < MAX_IPSEC_TUNNEL)) {
		if ((tunnel_ptr->enable == 1)
				&& (tunnel_ptr->mode == mode)
				&& (mode == MODE_ENCRYPTION)) {
			if (((rx_sip&tunnel_ptr->src_netmask) == tunnel_ptr->src_LAN)
					&& ((rx_dip&tunnel_ptr->dst_netmask) == tunnel_ptr->dst_LAN)
					&& (tx_sip == tunnel_ptr->src_WAN_IP)
					&& (tx_dip == tunnel_ptr->dst_WAN_IP)) {
				return tunnel_ptr;
			}
		}
		if ((tunnel_ptr->enable == 1)
				&& (tunnel_ptr->mode == mode)
				&& (mode == MODE_DECRYPTION)) {
			if ((rx_sip == tunnel_ptr->src_WAN_IP)
					&& (rx_dip == tunnel_ptr->dst_WAN_IP)
					&& ((tx_sip&tunnel_ptr->src_netmask) == tunnel_ptr->src_LAN)
					&& ((tx_dip&tunnel_ptr->dst_netmask) == tunnel_ptr->dst_LAN))
				return tunnel_ptr;
		}
		tunnel_ptr++;
		count++;
	}
	return NULL;
}

/*----------------------------------------------------------------------
* nat_build_keys
*	Note: To call this routine, the key->rule_id MUST be zero
*----------------------------------------------------------------------*/
static inline int nat_build_keys(NAT_KEY_T *key)
{
	return hash_gen_crc16((unsigned char *)key, NAT_KEY_SIZE) & HASH_BITS_MASK;
}

/*----------------------------------------------------------------------
* nat_write_hash_entry
*----------------------------------------------------------------------*/
static inline int nat_write_hash_entry(int index, void *hash_entry)
{
	int		i;
	u32		*srcep, *destp, *destp2;
	
	srcep = (u32 *)hash_entry;
	destp = destp2 = (u32 *)&hash_tables[index][0];
	
	for (i=0; i<(NAT_HASH_ENTRY_SIZE/sizeof(u32)); i++)
		*destp++ = *srcep++;

	consistent_sync(destp2, NAT_HASH_ENTRY_SIZE, PCI_DMA_TODEVICE);
	return 0;
}

/*----------------------------------------------------------------------
* ipsec_build_keys
*	Note: To call this routine, the key->rule_id MUST be zero
*----------------------------------------------------------------------*/
static inline int ipsec_build_keys(IPSEC_KEY_T *key)
{
	return hash_gen_crc16((unsigned char *)key, IPSEC_KEY_SIZE) & HASH_BITS_MASK;
}

/*----------------------------------------------------------------------
* ipsec_write_hash_entry
*----------------------------------------------------------------------*/
static inline int ipsec_write_hash_entry(int index, void *hash_entry)
{
	int		i;
	u32		*srcep, *destp, *destp2;
	
	srcep = (u32 *)hash_entry;
	destp = destp2 = (u32 *)&hash_tables[index][0];
	
	for (i=0; i<(IPSEC_HASH_ENTRY_SIZE/sizeof(u32)); i++)
		*destp++ = *srcep++;

	consistent_sync(destp2, IPSEC_HASH_ENTRY_SIZE, PCI_DMA_TODEVICE);
	return 0;
}

/*----------------------------------------------------------------------
 * Name: create_ipsec_hash_entry
 * Description: to create a new hash entry
 *---------------------------------------------------------------------*/
static int create_ipsec_hash_entry(
		struct IPSEC_VPN_TUNNEL_CONFIG *tunnel_config, struct sk_buff *skb,
		int port, int mode)
{
	u32 hash_data[HASH_MAX_DWORDS];
	NAT_HASH_ENTRY_T *nat_hash_entry;
	IPSEC_HASH_ENTRY_T *ipsec_hash_entry;
	int hash_index = 0;
	struct iphdr *iph;
	NAT_CB_T *nat_cb;
	unsigned char proto, in_proto;
	unsigned short rx_sport, rx_dport;
	unsigned int rx_sip, rx_dip, tx_sip, tx_dip, qid = 0, in_port;
	struct net_device *input_dev;
#ifdef CONFIG_CS351X_DUAL_WAN
	short nat_cb_vid, tx_vid;
#endif

	/* Getting information from skb and nat_cb */
	nat_cb = NAT_SKB_CB(skb);
	iph = (struct iphdr *)skb->nh.iph;

	if ((nat_cb->vpn_tag != NAT_CB_VPN_TAG)
			&& (nat_cb->vpn_tag != NAT_CB_VPN2_TAG))
		return 0;

	if (((u32)nat_cb & 3)) {
		printk("%s:Error: nat_cb is not aligned!\n", __func__);
		return 0;
	}

	proto = iph->protocol;

	rx_sip = ntohl(nat_cb->sip);
	rx_dip = ntohl(nat_cb->dip);
	rx_sport = ntohs(nat_cb->sport);
	rx_dport = ntohs(nat_cb->dport);
	tx_sip = ntohl(iph->saddr);
	tx_dip = ntohl(iph->daddr);
	in_proto = nat_cb->in_proto;

	input_dev = (struct net_device*)(nat_cb->input_dev);
	in_port = ((GMAC_INFO_T *)input_dev->priv)->port_id;

#ifdef CONFIG_CS351X_DUAL_WAN
	if (skb->protocol == __constant_htons(ETH_P_8021Q))
		tx_vid = (*(skb->data + 0x0F)) | ((*(skb->data + 0x0E)) << 8);
	else tx_vid = 0;
	nat_cb_vid = nat_cb->reserved[0] | (nat_cb->reserved[1] << 8);
#endif

	if (mode == MODE_ENCRYPTION) {
		/* filling up hash entry */
		nat_hash_entry = (NAT_HASH_ENTRY_T *)&hash_data;
		memset((void *)nat_hash_entry, 0, sizeof(NAT_HASH_ENTRY_T));
		nat_hash_entry->key.Ethertype	= 0;	
		nat_hash_entry->key.port_id 	= in_port;
		nat_hash_entry->key.rule_id 	= 0;
#ifdef CONFIG_CS351X_DUAL_WAN
		nat_hash_entry->key.vlan_id     = nat_cb_vid;
		nat_hash_entry->key.pppoe_sid 	= 0;
#endif
		nat_hash_entry->key.ip_protocol = in_proto;
		nat_hash_entry->key.reserved1 	= 0;
		nat_hash_entry->key.reserved2 	= 0;
		nat_hash_entry->key.sip 		= rx_sip;
		nat_hash_entry->key.dip 		= rx_dip;
		nat_hash_entry->key.sport 		= nat_cb->sport;
		nat_hash_entry->key.dport 		= nat_cb->dport;

		hash_index = nat_build_keys(&nat_hash_entry->key);

		/* handle hash timeout */
		if (hash_get_nat_owner_flag(hash_index))
			return -1;

		/* Check hash collision */
		if (hash_get_valid_flag(hash_index)) return -1;

		nat_hash_entry->key.rule_id = 1;
		nat_hash_entry->param.pppoe = 0;
		nat_hash_entry->param.sw_id = hash_index;
		ipsec_tunnel_id_table[hash_index] = tunnel_config->tableID;
		nat_hash_entry->param.mtu = 0;
		nat_hash_entry->action.dword = 0;
		nat_hash_entry->action.bits.sw_id = 1;

		qid = IPSEC_OUTBOUND_QID;
		nat_hash_entry->action.bits.dest_qid = TOE_CLASSIFICATION_QID(qid);

		/* enable timer */
		nat_hash_entry->tmo.counter = nat_hash_entry->tmo.interval = 60;
		ipsec_hash_timer_table[hash_index] = 60;

		/* write hash entry to hash table and validate it */
		nat_write_hash_entry(hash_index, nat_hash_entry);
		if (storlink_ctl.hw_vpn & SYSCTL_VPN_DEBUG) { /* debug message */
			printk("%s::hash=%d, sip=%x, dip=%x, class qid=%d", __func__,
					hash_index, rx_sip, rx_dip, qid);
			hash_dump_entry(hash_index);
		}
		hash_nat_enable_owner(hash_index);
		/* Must be the last one, else HW Tx fast SW */
		hash_validate_entry(hash_index); 
	}

	if (mode == MODE_DECRYPTION) {
		/* filling up hash entry */
		ipsec_hash_entry = (IPSEC_HASH_ENTRY_T *)&hash_data;
		memset((void *)ipsec_hash_entry, 0, sizeof(IPSEC_HASH_ENTRY_T));

		ipsec_hash_entry->key.Ethertype	= 0;
		ipsec_hash_entry->key.port_id	= in_port;
		ipsec_hash_entry->key.rule_id	= 0;
#ifdef CONFIG_CS351X_DUAL_WAN
		ipsec_hash_entry->key.vlan_id	= nat_cb_vid;
		ipsec_hash_entry->key.pppoe_sid	= 0;
#endif
		ipsec_hash_entry->key.ip_protocol	= in_proto;
		ipsec_hash_entry->key.reserved1	= 0;
		ipsec_hash_entry->key.reserved2	= 0;
		ipsec_hash_entry->key.sip		= rx_sip;
		ipsec_hash_entry->key.dip		= rx_dip;

		hash_index = ipsec_build_keys(&ipsec_hash_entry->key);

		/* handle hash timeout */
		if (hash_get_nat_owner_flag(hash_index))
			return -1;

		/* Check hash collision */
		if (hash_get_valid_flag(hash_index)) return -1;

		ipsec_hash_entry->key.rule_id = WAN_RULE_ID;
		ipsec_hash_entry->param.pppoe = 0;
		ipsec_hash_entry->param.sw_id = hash_index;
		ipsec_tunnel_id_table[hash_index] = tunnel_config->tableID;
		ipsec_hash_entry->param.mtu = 0;
		ipsec_hash_entry->action.dword = 0;
		ipsec_hash_entry->action.bits.sw_id = 1;

		if (in_port == 0)
			qid = IPSEC_INBOUND_QID;
		else // if (in_port == 1)
			qid = IPSEC_INBOUND_QID_2;
		ipsec_hash_entry->action.bits.dest_qid = TOE_CLASSIFICATION_QID(qid);

		/* enable timer */
		ipsec_hash_entry->tmo.counter = ipsec_hash_entry->tmo.interval = 60;
		ipsec_hash_timer_table[hash_index] = 60;

		/* write hash entry to hash table and validate it */
		ipsec_write_hash_entry(hash_index, ipsec_hash_entry);
		if (storlink_ctl.hw_vpn & SYSCTL_VPN_DEBUG) { /* debug message */
			printk("%s::hash=%d, sip=%x, dip=%x, class qid=%d", __func__,
					hash_index, rx_sip, rx_dip, qid);
			hash_dump_entry(hash_index);
		}
		hash_nat_enable_owner(hash_index);
		/* Must be the last one, else HW Tx fast SW */
		hash_validate_entry(hash_index);
	}

	if (mode == MODE_DECRYPTION_FAST_NET) {
		/* filling up hash entry */
		ipsec_hash_entry = (IPSEC_HASH_ENTRY_T *)&hash_data;
		memset((void *)ipsec_hash_entry, 0, sizeof(IPSEC_HASH_ENTRY_T));

		ipsec_hash_entry->key.Ethertype	= 0;
		ipsec_hash_entry->key.port_id	= port;
		ipsec_hash_entry->key.rule_id	= 0;
#ifdef CONFIG_CS351X_DUAL_WAN
		ipsec_hash_entry->key.vlan_id	= tx_vid;
		ipsec_hash_entry->key.pppoe_sid	= 0;
#endif
		ipsec_hash_entry->key.ip_protocol	= proto;
		ipsec_hash_entry->key.reserved1	= 0;
		ipsec_hash_entry->key.reserved2	= 0;
		ipsec_hash_entry->key.sip		= tx_dip;
		ipsec_hash_entry->key.dip		= tx_sip;

		hash_index = ipsec_build_keys(&ipsec_hash_entry->key);

		/* handle hash timeout */
		if (hash_get_nat_owner_flag(hash_index))
			return -1;

		/* Check hash collision */
		if (hash_get_valid_flag(hash_index)) return -1;

		ipsec_hash_entry->key.rule_id = WAN_RULE_ID;
		ipsec_hash_entry->param.pppoe = 0;
		ipsec_hash_entry->param.sw_id = hash_index;
		ipsec_tunnel_id_table[hash_index] = tunnel_config->tableID;
		ipsec_hash_entry->param.mtu = 0;
		ipsec_hash_entry->action.dword = 0;
		ipsec_hash_entry->action.bits.sw_id = 1;

		if (port == 0)
			qid = IPSEC_INBOUND_QID;
		else // if (port == 1)
			qid = IPSEC_INBOUND_QID_2;
		ipsec_hash_entry->action.bits.dest_qid = TOE_CLASSIFICATION_QID(qid);

		if (storlink_ctl.hw_vpn & SYSCTL_VPN_DEBUG) { /* debug message */
		}

		/* enable timer */
		ipsec_hash_entry->tmo.counter = ipsec_hash_entry->tmo.interval = 60;
		ipsec_hash_timer_table[hash_index] = 60;

		/* write hash entry to hash table and validate it */
		ipsec_write_hash_entry(hash_index, ipsec_hash_entry);
		if (storlink_ctl.hw_vpn & SYSCTL_VPN_DEBUG) { /* debug message */
			printk("%s::hash=%d, sip=%x, dip=%x, class qid=%d\n", __func__,
					hash_index, tx_dip, tx_sip, qid);
			hash_dump_entry(hash_index);
		}
		hash_nat_enable_owner(hash_index);
		/* Must be the last one, else HW Tx fast SW */
		hash_validate_entry(hash_index);
	}

	return hash_index;
}

/* ------------------------------------------------------------------
 * sl351x_ipsec_check_gmac_rx
 * Description: in GMAC RX stage, testing the packet if it's capable 
 * 				of being accelerated by IPsec VPN Accelerated engine.
 * 				If so, leave some info in skb->cb (can share with HW NAT)
 * --------------------------------------------------------------- */
void sl351x_ipsec_check_gmac_rx(struct sk_buff *skb, int port, void *l3off, void *l4off)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct vlan_ethhdr *vlan_ethh;
	struct ethhdr *ethh;
	struct pppoe_hdr *pppoeh;
	u8 proto, pppoe_frame = 0;
	unsigned short vid_skb = 0, eth_proto, ppp_proto;
	NAT_CB_T *nat_cb;

	if ((storlink_ctl.hw_vpn & SYSCTL_VPN_ENABLE) == 0)
		return;

	/* check packet. */
	iph = (struct iphdr *)&(skb->data[(u32)l3off]);
	tcph = (struct tcphdr *)((u32)iph + (iph->ihl<<2));
	proto = iph->protocol;

	nat_cb = NAT_SKB_CB(skb);
	if (((u32)nat_cb & 3)) {
		printk("%s:Error: nat_cb is not aligned!!\n", __func__);
		return;
	}

	nat_cb->vpn_tag = NAT_CB_VPN_TAG;
	nat_cb->in_proto = proto;
	/* 
	 * meaning HW NAT has not marked on this packet
	 * we have to mark some additional information
	 */
	if (nat_cb->tag != NAT_CB_TAG) {
		memcpy(nat_cb->sa, skb->data+6, 6);
		nat_cb->sip = iph->saddr;
		nat_cb->dip = iph->daddr;
		nat_cb->input_dev = (unsigned int)skb->dev;

		if ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
			nat_cb->sport = tcph->source;
			nat_cb->dport = tcph->dest;
		}

		/* VLAN */
#ifdef CONFIG_CS351X_DUAL_WAN
		if ((*(skb->data + 12)) == 0x81) {
			vid_skb = (*(skb->data + 15))|(((*(skb->data + 14)) & 0x0F )<<8);
			nat_cb->reserved[0] = vid_skb & 0x00FF;
			nat_cb->reserved[1] = (vid_skb & 0xFF00) >> 8;
		}
#endif

		/* PPPoE check */
		if (vid_skb != 0) {
		/* if it's VLAN packet */
			vlan_ethh = (struct vlan_ethhdr *)skb->data;
			pppoeh = (struct pppoe_hdr *)(skb->data + VLAN_ETH_HLEN);
			eth_proto = vlan_ethh->h_vlan_encapsulated_proto;
		} else {	/* not VLAN */
			ethh = (struct ethhdr *)skb->data;
			pppoeh = (struct pppoe_hdr *)(ethh + 1);
			eth_proto = ethh->h_proto;
		}
		ppp_proto = *(u16 *)&pppoeh->tag[0];

		if (eth_proto == __constant_htons(ETH_P_PPP_SES)	/* 0x8864 */
				&& (ppp_proto == __constant_htons(PPP_IP))) {	/*0x21 */
			pppoe_frame = 1;
		}
		nat_cb->pppoe_frame = pppoe_frame;
	}

	/* if packet is TCP SYN | FIN | RST packet, clean the mark. 
	 * We don't want to create hash yet */
	if ((proto == IPPROTO_TCP) && (tcp_flag_word(tcph) & (TCP_FLAG_SYN |
			TCP_FLAG_FIN | TCP_FLAG_RST))) {
		nat_cb->vpn_tag = 0;
	}


	nat_cb->vpn_spi = 0;

	/* if packet is ESP/AH packet, write info to skb->cb */
	if (proto == IPPROTO_ESP) {
		/* mark on it */
		struct ip_esp_hdr *esph;
		esph = (struct ip_esp_hdr *)&(skb->data[(u32)l4off]);
		nat_cb->vpn_spi = esph->spi;
	}

	if (proto == IPPROTO_AH) {
		/* mark on it */
		struct ip_auth_hdr *ahh;
		ahh = (struct ip_auth_hdr *)&(skb->data[(u32)l4off]);
		nat_cb->vpn_spi = ahh->spi;
	}
	
	return;
}

/* ------------------------------------------------------------------
 * sl351x_ipsec_check_gmac_tx
 * Description: in GMAC TX stage, testing the packet if it's capable 
 * 				of being accelerated by IPsec VPN Accelerated engine.
 * 				if so, with those info in skb->cb and current packet 
 * 				info, create hash entry for the traffic
 * --------------------------------------------------------------- */
int sl351x_ipsec_check_gmac_tx(struct sk_buff *skb, int port)
{
	struct iphdr *iph;
	NAT_CB_T *nat_cb;
	unsigned char proto;
	unsigned int spi_out, rx_sip, rx_dip, tx_sip, tx_dip;
	struct IPSEC_VPN_TUNNEL_CONFIG *tunnel_config;

	if ((storlink_ctl.hw_vpn & SYSCTL_VPN_ENABLE) == 0)
		return 0;

	/* check packet */
	nat_cb = NAT_SKB_CB(skb);
	iph = (struct iphdr *)skb->nh.iph;

	if ((nat_cb->vpn_tag != NAT_CB_VPN_TAG)
			&& (nat_cb->vpn_tag != NAT_CB_VPN2_TAG))
		return 0;

	if (((u32)nat_cb & 3)) {
		printk("%s:Error: nat_cb is not aligned!\n", __func__);
		return 0;
	}

	proto = iph->protocol;

	if (nat_cb->vpn_tag == NAT_CB_VPN_TAG) {
		rx_sip = ntohl(nat_cb->sip);
		rx_dip = ntohl(nat_cb->dip);
		tx_sip = ntohl(iph->saddr);
		tx_dip = ntohl(iph->daddr);

		/* This is LAN->WAN direction */
		if ((proto == IPPROTO_ESP) || (proto == IPPROTO_AH)) {
			if (proto == IPPROTO_ESP) {
				struct ip_esp_hdr *esph;
				esph = (struct ip_esp_hdr *)skb->h.raw;
				spi_out = esph->spi;
			}
			if (proto == IPPROTO_AH) {
				struct ip_auth_hdr *ahh;
				ahh = (struct ip_auth_hdr *)skb->h.raw;
				spi_out = ahh->spi;
			}

			/* check with tunnel/pair info */
			if ((tunnel_config = ipsec_vpn_find_and_verify_path(rx_sip, rx_dip,
					tx_sip, tx_dip, spi_out, MODE_ENCRYPTION)) != NULL) {
				/* this path is verified, so we create hash entry */
				create_ipsec_hash_entry(tunnel_config, skb, port, MODE_ENCRYPTION);
			}
		}

		if ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
			/* no a valid IPsec VPN packet */
			if (nat_cb->vpn_spi == 0) return 0;

			/* if it's TCP SYN | FIN | RST packet, we don't create hash */
			if (proto == IPPROTO_TCP) {
				struct tcphdr *tcph;
				tcph = (struct tcphdr*)((u32)iph + (iph->ihl<<2));
				if (tcp_flag_word(tcph) &
						(TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST))
					return 0;
			}

			/* check with tunnel/pair info */
			if ((tunnel_config = ipsec_vpn_find_and_verify_path(rx_sip, rx_dip,
					tx_sip, tx_dip, nat_cb->vpn_spi, MODE_DECRYPTION)) != NULL) {
				/* this path is verified, so we create hash entry */
				create_ipsec_hash_entry(tunnel_config, skb, port, MODE_DECRYPTION);
			}
		}
	}
	if (nat_cb->vpn_tag == NAT_CB_VPN2_TAG) {
		/*
		 * going to see if we can create hash entry for WAN->LAN, for
		 * this IPsec VPN acceleration module with non GMAC interface
		 * running at LAN
		 */
		tx_dip = ntohl(nat_cb->sip);
		tx_sip = ntohl(nat_cb->dip);
		rx_dip = ntohl(iph->saddr);
		rx_sip = ntohl(iph->daddr);

		if ((proto == IPPROTO_ESP) || (proto == IPPROTO_AH)) {
			/* we don't have correct SPI for incoming packet */
#if 0
			if (proto == IPPROTO_ESP) {
				struct ip_esp_hdr *esph;
				esph = (struct ip_esp_hdr *)skb->h.raw;
				spi_out = esph->spi;
			}
			if (proto == IPPROTO_AH) {
				struct ip_auth_hdr *ahh;
				ahh = (struct ip_auth_hdr *)skb->h.raw;
				spi_out = ahh->spi;
			}
#endif
			if ((tunnel_config = ipsec_vpn_find_and_verify_path(rx_sip, rx_dip,
					tx_sip, tx_dip, 0, MODE_DECRYPTION)) != NULL) {
				/* this path is verified, so we create hash entry */
				create_ipsec_hash_entry(tunnel_config, skb, port, MODE_DECRYPTION_FAST_NET);
			}
		}
	}
	return 0;
}

/* --------------------------------------------------------------------------*
 * ipsec_dev_kfree_skb
 * Description: a more complete dev_kfree_skb that checks destructor first
 * --------------------------------------------------------------------------*/
static inline void ipsec_dev_kfree_skb(struct sk_buff* skb)
{
	if (skb->destructor) dev_kfree_skb_any(skb);
	else dev_kfree_skb(skb);
	skb = NULL;
}

/* ------------------------------------------------------------------*
 * ipsec_vpn_tunnel_start
 * Description: API for setkey to send the needed info to driver
 * ------------------------------------------------------------------*/
void ipsec_vpn_tunnel_start(void)
{
	struct IPSEC_VPN_TUNNEL_CONFIG * tunnel_ptr;
	struct IPSEC_VPN_IP_PAIR_CONFIG * pair_ptr;
	int count, count_pair;

	/* first check the tunnel config with pair config
	 * for each tunnel config, start the hash. also,
	 * complete the tunnel config with info from pair config */

	tunnel_ptr = ipsec_tunnel;
	count = 0;

	while ((tunnel_ptr != NULL) && (count < MAX_IPSEC_TUNNEL)) {
		if (tunnel_ptr->enable == 1) {
			pair_ptr = ipsec_pair;
			count_pair = 0;
			while ((pair_ptr != NULL) && (count_pair < MAX_IPSEC_TUNNEL)) {
				if ((pair_ptr->enable == 1) && 
						(pair_ptr->src_WAN_IP == tunnel_ptr->src_WAN_IP) && 
						(pair_ptr->dst_WAN_IP == tunnel_ptr->dst_WAN_IP)) {
					/* find the matching pair & complete the tunnel config */
					tunnel_ptr->src_LAN = pair_ptr->src_LAN & pair_ptr->src_netmask;
					tunnel_ptr->src_netmask = pair_ptr->src_netmask;
					tunnel_ptr->dst_LAN = pair_ptr->dst_LAN & pair_ptr->dst_netmask;
					tunnel_ptr->dst_netmask = pair_ptr->dst_netmask;
					tunnel_ptr->src_LAN_GW = pair_ptr->src_LAN_GW;
					tunnel_ptr->mode = pair_ptr->direction;
					tunnel_ptr->tableID = count;

					break;
				}
				pair_ptr++;
				count_pair++;
			}
		}
		tunnel_ptr++;
		count++;
	}
}

/* ---------------------------------------------------------------------------
 * sl_fast_ipsec()
 * Description: the method which checks the skb with the valid hardware-enabled 
 *				ipsec-vpn tunnel.  If it matches, this packet will be sent to
 *				hardware VPN path.  This method is called by fast net module.
 * Return 1, if current packet will be handled by hardware VPN. 0, otherwise.
 * --------------------------------------------------------------------------*/
int sl_fast_ipsec(struct sk_buff *skb)
{
	int i, l3_off;
	struct iphdr *iph;
	struct tcphdr *tcph;
	NAT_CB_T *nat_cb;

	skb->data -= ETH_HLEN;
	skb->len += ETH_HLEN;
	l3_off = ipsec_adjust_hdr_location(skb);
	iph = skb->nh.iph;
	tcph = (struct tcphdr *)((u32)iph + (iph->ihl<<2));

	for(i=0; i<IPSEC_VPN_TUNNEL_HW_NUM; i++) {
		if(ipsec_tunnel[i].enable == 0) {
//			printk("tunnel %d enable == 0\n", i);
			continue;
		}

		if ((ipsec_tunnel[i].src_LAN == 
					(ntohl(iph->saddr) & ipsec_tunnel[i].src_netmask))
				&& (ipsec_tunnel[i].dst_LAN  == 
					(ntohl(iph->daddr) & ipsec_tunnel[i].dst_netmask))) {
			//skb->protocol = htons(ETH_P_IP);
			//skb->pkt_type = PACKET_OTHERHOST;
			/*
			 * WiFi or NIC incoming packet matches the configuration 
			 * for this IPsec VPN accelerated traffic
			 */

			/* only process UDP and TCP (not SYN/FIN/RST) packet */
			if ((iph->protocol != IPPROTO_TCP)
					&& (iph->protocol != IPPROTO_UDP))
				goto fast_ipsec_out;

			if ((iph->protocol == IPPROTO_TCP) && (tcp_flag_word(tcph)
					& (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)))
				goto fast_ipsec_out;

			/*
			 * mark on the packet, such that at when it sends through GMAC
			 * TX, we will be able to generate hash entry for WAN->LAN
			 */
			nat_cb = NAT_SKB_CB(skb);
			if (((u32)nat_cb & 3)) {
				printk("%s:Error: nat_cb is not aligned!!\n", __func__);
			}

			nat_cb->vpn_tag = NAT_CB_VPN2_TAG;
			nat_cb->in_proto = iph->protocol;
			if (nat_cb->tag != NAT_CB_TAG) {
				memcpy(nat_cb->sa, skb->data+6, 6);
				nat_cb->sip = iph->saddr;
				nat_cb->dip = iph->daddr;
				nat_cb->input_dev = (unsigned int)skb->dev;

				if ((iph->protocol == IPPROTO_TCP)
						|| (iph->protocol == IPPROTO_UDP)) {
					nat_cb->sport = tcph->source;
					nat_cb->dport = tcph->dest;
				}

				if((*(skb->data + 12)) == 0x81) {
					unsigned short vid_skb;
					vid_skb = (*(skb->data +15))|(((*(skb->data+14))&0x0F)<<8);
					nat_cb->reserved[0] = vid_skb & 0x00FF;
					nat_cb->reserved[1] = (vid_skb & 0xFF00) >> 8;
				}
			} else {
				//printk("%s::nat_cfg->tag should be NULL\n", __func__);
			}

			skb->cb[28] = IPSEC_CB_SKIP_FASTNET;
			if (nat_cb->vpn_tag == NAT_CB_VPN2_TAG) {

				ipsec_handle_skb(skb, i, 1, l3_off);
				//printk("%s - packet handled for LAN->WAN\n", __func__);
				return 1;
			}
		}
	}

fast_ipsec_out:
	skb->data += ETH_HLEN;
	skb->len -= ETH_HLEN;
	return 0;
}
EXPORT_SYMBOL(sl_fast_ipsec);

/* -----------------------------------------------------------------------------
 * skb_send_to_kernel()
 * Description: a simple function that transforms the skb and sends it to kernel
 * ----------------------------------------------------------------*/
static int skb_send_to_kernel(struct sk_buff *skb)
{
	skb->protocol = eth_type_trans(skb, skb->dev);
	/* skip FastNet because this has been rejected by IPsec VPN Acceleration */
	skb->cb[28] = IPSEC_CB_SKIP_FASTNET;

	return netif_receive_skb(skb);
}

#ifdef CONFIG_SL351X_DUALCORE_VLAN
static inline struct sk_buff* read_skb_from_desc_queue(volatile GMAC_RXDESC_T * curr_desc)
{
	struct sk_buff *skb;
	unsigned int temp;

	skb = (struct sk_buff*)__va(REG32(__va((unsigned char*)(curr_desc->word2.buf_adr - SKB_RESERVE_BYTES))));
	temp = (unsigned int)__va((unsigned char*)(curr_desc->word2.buf_adr 
							- SKB_RESERVE_BYTES + 4));
	skb->head = (unsigned char*)__va(REG32(temp));
	skb->data = (unsigned char*)__va(curr_desc->word2.buf_adr);
	skb->tail = skb->data;
	skb->end  = (unsigned char*)__va(REG32((unsigned int)skb->head + 12));

	return skb;
}
#else
static inline struct sk_buff* read_skb_from_desc_queue(volatile GMAC_RXDESC_T * curr_desc)
{
	unsigned int pkt_size = curr_desc->word1.bits.byte_count;

	consistent_sync((void *)__va(curr_desc->word2.buf_adr), pkt_size, PCI_DMA_FROMDEVICE);
	return (struct sk_buff*)(REG32(__va(curr_desc->word2.buf_adr)-SKB_RESERVE_BYTES));
}
#endif

/*------------------------------------------------------------------------
 * ipsec_handle_class_queue
 * Description: to handle packet that's being received by the class queue.
 *				upon successfully receiving, it either passes it to 
 *				ipsec_gmac_process to handle it, or put it in queue in tasklet
 *				and polling mode.  The interrupt routine in GMAC driver will 
 *				call this function upon receiving packets in class queue.
 *------------------------------------------------------------------------*/
int ipsec_handle_class_queue(struct net_device *dev, GMAC_INFO_T *tp, int budget)
{
	TOE_INFO_T *toe = &toe_private_data;
	volatile GMAC_RXDESC_T *curr_desc;
	struct sk_buff *skb;
	volatile DMA_RWPTR_T rwptr;
	unsigned int pkt_size, desc_count, good_frame, chksum_status, rx_status;
	struct net_device_stats *isPtr = (struct net_device_stats *)&tp->ifStatics;
	volatile NONTOE_QHDR_T	*class_qhdr;
	unsigned int desc_base = 0, sw_id, l3_offset;
	unsigned int queue_id, queue_id_start, queue_id_end;
	int rx_pkt_num=0, hash_index, queue_rx_pkt_num;
	IPSEC_HASH_ENTRY_T *ipsec_hash_entry;
	NAT_HASH_ENTRY_T *nat_hash_entry;

	if (tp->port_id == 0) {
		queue_id_start = IPSEC_INBOUND_QID;
		queue_id_end = IPSEC_INBOUND_QID;
	} else { // if (tp->port_id == 1)
		queue_id_start = IPSEC_OUTBOUND_QID;
		queue_id_end = IPSEC_INBOUND_QID_2;
	}

	for (queue_id=queue_id_start; queue_id<=queue_id_end; queue_id++) {
		class_qhdr = (NONTOE_QHDR_T*)TOE_CLASS_Q_HDR_BASE;
		class_qhdr += queue_id;
		desc_base = (unsigned int)toe->class_desc_base 
				+ queue_id*TOE_CLASS_DESC_NUM*sizeof(GMAC_RXDESC_T);
		rwptr.bits32 = readl(&class_qhdr->word1);
		queue_rx_pkt_num = 0;

		while ((rwptr.bits.rptr != rwptr.bits.wptr) &&
				(rx_pkt_num < budget) &&
				(queue_rx_pkt_num < (GMAC_NAPI_WEIGHT>>2))) {
			curr_desc = (GMAC_RXDESC_T*)(desc_base +
					(unsigned int)rwptr.bits.rptr * sizeof(GMAC_RXDESC_T));
			tp->rx_curr_desc = (unsigned int)curr_desc;
			rx_status = curr_desc->word0.bits.status;
			chksum_status = curr_desc->word0.bits.chksum_status;
			tp->rx_status_cnt[rx_status]++;
			tp->rx_chksum_cnt[chksum_status]++;
			desc_count = curr_desc->word0.bits.desc_count;
			pkt_size = curr_desc->word1.bits.byte_count;
			good_frame = 1;

			if ((curr_desc->word0.bits32 & (GMAC_RXDESC_0_T_derr | GMAC_RXDESC_0_T_perr))
					|| (chksum_status & 0x4)
					|| rx_status) {
				good_frame = 0;
				if (rx_status) {
					if (rx_status == 4 || rx_status == 7)
						isPtr->rx_crc_errors++;
				}
				consistent_sync((void *)__va(curr_desc->word2.buf_adr),
						pkt_size, PCI_DMA_FROMDEVICE);
				skb = (struct sk_buff*)(REG32(__va(curr_desc->word2.buf_adr)
						- SKB_RESERVE_BYTES));
				ipsec_dev_kfree_skb(skb);
			}

			if (good_frame == 1) {
				if (curr_desc->word0.bits.drop)
					printk("%s::Drop (GMAC-%d)!!!\n", __func__, tp->port_id);

				skb = read_skb_from_desc_queue(curr_desc);
				if (skb == NULL) {
					printk("Fatal Error!! skb==NULL!\n");
					goto next_rx;
				}
				//isPtr->rx_packets++;
				//if ((skb->len+pkt_size) > (SW_RX_BUF_SIZE+16)) {
				if ((skb->len+pkt_size) > (1514+16)) {
					printk("%s::error in skb allocation (most likely)\n", __func__);
					printk("%s::skb len %d, pkt_size %d\n", __func__, skb->len, pkt_size);
					/* skb->len should equal skb->tail-skb->data
					 * skb->truesize equals skb->end - skb->head */
					printk("skb->len = skb->tail - skb->data = %d\n", skb->tail - skb->data);
					printk("skb->truesize = skb->end - skb->head = %d\n", skb->end - skb->head);
					ipsec_dev_kfree_skb(skb);
				} else {
					hash_index = curr_desc->word1.bits.sw_id;
					sw_id = ipsec_tunnel_id_table[hash_index];

					/* update timer */
					if (ipsec_tunnel[sw_id].mode == MODE_ENCRYPTION) {
						nat_hash_entry = (NAT_HASH_ENTRY_T *)hash_get_entry(hash_index);
						ipsec_hash_timer_table[hash_index] = nat_hash_entry->tmo.interval;
					}
					if (ipsec_tunnel[sw_id].mode == MODE_DECRYPTION) {
						ipsec_hash_entry = (IPSEC_HASH_ENTRY_T *)hash_get_entry(hash_index);
						ipsec_hash_timer_table[hash_index] = ipsec_hash_entry->tmo.interval;
					}

					skb_reserve(skb, RX_INSERT_BYTES);

					if (skb->len != 0) {
						if (storlink_ctl.hw_vpn & SYSCTL_VPN_DEBUG) /* debug message */
							printk("%s::skb->len=%d\n",__func__,skb->len);
						skb->len = 0;
					}

					skb_put(skb, pkt_size);
					skb->dev = dev;
					skb->input_dev = dev;
				//	isPtr->rx_bytes += pkt_size;
					skb->ip_summed = CHECKSUM_UNNECESSARY;
					dev->last_rx = jiffies;

					l3_offset = curr_desc->word3.bits.l3_offset;
					if (storlink_ctl.hw_vpn & SYSCTL_VPN_ENABLE)
						ipsec_handle_skb(skb, sw_id, 0, l3_offset);
					else
						skb_send_to_kernel(skb);
				}
			}
next_rx:
			rwptr.bits.rptr = RWPTR_ADVANCE_ONE(rwptr.bits.rptr, TOE_CLASS_DESC_NUM);
			SET_RPTR(&class_qhdr->word1, rwptr.bits.rptr);
			tp->rx_rwptr.bits32 = rwptr.bits32;
			rwptr.bits32 = readl(&class_qhdr->word1);
			rx_pkt_num++;
			queue_rx_pkt_num++;
		}
	}

#ifdef CONFIG_CRYPTO_BATCH
	if (storlink_ctl.hw_vpn & SYSCTL_VPN_ENABLE)
		ipsec_handle_skb_finish();
#endif
	return (rx_pkt_num+crypto_queue_count);
}

/* ----------------------------------------------------------------------
 * ipsec_handle_skb_nfhook
 * description: it's to handle NF_HOOK okfn and calls ipsec_gmac_process, 
 * 				after NF_HOOK has finished its work
 * --------------------------------------------------------------------*/
static inline int ipsec_handle_skb_nfhook(struct sk_buff *skb)
{
	int result;
	NAT_CB_T *nat_cb = NAT_SKB_CB(skb);
	unsigned int sw_id = nat_cb->vpn_tag;

	nat_cb->vpn_tag = 0;
	skb->data = skb->mac.raw;
	skb->len += (unsigned int)(skb->nh.raw) - (unsigned int)(skb->mac.raw);
	result = ipsec_gmac_process(skb, sw_id);

	if (result == 0) {
		crypto_queue_count++;
		current_crypto_used++;
	}

	if (result != 0) ipsec_dev_kfree_skb(skb);

	return result;
}

/* ----------------------------------------------------------------------------
 * ipsec_handle_skb
 * description: it's to handle a given skb matched with specific tunnel id 
 * 				(sw_id), it calls ipsec_gmac_process to find a free crypto 
 * 				engine packet slot in a static array and update the count in 
 * 				the queue. If the queue is full, it calls process_ipsec_batch 
 * 				to handle the queue first.
 *				Return 0, if success.  And other value, if otherwise.
 * ----------------------------------------------------------------------------*/
int ipsec_handle_skb(struct sk_buff *skb, unsigned int sw_id, unsigned int clone_flag, unsigned int l3_offset)
{
	struct iphdr *ip_hdr;
	int result, l3_off;

	/* find the right IP header starting location */
	if (l3_offset != 0) l3_off = l3_offset;
	else l3_off = ETH_HLEN;

	ip_hdr = (struct iphdr *)(skb->data+l3_off);
	skb->nh.iph = ip_hdr;

	if (ntohs(ip_hdr->tot_len) < (skb->len-l3_off)) {
		if (storlink_ctl.hw_vpn & SYSCTL_VPN_DEBUG) { /* debug message */
			if (ntohs(ip_hdr->tot_len) < 40)
				printk("%s::ip_hdr->tot_len = %d\n", __func__, 
						ntohs(ip_hdr->tot_len));
		}
		skb_trim(skb, ntohs(ip_hdr->tot_len) + l3_off);
	}

	/* for packets coming from a device that's a port of a bridge, we need to 
	 * change skb->dev to the bridge device */
#if 0
	struct net_bridge_port *br_port;
	struct net_bridge_fdb_entry *br_fdb_sa;

	br_port = rcu_dereference(skb->dev->br_port);
	if( br_port != NULL && 
		(br_fdb_sa = br_fdb_get(br_port->br, &(skb->data[6]))) != NULL) {

		br_fdb_sa->ageing_timer = jiffies;
		skb->dev = br_port->br->dev;
		skb->input_dev = skb->dev;

		br_fdb_put(br_fdb_sa);
	}
#endif

	/* all fragmented packets will be handled by kernel.
	 * 0xbfff means everything but not IP_DF (don't fragment) */
	//if ((storlink_ctl.fast_net & 128) ||	/* fast_net debug. */
	if ((ip_hdr->frag_off & htons(0xbfff)) != 0)
		return skb_send_to_kernel(skb);

	/* when LAN packet is too big */
#if 1
	if ((ipsec_tunnel[sw_id].mode == MODE_ENCRYPTION) 
			&& ((skb->len + 38) > skb->dev->mtu))
		return skb_send_to_kernel(skb);
#endif

	if (storlink_ctl.hw_vpn & SYSCTL_VPN_NFHOOK) {
		NAT_CB_T *nat_cb;
		struct ethhdr *eth = (struct ethhdr*)(skb->data);
		nat_cb = NAT_SKB_CB(skb);
		nat_cb->vpn_tag = sw_id;
		skb->mac.raw = skb->data;
		skb->data += l3_off;
		skb->len -= l3_off;

		if (eth->h_proto == __constant_htons(ETH_P_8021Q)) {
			struct vlan_ethhdr *vethhdr = (struct vlan_ethhdr *)(skb->mac.raw);
			unsigned short vlan_TCI = ntohs(vethhdr->h_vlan_TCI);
			struct net_device *vlan_dev;
			unsigned short vid = (vlan_TCI & VLAN_VID_MASK);

			vlan_dev = __find_vlan_dev(skb->dev, vid);
			if (vlan_dev != NULL)
				result = NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, vlan_dev, 
						NULL, ipsec_handle_skb_nfhook);
			else
				result = NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, skb->dev, 
						NULL, ipsec_handle_skb_nfhook);
		} else
			result = NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, skb->dev, NULL, 
					ipsec_handle_skb_nfhook);
		return 0;
	} else {
		result = ipsec_gmac_process(skb, sw_id);

		if (result == 0) {
			crypto_queue_count++;
			current_crypto_used++;
		}

		/* if crypto_queue are all in used!!! 
		 * don't worry, if the queue is full, next time it will not be able 
		 * to add more packets in the current soft queue, then the later 
		 * packets will be dropped until there are spaces available. */
//		if ((current_crypto_used == CRYPTO_QUEUE_SIZE) ||
//				(crypto_queue_count == CRYPTO_QUEUE_SIZE)) {
//			ipsec_handle_skb_finish();
//		}

		/* need to clean skb here.. or it will cause error.
		 * and have TCP or whatever protocol that runs in 
		 * VPN tunnel to deal with missing/error packets */
		if (result !=0) ipsec_dev_kfree_skb(skb);

		return result;
	}
}

/* ----------------------------------------------------------------------------
 * ipsec_handle_skb_finsh()
 * Description: With a successfully filled array of crypto engine packets, the 
 *				starting point of the crypto engine packet, and the number of 
 *				the packets, it calls an API from crypto engine driver, 
 *				process_ipsec_batch, which will handle the crypto engine packets
 *				and fill them in TX descriptor queue of crypto engine.  It also
 *				updates the number of remaing crypto engine packet in the queue.
 * --------------------------------------------------------------------------*/
int ipsec_handle_skb_finish(void)
{
	if (crypto_queue_count > 0) {
		if ((current_crypto_loc - crypto_queue_count) >= 0)
			crypto_queue_count = process_ipsec_batch(CRYPTO_QUEUE, 
					crypto_queue_count, 
					current_crypto_loc-crypto_queue_count, 
					CRYPTO_QUEUE_SIZE);
		else
			crypto_queue_count = process_ipsec_batch(CRYPTO_QUEUE, 
					crypto_queue_count, 
					current_crypto_loc+CRYPTO_QUEUE_SIZE-crypto_queue_count, 
					CRYPTO_QUEUE_SIZE);

		if (crypto_queue_count != 0) {
//			printk("%s::still got some entries remaining in the crypto queue\n",__func__);
			/* schedule a tasklet to handle the remaining packets in the queue? */
			return 1;
		}
	}
	return 0;
}
EXPORT_SYMBOL(ipsec_handle_skb_finish);

/*------------------------------------------------------------------------
 * ipsec_gmac_process()
 * Description: to handle packet that's being received by the class queue.
 *				In batch mode, it finds a free crypto engine packet slot 
 *				from an allocated crypto engine packet array and then complete 
 *				the crypto engine packet.
 *				In default 1-to-1 mode, it will create a new crypto engine
 *				packet, complete the crypto engine packet with necessary
 *				information, and sends it to crypto engine.
 *				Return 0, if succeeds.  And otherwise.
 *------------------------------------------------------------------------*/
int ipsec_gmac_process(struct sk_buff *skb, unsigned int sw_id)
{
	struct IPSEC_PACKET_S *crypto_ops;
	struct IPSEC_VPN_TUNNEL_CONFIG *ipsec_tunnel_ptr = NULL;
	struct iphdr *ip_hdr = NULL;
	struct iphdr *top_ip_hdr = NULL;
	struct ip_esp_hdr *esp_hdr;
	struct ip_auth_hdr *ah_hdr;
	struct ah_data *ahp;
	int result = 0, ip_hdr_len, i;
	int clen, old_skblen = 0, alen, blksize, nfrags, ah_hlen;
	struct sk_buff *trailer;
	unsigned char *temp_auth_check_val;
	unsigned char *temp_ip_hdr_copy;
	int l3_offset;

	
	ipsec_tunnel_ptr = &(ipsec_tunnel[sw_id]);

	if (ipsec_tunnel_ptr == NULL) {
		printk("%s::Connection doesn't belong in existing tunnel configurations\n", __func__);
		printk("src ip = %x, dst ip = %x\n", ntohl(ip_hdr->saddr), ntohl(ip_hdr->daddr));
		return -1;
	}

	if (ipsec_tunnel_ptr->enable == 0) {
		printk("%s::err, tunnel is not enabled\n", __func__);
		return -1;
	}

	/* allocate the ipsec packet for crypto engine */
#ifdef CONFIG_CRYPTO_BATCH
	if (current_crypto_loc == CRYPTO_QUEUE_SIZE)
		current_crypto_loc = 0;
	crypto_ops = &(CRYPTO_QUEUE[current_crypto_loc]);
	
	/* if all the queues are currently being used. either waiting to be filled 
	 * in crypto engine's tx queue or waiting for crypto engine's rx callback 
	 * for post-processing */
	if (current_crypto_used == CRYPTO_QUEUE_SIZE) return 1;

	if (crypto_ops->used == 1) {
		/* just simply drop the current skb.. it's the easiest way to save the 
		 * effort will think about other way to fix it later. */
		return 1;
	}
	crypto_ops->used = 1;
	current_crypto_loc++;
	memset(crypto_ops, 0, sizeof(struct IPSEC_PACKET_S));
#else
	crypto_ops = (struct IPSEC_PACKET_S*)kmalloc(sizeof(struct IPSEC_PACKET_S), 
					GFP_ATOMIC);
	if (crypto_ops != NULL) {
		kfree(crypto_ops);
		return -1;
	}
#endif

	ip_hdr = (struct iphdr*)skb->nh.iph;
	l3_offset = (unsigned int)ip_hdr - (unsigned int)skb->data;
	if ((ipsec_tunnel_ptr->mode == MODE_ENCRYPTION) 
			&& (ipsec_tunnel_ptr->protocol == IPPROTO_ESP)) {

		count_encrypted++;
		read_lock(&ipsec_tunnel_lock);
		/* ip_hdr ttl decrement */
		ip_hdr->ttl--;
		/* recalculate ip header checksum */
		ip_send_check(ip_hdr);

		crypto_ops->op_mode = ENC_AUTH;
		crypto_ops->cipher_algorithm = ipsec_tunnel_ptr->cipher_alg;
		crypto_ops->auth_algorithm = ipsec_tunnel_ptr->auth_alg;
		crypto_ops->auth_result_mode = AUTH_APPEND;
		crypto_ops->iv_size = ipsec_tunnel_ptr->enc_iv_len;
		/* old.. IV changes per SA life time.. till 2.6.19 */
		memcpy(crypto_ops->iv, ipsec_tunnel_ptr->enc_iv, ipsec_tunnel_ptr->enc_iv_len);
		/* new.. IV changes per packet since 2.6.19, enable this in the future */
		//get_random_bytes(crypto_ops->iv, ipsec_tunnel_ptr->enc_iv_len);

		/* insert IP and ESP header into the current skb */
#ifdef SL351X_IPSEC_DEBUG
		int headroom = skb_headroom(skb);
		if (headroom < (IP_HEADER_SIZE + sizeof(struct ip_esp_hdr) 
								+ ipsec_tunnel_ptr->enc_iv_len)) {
			//printk("%s::allocating a new skb to replace the old one\n",__func__);
			struct sk_buff *skb2 = dev_alloc_skb(SW_RX_BUF_SIZE);
			if (skb2 == NULL) {
				printk("%s::fail to allocate a new skb!!\n",__func__);
				return -1;
			}
			skb_put(skb2, skb->len);
			memcpy(skb2->data, skb->data, skb->len);
			ipsec_dev_kfree_skb(skb);
			skb = skb2;
		}
#endif
		skb->data = skb_push(skb, IP_HEADER_SIZE+sizeof(struct ip_esp_hdr)
						+ipsec_tunnel_ptr->enc_iv_len);
		memcpy(skb->data, skb->data+IP_HEADER_SIZE+sizeof(struct ip_esp_hdr)
				+ipsec_tunnel_ptr->enc_iv_len, l3_offset+IP_HEADER_SIZE);

		esp_hdr = (struct ip_esp_hdr*)(skb->data+l3_offset+IP_HEADER_SIZE);
		esp_hdr->spi = ipsec_tunnel_ptr->spi;
		esp_hdr->seq_no = htonl(++ipsec_tunnel_ptr->xfrm->replay.oseq);
		ipsec_tunnel_ptr->current_sequence = ipsec_tunnel_ptr->xfrm->replay.oseq;
		memcpy(skb->data+l3_offset+IP_HEADER_SIZE+sizeof(struct ip_esp_hdr), 
				crypto_ops->iv, ipsec_tunnel_ptr->enc_iv_len);
		clen = skb->len - l3_offset - IP_HEADER_SIZE
				- sizeof(struct ip_esp_hdr) - ipsec_tunnel_ptr->enc_iv_len;
		old_skblen = clen;

		if ((ipsec_tunnel_ptr->auth_alg == 0)
				|| (ipsec_tunnel_ptr->auth_alg == 2))
			alen = 20;
		else if ((ipsec_tunnel_ptr->auth_alg == 1)
				|| (ipsec_tunnel_ptr->auth_alg == 3))
			alen = 16;
		else
			alen = 20;	/* well shouldn't get here. */
		if ((ipsec_tunnel_ptr->cipher_alg == 2)
				|| (ipsec_tunnel_ptr->cipher_alg == 6))
			blksize = 16;
		else
			blksize = 8;
		blksize = ALIGN(blksize, 4);
		clen = ALIGN(clen+2, blksize);
		if ((nfrags = skb_cow_data(skb, clen-old_skblen+alen, &trailer)) < 0)
			printk("%s::it shouldn't get here\n",__func__);
		do {
			for (i=0; i<clen-old_skblen - 2; i++)
				*(u8*)(trailer->tail + i) = i+1;
		} while (0);
		*(u8*)(trailer->tail + clen-old_skblen -2) = (clen - old_skblen)-2;
		pskb_put(skb,trailer, clen-old_skblen);
		*(u8*)(trailer->tail - 1) = IPPROTO_IPIP;
		crypto_ops->auth_header_len = l3_offset + IP_HEADER_SIZE;
		crypto_ops->auth_algorithm_len = clen + sizeof(struct ip_esp_hdr) 
				+ ipsec_tunnel_ptr->enc_iv_len;
		crypto_ops->cipher_header_len = l3_offset + IP_HEADER_SIZE + 
				sizeof(struct ip_esp_hdr) + ipsec_tunnel_ptr->enc_iv_len;
		crypto_ops->cipher_algorithm_len = clen;
		crypto_ops->auth_check_len = (unsigned int)(ipsec_tunnel_ptr->icv_trunc_len / 4);
		crypto_ops->icv_trunc_len = ipsec_tunnel_ptr->icv_trunc_len;
		crypto_ops->icv_full_len = ipsec_tunnel_ptr->icv_full_len;

		ip_hdr = (struct iphdr *)(skb->data+l3_offset);
		ip_hdr->protocol = ipsec_tunnel_ptr->protocol;
		ip_hdr->frag_off = 0;
		for (i=0; i<ipsec_tunnel_ptr->auth_key_len; i++)
			crypto_ops->auth_key[i] = ipsec_tunnel_ptr->auth_key[i];
		crypto_ops->auth_key_size = ipsec_tunnel_ptr->auth_key_len;
		for (i=0; i<ipsec_tunnel_ptr->enc_key_len; i++)
			crypto_ops->cipher_key[i] = ipsec_tunnel_ptr->enc_key[i];
		crypto_ops->cipher_key_size = ipsec_tunnel_ptr->enc_key_len;
		read_unlock(&ipsec_tunnel_lock);
	} else if ((ipsec_tunnel_ptr->mode == MODE_DECRYPTION) 
			&& (ipsec_tunnel_ptr->protocol == IPPROTO_ESP)) {
		count_decrypted++;
		esp_hdr = (struct ip_esp_hdr*)((u32)ip_hdr + IP_HEADER_SIZE);

		read_lock(&ipsec_tunnel_lock);
		if (esp_hdr->seq_no != htonl(++ipsec_tunnel_ptr->current_sequence)) {
			if (esp_hdr->seq_no > htonl(ipsec_tunnel_ptr->current_sequence)) {
				/* lose 1 or more packets */
				ipsec_tunnel_ptr->current_sequence = ntohl(esp_hdr->seq_no);
			}
		}
		ip_hdr_len = ntohs(ip_hdr->tot_len);
		crypto_ops->op_mode = AUTH_DEC;
		crypto_ops->cipher_algorithm = ipsec_tunnel_ptr->cipher_alg;
		crypto_ops->auth_algorithm = ipsec_tunnel_ptr->auth_alg;
		crypto_ops->auth_result_mode = AUTH_CHKVAL;
		crypto_ops->iv_size = ipsec_tunnel_ptr->enc_iv_len;
		memcpy(crypto_ops->iv, (void*)((u32)esp_hdr+sizeof(struct ip_esp_hdr)),
				ipsec_tunnel_ptr->enc_iv_len);
		crypto_ops->auth_header_len = l3_offset + IP_HEADER_SIZE;
		crypto_ops->cipher_header_len = l3_offset + IP_HEADER_SIZE 
				+ sizeof(struct ip_esp_hdr) + ipsec_tunnel_ptr->enc_iv_len;
		crypto_ops->auth_algorithm_len = ip_hdr_len - IP_HEADER_SIZE 
				- ipsec_tunnel_ptr->icv_trunc_len;
		/* subtract IP header, ESP header and AH Trailer */
		crypto_ops->cipher_algorithm_len = ip_hdr_len - IP_HEADER_SIZE 
				- sizeof(struct ip_esp_hdr) -  ipsec_tunnel_ptr->enc_iv_len 
				- ipsec_tunnel_ptr->icv_trunc_len;
		crypto_ops->auth_check_len = (unsigned int)(ipsec_tunnel_ptr->icv_trunc_len / 4);
		crypto_ops->auth_checkval = (unsigned char*)(skb->data + skb->len 
				- ipsec_tunnel_ptr->icv_trunc_len);
		crypto_ops->icv_trunc_len = ipsec_tunnel_ptr->icv_trunc_len;
		crypto_ops->icv_full_len = ipsec_tunnel_ptr->icv_full_len;

		for (i=0; i<ipsec_tunnel_ptr->auth_key_len;i++)
			crypto_ops->auth_key[i] = ipsec_tunnel_ptr->auth_key[i];
		crypto_ops->auth_key_size = ipsec_tunnel_ptr->auth_key_len;
		for (i=0; i<ipsec_tunnel_ptr->enc_key_len;i++)
			crypto_ops->cipher_key[i] = ipsec_tunnel_ptr->enc_key[i];
		crypto_ops->cipher_key_size = ipsec_tunnel_ptr->enc_key_len;
		read_unlock(&ipsec_tunnel_lock);
	} else if ((ipsec_tunnel_ptr->mode == MODE_ENCRYPTION) 
			&& (ipsec_tunnel_ptr->protocol == IPPROTO_AH)) {
		count_encrypted++;

		read_lock(&ipsec_tunnel_lock);
		/* insert IP and AH header into the current skb */
#ifdef SL351X_IPSEC_DEBUG
		int headroom = skb_headroom(skb);
		if (headroom < (IP_HEADER_SIZE+sizeof(struct ip_auth_hdr)
				+ipsec_tunnel_ptr->icv_trunc_len)) {
			struct sk_buff *skb2 = dev_alloc_skb(SW_RX_BUF_SIZE);
			if (skb2 == NULL) {
				printk("%s::fail to allocate a new skb!!\n",__func__);
				return -1;
			}
			skb_put(skb2, skb->len);
			memcpy(skb2->data, skb->data, skb->len);
			ipsec_dev_kfree_skb(skb);
			skb = skb2;
		}
#endif
		skb->data = skb_push(skb, IP_HEADER_SIZE+sizeof(struct ip_auth_hdr)
						+ipsec_tunnel_ptr->icv_trunc_len);
		top_ip_hdr = skb->nh.iph;
		ip_hdr = (struct iphdr*)(skb->data+l3_offset+IP_HEADER_SIZE+
					sizeof(struct ip_auth_hdr)+ipsec_tunnel_ptr->icv_trunc_len);
		memcpy(skb->data, skb->data+IP_HEADER_SIZE
				+sizeof(struct ip_auth_hdr)+ipsec_tunnel_ptr->icv_trunc_len,
				l3_offset);
		((struct ethhdr*)skb->data)->h_proto = ((struct ethhdr*)(skb->data
					+IP_HEADER_SIZE+sizeof(struct ip_auth_hdr)
					+ipsec_tunnel_ptr->icv_trunc_len))->h_proto;
		top_ip_hdr->version = ip_hdr->version;
		top_ip_hdr->ihl = 5;
		top_ip_hdr->tos = 0;
		top_ip_hdr->tot_len = htons(skb->len-l3_offset);
		top_ip_hdr->frag_off = 0;
		top_ip_hdr->ttl = 0;
		top_ip_hdr->protocol = IPPROTO_AH;
		top_ip_hdr->check = 0;
		top_ip_hdr->saddr = htonl(ipsec_tunnel_ptr->src_WAN_IP);
		top_ip_hdr->daddr = htonl(ipsec_tunnel_ptr->dst_WAN_IP);
		top_ip_hdr->id = ip_hdr->id;

		ah_hdr = (struct ip_auth_hdr *)(skb->data+l3_offset+IP_HEADER_SIZE);
		ah_hdr->nexthdr = top_ip_hdr->protocol;

		ahp = ipsec_tunnel_ptr->xfrm->data;
		ah_hdr->hdrlen = (XFRM_ALIGN8(sizeof(struct ip_auth_hdr)
							+ipsec_tunnel_ptr->icv_trunc_len) >> 2)-2;

		ah_hdr->nexthdr = IPPROTO_IPIP;
		ah_hdr->reserved = 0;
		ah_hdr->spi = ipsec_tunnel_ptr->xfrm->id.spi;
		ah_hdr->seq_no = htonl(++ipsec_tunnel_ptr->xfrm->replay.oseq);
		/* set AH->auth_data to 0 */
		memset(skb->data+l3_offset+IP_HEADER_SIZE+sizeof(struct ip_auth_hdr), 
						0x0, ipsec_tunnel_ptr->icv_trunc_len);

		/* 2nd ip_hdr adjustment */
		ip_hdr->ttl--;
		/* recalculate ip header checksum */
		ip_send_check(ip_hdr);

		crypto_ops->op_mode = AUTH;
		crypto_ops->auth_algorithm = ipsec_tunnel_ptr->auth_alg;
		crypto_ops->auth_result_mode = AUTH_APPEND;
		crypto_ops->auth_header_len = l3_offset;
		crypto_ops->auth_algorithm_len = skb->len - l3_offset;
		crypto_ops->auth_check_len = (unsigned int)(ipsec_tunnel_ptr->icv_trunc_len / 4);
//		crypto_ops->auth_checkval = (unsigned char*)(skb->data+skb->len-ipsec_tunnel_ptr->icv_trunc_len);
		crypto_ops->icv_trunc_len = ipsec_tunnel_ptr->icv_trunc_len;
		crypto_ops->icv_full_len = ipsec_tunnel_ptr->icv_full_len;

		for (i=0; i<ipsec_tunnel_ptr->auth_key_len;i++)
			crypto_ops->auth_key[i] = ipsec_tunnel_ptr->auth_key[i];
		crypto_ops->auth_key_size = ipsec_tunnel_ptr->auth_key_len;
		read_unlock(&ipsec_tunnel_lock);
	} else if ((ipsec_tunnel_ptr->mode == MODE_DECRYPTION) 
				&& (ipsec_tunnel_ptr->protocol == IPPROTO_AH)) {
		count_decrypted++;

		read_lock(&ipsec_tunnel_lock);
		top_ip_hdr = skb->nh.iph;
		ah_hdr = (struct ip_auth_hdr *)(skb->data + l3_offset + IP_HEADER_SIZE);
		ahp = (struct ah_data *)(ipsec_tunnel_ptr->xfrm->data);

		ah_hlen = (ah_hdr->hdrlen + 2) << 2;
		if (ah_hlen != XFRM_ALIGN8(sizeof(struct ip_auth_hdr) + ahp->icv_full_len) &&
				ah_hlen != XFRM_ALIGN8(sizeof(struct ip_auth_hdr) + ahp->icv_trunc_len))
			return -1;

		temp_ip_hdr_copy = &(crypto_ops->iv[0]);
		memcpy(temp_ip_hdr_copy,skb->data+l3_offset, 12);
		top_ip_hdr->tos = 0;
		top_ip_hdr->frag_off = 0;
		top_ip_hdr->ttl = 0;
		top_ip_hdr->check = 0;
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		crypto_ops->op_mode = AUTH;
		crypto_ops->auth_algorithm = ipsec_tunnel_ptr->auth_alg;
		crypto_ops->auth_result_mode = AUTH_CHKVAL;
		crypto_ops->auth_header_len = l3_offset;
		crypto_ops->auth_algorithm_len = skb->len - l3_offset;
		crypto_ops->auth_check_len = (unsigned int)(ipsec_tunnel_ptr->icv_trunc_len / 4);
		temp_auth_check_val = &(crypto_ops->cipher_key[0]);
		memcpy(temp_auth_check_val,(void*)((u32)ah_hdr
				+sizeof(struct ip_auth_hdr)), ipsec_tunnel_ptr->icv_trunc_len);
		crypto_ops->auth_checkval = temp_auth_check_val;
		crypto_ops->icv_trunc_len = ipsec_tunnel_ptr->icv_trunc_len;
		crypto_ops->icv_full_len = ipsec_tunnel_ptr->icv_full_len;
		memset((void*)((u32)ah_hdr+sizeof(struct ip_auth_hdr)),
				0x0, ipsec_tunnel_ptr->icv_trunc_len);

		for (i=0; i<ipsec_tunnel_ptr->auth_key_len;i++)
			crypto_ops->auth_key[i] = ipsec_tunnel_ptr->auth_key[i];
		crypto_ops->auth_key_size = ipsec_tunnel_ptr->auth_key_len;
		read_unlock(&ipsec_tunnel_lock);
	} else {
		printk("%s::Something is wrong, packet shouldn't go to other class queue !\n",__func__);
		crypto_ops->used = 0;
		if (current_crypto_loc == 0)
			current_crypto_loc = CRYPTO_QUEUE_SIZE - 1;
		else
			current_crypto_loc--;
		return -1;
	}

	/* create the input scatterlist and make the pointer of IPSEC_PACKET_S to it */
#ifndef CONFIG_CRYPTO_BATCH
	input_ptr = (struct scatterlist *)kmalloc(sizeof(struct scatterlist), 
					GFP_ATOMIC);
	input_ptr->page = virt_to_page((void*)skb->data);
	input_ptr->offset = offset_in_page((void*)skb->data);
	input_ptr->length = skb->len;
	crypto_ops->in_packet = input_ptr;
#endif
	crypto_ops->in_packet2 = (unsigned char*)skb->data;
	crypto_ops->input_skb = skb;

	crypto_ops->pkt_len = skb->len;
	crypto_ops->callback = ipsec_finish_callback;
	crypto_ops->used = 1;
	crypto_ops->out_packet = NULL;

#ifdef CONFIG_SL351X_IPSEC_REUSE_SKB
	/* using new skb rather than resue the old one */
	crypto_ops->output_skb = skb;
	crypto_ops->out_packet2 = (unsigned char*)(crypto_ops->output_skb->data);
#else
	/* the output from crypto engine will be stored in a new skb so later if 
	 * the output is not regonized, malformed, we can netif_rx the original 
	 * packet */
	crypto_ops->output_skb = alloc_skb(MAX_SKB_SIZE,GFP_ATOMIC);
	if (!crypto_ops->output_skb) {
		memset(crypto_ops, 0, sizeof(struct IPSEC_PACKET_S));
		return -1;
	}
	skb_reserve(crypto_ops->output_skb, skb->data - skb->head);
	crypto_ops->output_skb->dev = skb->dev;
	crypto_ops->output_skb->input_dev = skb->dev;
	crypto_ops->output_skb->protocol = skb->protocol;
	crypto_ops->out_packet2 = (unsigned char*)(crypto_ops->output_skb->data);
	crypto_ops->out_buffer_len = MAX_SKB_SIZE;
#endif

	crypto_ops->icv_full_len = ipsec_tunnel_ptr->icv_full_len;
	crypto_ops->icv_trunc_len = ipsec_tunnel_ptr->icv_trunc_len;
	crypto_ops->tunnel_ID = ipsec_tunnel_ptr->tableID;

#ifdef CONFIG_CRYPTO_BATCH
	result = 0;
#else
	result = ipsec_crypto_hw_process(crypto_ops);
#endif

	if (result != 0) {
		printk("%s::Something is wrong when calling ipsec_crypto_hw_process!\n", __func__);
		crypto_ops->used = 0;
		if (current_crypto_loc == 0)
			current_crypto_loc = CRYPTO_QUEUE_SIZE - 1;
		else
			current_crypto_loc--;
	}

	return result;
}

/*--------------------------------------------------------------*
 * ipsec_finish_callback
 * Description: for sl2312_ipsec module to callback the sl351x_ipsec,
 *				so it can send the processed information back and
 *				sl351x_ipsec module can process the encrypted/decrypted
 *				info to GMAC and send it out
 *------------------------------------------------------------*/
void ipsec_finish_callback(struct IPSEC_PACKET_S *ipsec_ptr)
{
	struct iphdr *ip_hdr, *ip_hdr2;
	struct IPSEC_VPN_TUNNEL_CONFIG *ipsec_tunnel_ptr = NULL;
	struct sk_buff *skb, *original_skb;
	u8 nexthdr[2];
	int padlen, l3_offset;

	packet_error = 0;
	crypto_error = 0;

	if (ipsec_ptr->status == 2) {
		packet_error = 1;
		skb = ipsec_ptr->output_skb;
		goto end_finish_callback;
	}

	if (ipsec_ptr->status == 3) {
		crypto_error = 1;
		skb = ipsec_ptr->output_skb;
		goto end_finish_callback;
	}

	skb = ipsec_ptr->output_skb;
	skb->pkt_type = PACKET_OTHERHOST;

	ipsec_tunnel_ptr = &(ipsec_tunnel[ipsec_ptr->tunnel_ID]);

	if (skb->data != ipsec_ptr->out_packet2) {
		printk("%s::...\n",__func__);
		packet_error = 1;
		goto end_finish_callback;
	}

	/* test of crypto'ed packets */
	ipsec_adjust_hdr_location(skb);
	l3_offset = (u32)skb->nh.iph - (u32)skb->data;
	if (ipsec_ptr->used == 0)
		printk("%s::... this shouldn't... happen\n",__func__);

	if ((((ntohl(skb->nh.iph->saddr)&ipsec_tunnel_ptr->src_netmask) != ipsec_tunnel_ptr->src_LAN)
				|| (ipsec_tunnel_ptr->dst_LAN != (ntohl(skb->nh.iph->daddr)&ipsec_tunnel_ptr->dst_netmask)))
			&& (ipsec_tunnel_ptr->mode == MODE_ENCRYPTION)
			&& (ipsec_tunnel_ptr->protocol == IPPROTO_ESP)) {
		packet_error = 1;
		goto end_finish_callback;
	}

	if (((ntohl(skb->nh.iph->saddr) != ipsec_tunnel_ptr->src_WAN_IP)
			|| (ipsec_tunnel_ptr->dst_WAN_IP != ntohl(skb->nh.iph->daddr)))
			&& (ipsec_tunnel_ptr->mode == MODE_DECRYPTION)) {
		packet_error = 1;
		goto end_finish_callback;
	}

	if (ipsec_ptr->op_mode == ENC_AUTH) {
		/* skb management */
		skb->tail = skb->data;
		skb->len = 0;
		skb_put(skb, ipsec_ptr->out_pkt_len);
		skb->data = skb_pull(skb, l3_offset);
		skb->nh.iph->tot_len = htons(skb->len);
		skb->nh.iph->ttl = 128;
		skb->nh.iph->frag_off = 0;

		/* check if the WAN is PPPoE. if so, we have to add in 
		 * PPPoE header between Ethernet header and IP Header */
#if 0
		if ((storlink_ctl.hw_vpn & SYSCTL_VPN_PPPOE)
				&& (ipsec_tunnel_ptr->pppoe_sock)) {
//			printk("%s::got here. going to add pppoe header\n",__func__);

			/* 1) check if headroom is enough for ~6 bytes PPPoE header
			 * if ok, then pull.. if not, allocate a new skb */
			int headroom = skb_headroom(skb);
			struct net_device *dev = ipsec_tunnel_ptr->pppoe_sock->pppoe_dev;
			struct pppoe_hdr * ph;
			unsigned char *pp;
			int proto = PPP_IP;

			if (dev != NULL) {
				packet_error = 1;
				goto end_finish_callback;
			}

			if (headroom < (sizeof(struct pppoe_hdr)+2)) {
				/* if the headroom is not enough, we have to reallocate a new 
				 * skb. */
//				printk("%s::allocating a new skb, because headroom is not enough\n",__func__);
				struct sk_buff *skb2 = dev_alloc_skb(32+skb->len + sizeof(struct pppoe_hdr) 
										+ dev->hard_header_len+2);
				if (skb2 == NULL) {
					packet_error = 1;
					goto end_finish_callback;
				}

				/* copy the information from the old skb to the new skb */
				skb_reserve(skb2, dev->hard_header_len + sizeof(struct pppoe_hdr));
				skb_put(skb2, skb->len+sizeof(struct pppoe_hdr));
				memcpy(skb2->data+dev->hard_header_len+sizeof(struct pppoe_hdr), 
						skb->data+dev->hard_header_len, 
						skb->len-dev->hard_header_len);
				skb2->pkt_type = PACKET_OTHERHOST;
				skb2->nh.iph = (struct iphdr*)(&skb2->data[dev->hard_header_len
								+sizeof(struct pppoe_hdr)+2]);
				ph = (struct pppoe_hdr *)(&skb2->data[dev->hard_header_len]);

				/* clean the old skb */
				ipsec_dev_kfree_skb(skb);
				skb = skb2;
			} else {
				skb->data = skb_push(skb,sizeof(struct pppoe_hdr)+2);
				ph = (struct pppoe_hdr *)(&skb->data[ETH_HLEN]);
			}

			/* 2) fill up pppoe header information */
			ph->ver = 1;
			ph->type = 1;
			ph->code = 0;
			ph->sid = ipsec_tunnel_ptr->pppoe_sock->num;
			ph->length = htons(skb->len - dev->hard_header_len 
							- sizeof(struct pppoe_hdr));

			pp = (unsigned char*)&skb->data[ETH_HLEN+sizeof(struct pppoe_hdr)];

			pp[0] = proto >>  8;
			pp[1] = proto;

			skb->protocol = __constant_htons(ETH_P_PPP_SES);
			skb->nh.raw = skb->data;
			skb->nh.iph = (struct iphdr*)(&skb->data[ETH_HLEN
								+sizeof(struct pppoe_hdr)+2]);
//			printk("%s::finish adding PPPoE header\n",__func__);
		}
#endif
	}

	if (ipsec_ptr->op_mode == AUTH_DEC) {
		if (ipsec_ptr->auth_cmp_result == 0) {
			//printk("%s::fail to authenticate\n", __func__);
			packet_error = 1;
			goto end_finish_callback;
		}

		if (ipsec_ptr->out_pkt_len != ipsec_ptr->pkt_len) {
			//printk("%s::weird problem.. o_O\n",__func__);
			packet_error = 1;
			goto end_finish_callback;
		}

		/* skb management */
		skb->tail = skb->data;
		skb->len = 0;
		skb->data = skb->data + l3_offset + IP_HEADER_SIZE +
				sizeof(struct ip_esp_hdr) + ipsec_tunnel_ptr->enc_iv_len;
		skb_put(skb, ipsec_ptr->out_pkt_len - l3_offset - IP_HEADER_SIZE
				- sizeof(struct ip_esp_hdr) - ipsec_tunnel_ptr->enc_iv_len);
		skb->nh.iph = (struct iphdr*)skb->data;

		if (skb_copy_bits(skb, skb->len - ipsec_ptr->icv_trunc_len - 2, nexthdr, 2))
			BUG();
		padlen = nexthdr[0];
		skb_trim(skb, skb->len - ipsec_ptr->icv_trunc_len - padlen - 2);

		skb->nh.iph->ttl--;
	}

	if (ipsec_ptr->op_mode == AUTH) {
		if (ipsec_ptr->auth_result_mode == AUTH_APPEND) {
			/* skb management */
			skb->tail = skb->data;
			skb->len = 0;
			skb_put(skb,ipsec_ptr->out_pkt_len - ipsec_ptr->icv_trunc_len);
			skb->nh.iph = (struct iphdr*)(&skb->data[ETH_HLEN]);
			ip_hdr = skb->nh.iph;

			ip_hdr2 = (struct iphdr*)(skb->data + ETH_HLEN+IP_HEADER_SIZE+
						sizeof(struct ip_auth_hdr)+ipsec_ptr->icv_trunc_len);

			ip_hdr->tos = ip_hdr2->tos;
			ip_hdr->ttl = 64;
			ip_hdr->frag_off = ip_hdr2->frag_off;
			ip_send_check(ip_hdr);
			
			memcpy(skb->data+ETH_HLEN+IP_HEADER_SIZE+sizeof(struct ip_auth_hdr),
					skb->data+skb->len,ipsec_tunnel_ptr->icv_trunc_len);
		}
		if (ipsec_ptr->auth_result_mode == AUTH_CHKVAL) {
			if (ipsec_ptr->auth_cmp_result == 0) {
				//printk("%s::authentication fails!, kernel ", __func__);
				//printk("is going to handle this packet\n");
				packet_error = 1;
				goto end_finish_callback;
			}

			/* skb management */
			skb->tail = skb->data;
			skb->len = 0;
			skb->data = skb->data + IP_HEADER_SIZE + sizeof(struct ip_auth_hdr) 
					+ ipsec_tunnel_ptr->icv_trunc_len;
			skb_put(skb, ipsec_ptr->out_pkt_len-IP_HEADER_SIZE 
					-sizeof(struct ip_auth_hdr)-ipsec_tunnel_ptr->icv_trunc_len);
			((struct ethhdr *)(skb->data))->h_proto = ((struct ethhdr *)(ipsec_ptr->out_packet2))->h_proto;
			ip_hdr2 = (struct iphdr*)(skb->data + ETH_HLEN);
			ip_hdr2->ttl--;
		}
	}

end_finish_callback:
#ifdef CONFIG_SL351X_IPSEC_REUSE_SKB
	original_skb = NULL;
#else
	original_skb = ipsec_ptr->input_skb;
#endif

	ipsec_gmac_callback(skb, ipsec_ptr,original_skb,ipsec_ptr->flag_polling);
}

/*-----------------------------------------------------------------*
 * ipsec_gmac_callback
 * Description: for sl351x_ipsec to fill up mac address for skb, call 
 *				xmit routine to send the skb out
 *				If the newly created packet is malformed or not able 
 *				to be sent, send the original packet to kernel and have
 *				kernel to handle it.
 *----------------------------------------------------------------*/
int ipsec_gmac_callback(struct sk_buff *skb, struct IPSEC_PACKET_S * ipsec_ptr, struct sk_buff *old_skb, int flag_polling)
{
	struct IPSEC_VPN_TUNNEL_CONFIG * ipsec_tunnel_ptr;
	struct iphdr *ip_hdr = skb->nh.iph;
	__u32 dip, sip;
	__u8 ip_tos;
	/* flag to control which packet is going to be sent */
	int send_new_packet = 1;
	u8 nexthdr[2];
	int padlen, skb_size_for_mtu, iif=0;

	if (crypto_error == 1) {
		if (old_skb != NULL) ipsec_dev_kfree_skb(old_skb);

		if (skb != NULL) ipsec_dev_kfree_skb(skb);

#ifdef CONFIG_CRYPTO_BATCH
		ipsec_ptr->used = 0;
		current_crypto_used--;
#else
		kfree(ipsec_ptr->in_packet);
		kfree(ipsec_ptr);
#endif
		return 0;
	}

	ipsec_tunnel_ptr = &(ipsec_tunnel[ipsec_ptr->tunnel_ID]);

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	if ((ipsec_tunnel_ptr->mode == MODE_ENCRYPTION)
			&& (ipsec_tunnel_ptr->protocol == IPPROTO_ESP)) {
		skb->nh.iph->saddr = htonl(ipsec_tunnel_ptr->src_WAN_IP);
		skb->nh.iph->daddr = htonl(ipsec_tunnel_ptr->dst_WAN_IP);
	}

	if (packet_error == 1) {
		send_new_packet = 0;
		goto send_packet;
	}

	dip = skb->nh.iph->daddr;
	sip = skb->nh.iph->saddr;
	ip_tos = skb->nh.iph->tos;
	skb_size_for_mtu = ntohs(skb->nh.iph->tot_len);

	/*
	 * process of finding destination
	 * 1. find if the routing cache exists or not, if so, send the packet
	 * 	  with the dst found
	 * 2. else, have the kernel handles it, such that there will be a 
	 * 	  routing cache next time when the program comes here again.
	 */
	if ((ipsec_tunnel_ptr->mode == MODE_DECRYPTION) && (old_skb->dev != NULL))
		iif = old_skb->dev->ifindex;
	if (sl351x_ipsec_route_cache(skb, dip, sip, ip_tos) != 0) {
		skb->dev = skb->dst->dev;
		skb->protocol = htons(ETH_P_IP);
		if ((skb->dev->features & NETIF_F_HW_CSUM) == 0)
			ip_send_check(skb->nh.iph);
	} else {
		//deubg WEN
		//if (ipsec_tunnel_ptr->mode == MODE_DECRYPTION)
			//printk("%s:Decryption:dst is not found\n", __func__);
		//else
			//printk("%s:Encryption:dst is not found\n", __func__);
		send_new_packet = 0;
	}

	/* when mtu is smaller than skb size. fragmentation might
	 * involve in this case. have kernel deals with this packet */
	if ((send_new_packet == 1) && (skb->dev->mtu < skb_size_for_mtu)
			&& (dst_mtu((struct dst_entry *)skb->dst) < skb_size_for_mtu)) {
		if (storlink_ctl.hw_vpn & SYSCTL_VPN_DEBUG) { /* debug message */
			printk("%s:err:mtu over size: packet = ", __func__);
			printk("%d vs dev mtu = %d vs", skb_size_for_mtu, skb->dev->mtu);
			printk(" dst mtu = %d\n", dst_mtu((struct dst_entry *)skb->dst));
		}
		send_new_packet = 0;
	}

#if 0		/* do we need this check for packet destined to machine itself? */
	/* check if the destination mac address is the same as dev's mac 
	 * address!! */
	struct  ethhdr *eth = (struct ethhdr *)(skb->data);
	if (send_new_packet && ((eth->h_dest[0] == skb->dev->dev_addr[0]) && 
			(eth->h_dest[1] == skb->dev->dev_addr[1]) &&
			(eth->h_dest[2] == skb->dev->dev_addr[2]) &&
			(eth->h_dest[3] == skb->dev->dev_addr[3]) &&
			(eth->h_dest[4] == skb->dev->dev_addr[4]) &&
			(eth->h_dest[5] == skb->dev->dev_addr[5]))) {
		printk("%s::dst mac matches output device's mac\n",__func__);
#ifdef CONFIG_SL351X_IPSEC_REUSE_SKB
		struct  ethhdr *eth = (struct ethhdr *)(skb->data);
		skb->pkt_type = PACKET_HOST;
		return skb_send_to_kernel(skb);
#else
		send_new_packet = 0;
#endif
	}
#endif

send_packet:
	/*
	 * handle the resulted skb.
	 * if send_new_packet flag is on, the encrypted/decrypted packet will be 
	 * sent out. if not, then original packet will be sent
	 * to kernel and has kernel to handle it.
	 */
	if (send_new_packet == 1) {
		//printk("%s::sending new packet\n",__func__);
		if ((NAT_SKB_CB(old_skb))->vpn_tag == NAT_CB_VPN2_TAG)
			memcpy(skb->cb, old_skb->cb, sizeof(skb->cb));

		if ((storlink_ctl.hw_vpn & SYSCTL_VPN_NFHOOK)
				&& (old_skb->nfmark != 0))
			skb->nfmark = old_skb->nfmark;

		/* clean old skb */
		if (old_skb != NULL) ipsec_dev_kfree_skb(old_skb);

#ifdef CONFIG_CRYPTO_BATCH
		ipsec_ptr->used = 0;
		current_crypto_used--;
#else
		kfree(ipsec_ptr->in_packet);
		kfree(ipsec_ptr);
#endif
		/* for tx routine to know this packet is an IPsec-VPN packet */
		skb->cb[28] = IPSEC_CB_HW_PROCESSED;

		if (storlink_ctl.hw_vpn & SYSCTL_VPN_NFHOOK)
			NF_HOOK(PF_INET, NF_IP_FORWARD, skb, NULL, skb->dev, dst_output);
		else
			dst_output(skb);
	}
	if (send_new_packet == 0) {
		//printk("%s::this packet is going software vpn path\n",__func__);
		if (skb->dst != NULL) dst_release(skb->dst);

		/* for tx routine to know this packet is a IPsec-VPN packet */
		old_skb->cb[28] = IPSEC_CB_SKIP_FASTNET;

		/* clean the new skb */
		if (skb != NULL) ipsec_dev_kfree_skb(skb);

#ifndef CONFIG_SL351X_IPSEC_REUSE_SKB
		/* update the old skb in the case for ESP encryption path, because 
		 * original skb has been modified. */
		if ((ipsec_tunnel_ptr->mode == MODE_ENCRYPTION) 
				&& (ipsec_tunnel_ptr->protocol == IPPROTO_ESP)) {
			int l3_offset;
			l3_offset = (u32)old_skb->nh.iph - (u32)old_skb->data
					- IP_HEADER_SIZE - sizeof(struct ip_esp_hdr)
					- ipsec_tunnel_ptr->enc_iv_len;
			/* encryption */
			memcpy(old_skb->data+IP_HEADER_SIZE+sizeof(struct ip_esp_hdr)
					+ipsec_tunnel_ptr->enc_iv_len, old_skb->data, l3_offset);
			old_skb->data = skb_pull(old_skb, IP_HEADER_SIZE
					+sizeof(struct ip_esp_hdr)+ipsec_tunnel_ptr->enc_iv_len);
			if (skb_copy_bits(old_skb, old_skb->len-2, nexthdr, 2))
				BUG();
			padlen = nexthdr[0];
			skb_trim(old_skb, old_skb->len-padlen-2);
			(ipsec_tunnel_ptr->xfrm->replay.oseq)--;
			ip_hdr = old_skb->nh.iph;
			ip_hdr->ttl++;
			ip_send_check(ip_hdr);
		}

		/* update the old skb in the case of AH decryption path, because 
		 * the original skb has been modified. */
		if ((ipsec_tunnel_ptr->mode == MODE_DECRYPTION) 
				&& (ipsec_tunnel_ptr->protocol == IPPROTO_AH)) {
			int l3_offset = (u32)old_skb->nh.iph - (u32)old_skb->data;
			memcpy(old_skb->data+l3_offset,ipsec_ptr->iv, 12);
			memcpy(old_skb->data+l3_offset+IP_HEADER_SIZE
					+sizeof(struct ip_auth_hdr), ipsec_ptr->cipher_key, 
					ipsec_tunnel_ptr->icv_trunc_len);
		}

		/* updatee the old skb in the case of AH encryption path, because 
		 * original skb has been modified. */
		if ((ipsec_tunnel_ptr->mode == MODE_ENCRYPTION) 
				&& (ipsec_tunnel_ptr->protocol == IPPROTO_AH)) {
			int l3_offset;
			l3_offset = (u32)old_skb->nh.iph - (u32)old_skb->data
					- IP_HEADER_SIZE - sizeof(struct ip_auth_hdr)
					- ipsec_tunnel_ptr->icv_trunc_len;
			memcpy(old_skb->data+IP_HEADER_SIZE+sizeof(struct ip_auth_hdr)
					+ipsec_tunnel_ptr->icv_trunc_len, skb->data, l3_offset);
			old_skb->data = skb_pull(old_skb, IP_HEADER_SIZE
					+sizeof(struct ip_auth_hdr)+ipsec_tunnel_ptr->icv_trunc_len);
			ipsec_tunnel_ptr->xfrm->replay.oseq--;
			ip_hdr = old_skb->nh.iph;
			ip_send_check(ip_hdr);
		}

		if (flag_polling == 1) {
			old_skb->protocol = eth_type_trans(old_skb,old_skb->dev);
			netif_rx(old_skb);
#if 0
			/* crypto_engine is in polling mode, better drop this packet */
			if (old_skb != NULL) ipsec_dev_kfree_skb(old_skb);
#endif
		} else {
			NAT_CB_T *nat_cb;
			nat_cb = NAT_SKB_CB(old_skb);
			if (nat_cb->vpn_tag == NAT_CB_VPN2_TAG) {
				old_skb->data += ETH_HLEN;
				old_skb->len -= ETH_HLEN;
				netif_rx(old_skb);
			} else
				skb_send_to_kernel(old_skb);
		}
#endif
#ifdef CONFIG_CRYPTO_BATCH
		current_crypto_used--;
		ipsec_ptr->used = 0;
#else
		kfree(ipsec_ptr->in_packet);
		kfree(ipsec_ptr);
#endif
	}
	
	return 0;
}

/* ----------------------------------------------------------------*
 * vpn_sysctl_info
 * Description: ioctl handler which is triggered when 
 *				/proc/sys/net/vpn/vpn_pair is changed.
 *				It first reads in the new values, and then updates
 *				tunnel configuration and reset all the connections.
 * ----------------------------------------------------------------*/
static int vpn_sysctl_info(ctl_table *ctl, int write, struct file * filp,
                           void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, i, j, flag;

	ret = proc_dointvec(ctl, write, filp, buffer, lenp, ppos);

	/* update the field of pair info when there is a write action on
	 * /proc/sys/net/vpn/vpn_pair */
	if (write != 0) {
		memset(ipsec_pair, 0, MAX_IPSEC_TUNNEL
				*sizeof(struct IPSEC_VPN_IP_PAIR_CONFIG));
		IPSEC_VPN_TUNNEL_HW_NUM = 0;
		for (i=0 ; i < MAX_IPSEC_TUNNEL ; i++) {
			ipsec_pair[i].enable = (__u8)vpn_info[i*9+0];
			ipsec_pair[i].direction = (__u8)vpn_info[i*9+1];
			ipsec_pair[i].src_LAN = (__u32)vpn_info[i*9+2];
			ipsec_pair[i].src_netmask = (__u32)vpn_info[i*9+3];
			ipsec_pair[i].src_LAN_GW = (__u32)vpn_info[i*9+4];
			ipsec_pair[i].dst_LAN = (__u32)vpn_info[i*9+5];
			ipsec_pair[i].dst_netmask = (__u32)vpn_info[i*9+6];
			ipsec_pair[i].src_WAN_IP = (__u32)vpn_info[i*9+7];
			ipsec_pair[i].dst_WAN_IP = (__u32)vpn_info[i*9+8];

			if (ipsec_pair[i].enable)
				IPSEC_VPN_TUNNEL_HW_NUM++;
		}

		if (IPSEC_VPN_TUNNEL_HW_NUM % 2)
			printk("%s::something might be wrong with the vpn_pair value\n", 
					__func__);

		/* update tunnel */
		for (i=0; i < MAX_IPSEC_TUNNEL ; i++) {
			flag = 0;
			for (j=0; j < IPSEC_VPN_TUNNEL_HW_NUM ; j++) {
				/* find the matching pair to this current tunnel. So we 
				 * change its status to the new status that's been updated */
				if ((ipsec_pair[j].src_WAN_IP == ipsec_tunnel[i].src_WAN_IP) 
						&& (ipsec_pair[j].dst_WAN_IP == ipsec_tunnel[i].dst_WAN_IP) 
						&& (ipsec_pair[j].src_WAN_IP != 0) 
						&& (ipsec_pair[j].dst_WAN_IP != 0)) {
					ipsec_tunnel[i].enable = ipsec_pair[j].enable;
					ipsec_tunnel[i].src_LAN = ipsec_pair[j].src_LAN;
					ipsec_tunnel[i].src_netmask = ipsec_pair[j].src_netmask;
					ipsec_tunnel[i].src_LAN_GW = ipsec_pair[j].src_LAN_GW;
					ipsec_tunnel[i].dst_LAN = ipsec_pair[j].dst_LAN;
					ipsec_tunnel[i].dst_netmask = ipsec_pair[j].dst_netmask;
					ipsec_tunnel[i].mode = ipsec_pair[j].direction;
					flag = 1;
				}
			}
			/* can't find the pair info from the existing tunnel set 
			 * means, the pair has been deleted. clean the tunnel */
#if 0
			if (flag == 0) {
				if (ipsec_tunnel[i].sa_hash_flag == 1) {
					printk("%s::disabling the hash entry for existing running tunnel!\n", __func__);
					hash_set_valid_flag(ipsec_tunnel[i].sa_hash_entry, 0);
					hash_invalidate_entry(ipsec_tunnel[i].sa_hash_entry);
					ipsec_tunnel[i].sa_hash_flag = 0;
				}
//				memset(tunnel_ptr, 0, sizeof(struct IPSEC_VPN_TUNNEL_CONFIG));
			}
#endif
		}

		/* reset connection, because the pair has been reseted. */
//		memset(ipsec_conn, 0, MAX_IPSEC_CONN*sizeof(struct IPSEC_CONN_T));
	}
	return ret;
}

/* ----------------------------------------------------------------------
 * ipsec_hash_timer_func()
 * Description:	timer that cleans inactive hash entry that has been 
 * 				created by IPsec VPN Acceleration
 * ---------------------------------------------------------------------*/
static void ipsec_hash_timer_func(u32 data)
{
	int i;

	for (i=0; i<HASH_TOTAL_ENTRIES; i++) {
		if (ipsec_hash_timer_table[i] != 0) {
			if (ipsec_hash_timer_table[i] < 0) {
				hash_nat_disable_owner(i);
				hash_invalidate_entry(i);
				ipsec_hash_timer_table[i] = 0;
			} else if ((ipsec_hash_timer_table[i] - IPSEC_TIMER_PERIOD) <= 0) {
				ipsec_hash_timer_table[i] = 0;
				/* clean hash entry */
				hash_nat_disable_owner(i);
				hash_invalidate_entry(i);
			} else ipsec_hash_timer_table[i] -= IPSEC_TIMER_PERIOD;
		}
	}

	ipsec_timer_obj.expires = jiffies + (IPSEC_TIMER_PERIOD * HZ);
	add_timer((struct timer_list *)data);
}

MODULE_AUTHOR("Wen Hsu<wen.hsu@cortina-systems.com>");
MODULE_DESCRIPTION("Cortina Systems hardware-accelerated IPSEC-VPN");
