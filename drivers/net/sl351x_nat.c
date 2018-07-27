/****************************************************************************
* Copyright 2006 StorLink Semiconductors, Inc.  All rights reserved.                
*----------------------------------------------------------------------------
* Name			: sl351x_nat.c
* Description	: 
*		Handle Storlink SL351x NAT Functions
*
*
* Packet Flow:
*
*            (xmit)+<--- SW NAT -->+(xmit)
*                  |       ^^      |
*                  |       ||      |
*                  |       ||      |
*   Client <---> GMAC-x  HW-NAT  GMAC-y  <---> Server
*
*
* History
*
*	Date		Writer		Description
*----------------------------------------------------------------------------
*	03/13/2006	Gary Chen	Create and implement
*	07/03/2008	CH HSU		Support DMZ 
*
****************************************************************************/
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
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
#include <linux/if_ether.h>
#include <linux/if_pppox.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ppp_defs.h>
#include <net/ip.h>

#define	 MIDWAY 
#define	 SL_LEPUS

#include <asm/arch/sl2312.h>
#include <asm/arch/sl351x_gmac.h>
#include <asm/arch/sl351x_hash_cfg.h>
#include <asm/arch/sl351x_nat_cfg.h>
#ifdef CONFIG_NETFILTER
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_tcp.h>
#endif

#ifdef CONFIG_CS351X_DUAL_WAN
#include <linux/if_vlan.h>
#endif

//#define NAT_DEBUG_MSG		1
#define _NOT_CHECK_SIP_DIP
//#define	SL351x_NAT_TEST_BY_SMARTBITS		1	// Initialize 32 hash entries and test by SmartBITS
#ifdef CONFIG_RTL8366SR_PHY
#undef VITESSE_G5SWITCH
#define CONFIG_SL351x_RTLDMZ	1
//#define SKIP_NAT_CFG	1
#endif
#ifdef CONFIG_SL351x_NAT

/*----------------------------------------------------------------------
* Definition
*----------------------------------------------------------------------*/
#ifdef CONFIG_SL3516_ASIC
#define CONFIG_SL351x_NAT_TCP_UDP
#define CONFIG_SL351x_NAT_GRE
#define CONFIG_CS351X_IGMP_UDP
#ifdef CONFIG_SL351X_IPSEC
#define CONFIG_SL351x_TCP_UDP_RULE_ID	1	/* Rule 0 is used by ipsec */
#define CONFIG_SL351x_GRE_RULE_ID		2
#define IGMP_RULE						3
#else	/*CONFIG_SL351X_IPSEC*/
#define CONFIG_SL351x_TCP_UDP_RULE_ID	0
#define CONFIG_SL351x_GRE_RULE_ID		1
#define IGMP_RULE						2
#endif	/*CONFIG_SL351X_IPSEC*/
#else	/*CONFIG_SL3516_ASIC*/
#define CONFIG_SL351x_NAT_TCP_UDP
//#define CONFIG_SL351x_NAT_GRE
#define CONFIG_SL351x_TCP_UDP_RULE_ID	0
#define CONFIG_SL351x_GRE_RULE_ID		0
#endif	/*CONFIG_SL3516_ASIC*/

#define	nat_printf					printk
#define NAT_FTP_CTRL_PORT 			(21)	// TCP
#define NAT_H323_PORT				(1720)	// TCP
#define NAT_T120_PORT				(1503)	// TCP
#define NAT_PPTP_PORT				(1723)	// TCP
#define NAT_TFTP_PORT 				(69)	// UDP
#define NAT_DNS_PORT 				(53)	// UDP
#define NAT_NTP_PORT				(123)	// UDP
#define NAT_RAS_PORT				(1719)	// UDP
#define NAT_BOOTP67_PORT			(67)	// UDP
#define NAT_BOOTP68_PORT			(68)	// UDP

#define NAT_TCP_PORT_MAX			64
#define NAT_UDP_PORT_MAX			64
#define MIN_READ					0xf6000000
#define MAX_READ					0xf7000000

#define GRE_PROTOCOL				(0x880b)
#define GRE_PROTOCOL_SWAP			__constant_htons(0x880b)

extern int Giga_switch;

extern int Tantos_switch;
u_int8_t key_da[6], key_da_del[6];
u_int32_t key_dip, key_dip_del, timeout = 0;

#ifdef GMAC_DEBUG_U	
extern int gmac_dump_rxpkt;
extern int gmac_dump_txpkt;
#endif

#if 0	/* Remove sl_switch.c, it is a module now */
extern int switch_showing_flag;	
extern int switch_reset_flag;		
#endif //#if 0

typedef struct
{
	u16		flags_ver;
	u16		protocol;
	u16		payload_length;
	u16		call_id;
	u32		seq;
	u32		ack;
} GRE_PKTHDR_T;
	
/*----------------------------------------------------------------------
* NAT Configuration
* 
* Note: Any change for network setting, the NAT configuration should 
*       be changed also.
*	cfg->lan_port	0 if GMAC-0, 1: if GMAC-1
*	cfg->wan_port	0 if GMAC-0, 1: if GMAC-1
*	cfg->lan_ipaddr, cfg->lan_gateway, cfg->lan_netmask
*	cfg->wan_ipaddr, cfg->wan_gateway, cfg->wan_netmask
*	
*----------------------------------------------------------------------*/
NAT_CFG_T 		nat_cfg;
static int		nat_initialized;
u32 			nat_collision;

#ifdef CONFIG_SL351x_NAT_TCP_UDP
static u16		fixed_tcp_port_list[]={NAT_FTP_CTRL_PORT,
							   			NAT_H323_PORT,
							   			// NAT_T120_PORT,
							   			NAT_PPTP_PORT,
										0};
static u16		fixed_udp_port_list[]={NAT_DNS_PORT,
									  	NAT_NTP_PORT,
									  	NAT_TFTP_PORT,
										NAT_RAS_PORT,
									  	NAT_BOOTP67_PORT,
									  	NAT_BOOTP68_PORT,
									   	0};
#endif									   	

// #define _HAVE_DYNAMIC_PORT_LIST
#ifdef _HAVE_DYNAMIC_PORT_LIST									   	
static u16		dynamic_tcp_port_list[NAT_TCP_PORT_MAX+1];
static u16		dynamic_udp_port_list[NAT_UDP_PORT_MAX+1]};
#endif

wait_queue_head_t url_block_wait;
unsigned char block_url_info[sizeof(struct iphdr)+sizeof(struct tcphdr)];
unsigned int url_block_len;

int sl351x_nat_tcp_udp_output(struct sk_buff *skb, int port);
int sl351x_igmp_udp_output(struct sk_buff *skb, int port);
int sl351x_nat_udp_output(struct sk_buff *skb, int port);
int sl351x_nat_gre_output(struct sk_buff *skb, int port);
void igmp_add_hash_entry(void); 
void igmp_del_hash_entry(u_int8_t port, u_int32_t vlan, u_int32_t protocol);  
void conntrack_del_hash_entry(int port, u32 srcip, u32 dstip, u16 proto, u32 sport, u32 dport);

extern int mac_set_rule_reg(int mac, int rule, int enabled, u32 reg0, u32 reg1, u32 reg2);
extern void hash_dump_entry(int index);
extern void mac_get_hw_tx_weight(struct net_device *dev, char *weight);
extern void mac_set_hw_tx_weight(struct net_device *dev, char *weight);
extern void mac_get_sw_tx_weight(struct net_device *dev, char *weight);
extern void mac_set_sw_tx_weight(struct net_device *dev, char *weight);
extern void phy_write_masked(unsigned char port_no,unsigned char reg,unsigned int val,unsigned int mask);
extern void dm_byte(u32 location, int length);

#if 0	/* Remove sl_switch.c, it is a module now */
extern int phy_read(unsigned char port_no, unsigned char reg);
extern void phy_write(unsigned char port_no, unsigned char reg, unsigned int val);
extern void switch_show_statistics(int do_reset);
#endif //#if 0

#ifdef SL351x_NAT_TEST_BY_SMARTBITS
static void nat_init_test_entry(void);
#endif

extern unsigned int mii_read(unsigned char phyad,unsigned char regad);
extern void mii_write(unsigned char phyad,unsigned char regad,unsigned int value);
extern void dm_long_1(u32 location, int length);
extern void dm_short(u32 location, int length);
extern void dm_byte(u32 location, int length);
/*----------------------------------------------------------------------
* sl351x_nat_init
*	initialize a NAT matching rule
*	Called by SL351x Driver
*		key		: port, protocol, Sip, Dip, Sport, Dport
*		Action	: Srce Q: HW Free Queue,
*				  Dest Q: HW TxQ
*				  Change DA
*				  Change SA
*                 Change Sip or Dip
*    			  Change Sport or Dport
*----------------------------------------------------------------------*/
void sl351x_nat_init(void)
{
	int					rc;
	GMAC_MRxCR0_T		mrxcr0;
	GMAC_MRxCR1_T		mrxcr1;
	GMAC_MRxCR2_T		mrxcr2;
	NAT_CFG_T			*cfg;
	
	if (nat_initialized)
		return;

	nat_initialized = 1;
		
	if ((sizeof(NAT_HASH_ENTRY_T) > HASH_MAX_BYTES) ||
		(sizeof(GRE_HASH_ENTRY_T) > HASH_MAX_BYTES) ||
		(sizeof(NAT_0_HASH_ENTRY_T) > HASH_MAX_BYTES)) 
	{
		nat_printf("NAT_HASH_ENTRY_T structure Size is too larger!\n");
		while(1);
	}
		
	cfg = (NAT_CFG_T *)&nat_cfg;
	memset((void *)cfg, 0, sizeof(NAT_CFG_T));
#ifdef _HAVE_DYNAMIC_PORT_LIST
	memset((void *)dynamic_tcp_port_list, 0, sizeof(dynamic_tcp_port_list));
	memset((void *)dynamic_udp_port_list, 0, sizeof(dynamic_udp_port_list));
#endif

	if(Giga_switch || Tantos_switch)
	{
		cfg->enabled			= 1;
		cfg->tcp_udp_rule_id 	= CONFIG_SL351x_TCP_UDP_RULE_ID;
		cfg->gre_rule_id 		= CONFIG_SL351x_GRE_RULE_ID;
#ifdef CONFIG_RTL8366SR_PHY	
		cfg->lan_port			= GMAC_PORT0;
		cfg->wan_port			= GMAC_PORT1;
#else				
		cfg->lan_port			= GMAC_PORT1;
		cfg->wan_port			= GMAC_PORT0;
#endif			
		cfg->default_hw_txq 	= 0;
		cfg->tcp_tmo_interval 	= 60;
		cfg->udp_tmo_interval 	= 180;
		cfg->gre_tmo_interval 	= 60;
	}
	else
	{
		cfg->enabled			= 1;
		cfg->tcp_udp_rule_id 	= CONFIG_SL351x_TCP_UDP_RULE_ID;
		cfg->gre_rule_id 		= CONFIG_SL351x_GRE_RULE_ID;
		cfg->lan_port			= GMAC_PORT0;
		cfg->wan_port			= GMAC_PORT1;
		cfg->default_hw_txq 	= 0;
		cfg->tcp_tmo_interval 	= 60;
		cfg->udp_tmo_interval 	= 180;
		cfg->gre_tmo_interval 	= 60;
		
	}

#ifndef SKIP_NAT_CFG	
#if 1	//	debug purpose
	cfg->gmacDev[0].lan_wan_status = HW_NAT_LAN;
	cfg->gmacDev[0].ipcfg.total				= 1;
	cfg->gmacDev[0].ipcfg.entry[0].ipaddr	= IPIV(192,168,1,1);	// 192.168.2.92
	cfg->gmacDev[0].ipcfg.entry[0].netmask	= IPIV(255,255,255,0);
	cfg->gmacDev[1].lan_wan_status = HW_NAT_WAN;
	cfg->gmacDev[1].ipcfg.total				= 1;
	cfg->gmacDev[1].ipcfg.entry[0].ipaddr	= IPIV(192,168,3,50);	// 192.168.1.200
	cfg->gmacDev[1].ipcfg.entry[0].netmask	= IPIV(255,255,255,0);
#endif

#if 1
	cfg->xport.total = 0;
#else
	cfg->xport.total = 4;
	
	// H.323/H.225 Call setup
	cfg->xport.entry[0].protocol = IPPROTO_TCP;
	cfg->xport.entry[0].sport_start = 0;
	cfg->xport.entry[0].sport_end = 0;
	cfg->xport.entry[0].dport_start = 1720;
	cfg->xport.entry[0].dport_end = 1720;
	cfg->xport.entry[1].protocol = IPPROTO_TCP;
	cfg->xport.entry[1].sport_start = 1720;
	cfg->xport.entry[1].sport_end = 1720;
	cfg->xport.entry[1].dport_start = 0;
	cfg->xport.entry[1].dport_end = 0;
	
	// RAS Setup
	cfg->xport.entry[2].protocol = IPPROTO_UDP;
	cfg->xport.entry[2].sport_start = 0;
	cfg->xport.entry[2].sport_end = 0;
	cfg->xport.entry[2].dport_start = 1719;
	cfg->xport.entry[2].dport_end = 1719;
	cfg->xport.entry[3].protocol = IPPROTO_UDP;
	cfg->xport.entry[3].sport_start = 1719;
	cfg->xport.entry[3].sport_end = 1719;
	cfg->xport.entry[3].dport_start = 0;
	cfg->xport.entry[3].dport_end = 0;
#endif	
#endif  // SKIP_NAT_CFG

#ifdef CONFIG_SL351x_NAT_TCP_UDP
	mrxcr0.bits32 = 0;
	mrxcr1.bits32 = 0;
	mrxcr2.bits32 = 0;
	mrxcr0.bits.port = 1;
	mrxcr0.bits.priority = cfg->tcp_udp_rule_id;
	mrxcr0.bits.l3 = 1;
	mrxcr0.bits.l4 = 1;
	mrxcr1.bits.sip = 1;
	mrxcr1.bits.dip = 1;
	mrxcr1.bits.l4_byte0_15 = 0x0f;	/* Byte 0-3 */
	mrxcr0.bits.sprx = 3; /* 1st and 4nd words of L4 byte selects swap */
#ifdef CONFIG_CS351X_DUAL_WAN
	mrxcr0.bits.l2 = 1;
	mrxcr0.bits.vlan = 1;
//	mrxcr0.bits.pppoe = 1;
#endif
	rc = mac_set_rule_reg(GMAC_PORT0, cfg->tcp_udp_rule_id, 1, mrxcr0.bits32, mrxcr1.bits32, mrxcr2.bits32);
	if (rc < 0) {
		nat_printf("NAT Failed to set MAC-%d Rule %d!\n", GMAC_PORT0, cfg->tcp_udp_rule_id);
	}

	rc = mac_set_rule_reg(GMAC_PORT1, cfg->tcp_udp_rule_id, 1, mrxcr0.bits32, mrxcr1.bits32, mrxcr2.bits32);
	if (rc < 0) {
		nat_printf("NAT Failed to set MAC-%d Rule %d!\n", GMAC_PORT1, cfg->tcp_udp_rule_id);
	}
#endif // CONFIG_SL351x_NAT_TCP_UDP

#ifdef CONFIG_SL351x_NAT_GRE
	mrxcr0.bits32 = 0;
	mrxcr1.bits32 = 0;
	mrxcr2.bits32 = 0;
	mrxcr0.bits.port = 1;
	mrxcr0.bits.priority = cfg->gre_rule_id;
	mrxcr0.bits.l3 = 1;
	mrxcr0.bits.l4 = 1;
	mrxcr1.bits.sip = 1;
	mrxcr1.bits.dip = 1;
	mrxcr1.bits.l4_byte0_15 = 0xcc;	// Byte 2, 3, 6, 7
	mrxcr0.bits.sprx = 4;			// see GMAC driver about SPR
#ifdef CONFIG_CS351X_DUAL_WAN
	mrxcr0.bits.l2 = 1;
	mrxcr0.bits.vlan = 1;
//	mrxcr0.bits.pppoe = 1;
#endif
	
	rc = mac_set_rule_reg(GMAC_PORT0, cfg->gre_rule_id, 1, mrxcr0.bits32, mrxcr1.bits32, mrxcr2.bits32);
	if (rc < 0) {
		nat_printf("NAT Failed to set MAC-%d Rule %d!\n", GMAC_PORT0, cfg->gre_rule_id);
	}

	rc = mac_set_rule_reg(GMAC_PORT1, cfg->gre_rule_id, 1, mrxcr0.bits32, mrxcr1.bits32, mrxcr2.bits32);
	if (rc < 0) {
		nat_printf("NAT Failed to set MAC-%d Rule %d!\n", GMAC_PORT1, cfg->gre_rule_id);
	}
#endif

#ifdef CONFIG_CS351X_IGMP_UDP
	mrxcr0.bits32 = 0;
	mrxcr1.bits32 = 0;
	mrxcr2.bits32 = 0;
	mrxcr0.bits.port = 1;
	mrxcr0.bits.l2 = 1;
	mrxcr0.bits.da = 1;
	mrxcr0.bits.priority = IGMP_RULE;
	mrxcr0.bits.l3 = 1;
	mrxcr1.bits.dip = 1;
	mrxcr0.bits.sprx = 3;	/*Support TCP/UDP Protocol*/
#ifdef CONFIG_CS351X_DUAL_WAN
	mrxcr0.bits.l2 = 1;
	mrxcr0.bits.vlan = 1;
//	mrxcr0.bits.pppoe = 1;
#endif

	rc = mac_set_rule_reg(GMAC_PORT0, IGMP_RULE, 1, mrxcr0.bits32, mrxcr1.bits32, mrxcr2.bits32);
	if (rc < 0) {
		nat_printf("IGMP Failed to set MAC-%d Rule %d!\n", GMAC_PORT0, IGMP_RULE);
	}

	rc = mac_set_rule_reg(GMAC_PORT1, IGMP_RULE, 1, mrxcr0.bits32, mrxcr1.bits32, mrxcr2.bits32);
	if (rc < 0)	{
		nat_printf("IGMP Failed to set MAC-%d Rule %d!\n", GMAC_PORT1, IGMP_RULE);
	}
#endif // CONFIG_CS351X_IGMP_UDP

	init_waitqueue_head(&url_block_wait);
	
#ifdef SL351x_NAT_TEST_BY_SMARTBITS
	nat_init_test_entry();
#endif
}

/*----------------------------------------------------------------------
* sl351x_nat_add_path
*----------------------------------------------------------------------*/
static inline int sl351x_nat_add_path(NAT_GMACDEV_T *gmacdev_in, unsigned int vid_in, NAT_GMACDEV_T *gmacdev_out, unsigned int vid_out)
{
	int i;
	NAT_PATH_ENTRY_T *natpath;

	if ((gmacdev_in->dev == gmacdev_out->dev) && (vid_in == vid_out))
		return 1;		// in device == out device
	natpath = (NAT_PATH_ENTRY_T *)&gmacdev_in->hw_nat_path.entry[0];
	for (i=0; i<gmacdev_in->hw_nat_path.total; i++, natpath++) {
		if ((natpath->out_dev == gmacdev_out->dev)
				&& (natpath->out_vlan_id == vid_out)
				&& (natpath->vlan_id == vid_in))
			return 2;	// path existed
	}
	if (gmacdev_in->hw_nat_path.total < CONFIG_NAT_MAX_PATH) {
		gmacdev_in->hw_nat_path.entry[gmacdev_in->hw_nat_path.total].out_dev = gmacdev_out->dev;
		strcpy(gmacdev_in->hw_nat_path.entry[gmacdev_in->hw_nat_path.total].name, gmacdev_out->dev->name);
		gmacdev_in->hw_nat_path.entry[gmacdev_in->hw_nat_path.total].vlan_id = vid_in;
		gmacdev_in->hw_nat_path.entry[gmacdev_in->hw_nat_path.total].out_vlan_id = vid_out;
		gmacdev_in->hw_nat_path.total++;
	}
	else
		return 3;		// too big

	return 0;
}

/*----------------------------------------------------------------------
* sl351x_nat_del_path
*----------------------------------------------------------------------*/
static inline int sl351x_nat_del_path(NAT_GMACDEV_T *gmacdev_in, unsigned int vid_in, NAT_GMACDEV_T *gmacdev_out, unsigned int vid_out)
{
	int i, j;
	NAT_PATH_ENTRY_T *natpath;
	NAT_PATH_ENTRY_T *natpath_next;

	natpath = (NAT_PATH_ENTRY_T *)&gmacdev_in->hw_nat_path.entry[0];
	for (i=0; i<gmacdev_in->hw_nat_path.total; i++, natpath++) {
		if ((natpath->out_dev == gmacdev_out->dev) 
				&& (natpath->vlan_id == vid_in)
				&& (natpath->out_vlan_id == vid_out)) {
			natpath_next = natpath + 1;
			for (j=i+1; j<gmacdev_in->hw_nat_path.total; i++, j++) {
				memcpy((void *)natpath, (void *)natpath_next, sizeof(NAT_PATH_ENTRY_T));
				natpath++;
				natpath_next++;
				natpath->out_dev = NULL;
				memset(natpath->name, 0, IFNAMSIZ);
			}
			gmacdev_in->hw_nat_path.total--;
			return 0;
		}
	}
	return 1; // no match is found
}

/*----------------------------------------------------------------------
* sl351x_nat_allow_all_hw_nat_path
*----------------------------------------------------------------------*/
static inline void sl351x_nat_allow_all_hw_nat_path(void)
{
	int i, j;

	for (i=0; i<CONFIG_GMAC_DEVICE_NUM; i++) {
		if (nat_cfg.gmacDev[i].dev == NULL) return;

		nat_cfg.gmacDev[i].hwNAT_enabled = 1;
		for (j=0; j<CONFIG_GMAC_DEVICE_NUM; j++) {
			if ((i != j) && (nat_cfg.gmacDev[j].dev != NULL)) {
				sl351x_nat_add_path(&nat_cfg.gmacDev[i], 0, &nat_cfg.gmacDev[j], 0);
			}
		}
	}
	return;
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
* nat_0_build_keys
*	Note: To call this routine, the key->rule_id MUST be zero
*----------------------------------------------------------------------*/
static inline int nat_0_build_keys(NAT_KEY0_T *key)
{
	return hash_gen_crc16((unsigned char *)key, NAT_KEY0_SIZE) & HASH_BITS_MASK;
}

/*----------------------------------------------------------------------
* gre_build_keys
*	Note: To call this routine, the key->rule_id MUST be zero
*----------------------------------------------------------------------*/
static inline int gre_build_keys(GRE_KEY_T *key)
{
	return hash_gen_crc16((unsigned char *)key, GRE_KEY_SIZE) & HASH_BITS_MASK;
}

/*----------------------------------------------------------------------
* igmp_build_keys
*	Note: To call this routine, the key->rule_id MUST be zero
*----------------------------------------------------------------------*/
static inline int igmp_build_keys(IGMP_KEY_T *key)
{
	return hash_gen_crc16((unsigned char *)key, IGMP_KEY_SIZE) & HASH_BITS_MASK;
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
* nat_0_write_hash_entry
*----------------------------------------------------------------------*/
static inline int nat_0_write_hash_entry(int index, void *hash_entry)
{
	int		i;
	u32		*srcep, *destp, *destp2;
	
	srcep = (u32 *)hash_entry;
	destp = destp2 = (u32 *)&hash_tables[index][0];
	
	for (i=0; i<(NAT_0_HASH_ENTRY_SIZE/sizeof(u32)); i++)
		*destp++ = *srcep++;

	consistent_sync(destp2, NAT_0_HASH_ENTRY_SIZE, PCI_DMA_TODEVICE);
	return 0;
}

/*----------------------------------------------------------------------
* gre_write_hash_entry
*----------------------------------------------------------------------*/
static inline int gre_write_hash_entry(int index, void *hash_entry)
{
	int		i;
	u32		*srcep, *destp, *destp2;
	
	srcep = (u32 *)hash_entry;
	destp = destp2 = (u32 *)&hash_tables[index][0];
	
	for (i=0; i<(GRE_HASH_ENTRY_SIZE/sizeof(u32)); i++)
		*destp++ = *srcep++;
	
	consistent_sync(destp2, GRE_HASH_ENTRY_SIZE, PCI_DMA_TODEVICE);
	return 0;
}

/*----------------------------------------------------------------------
* igmp_write_hash_entry
*----------------------------------------------------------------------*/
static inline int igmp_write_hash_entry(int index, void *hash_entry)
{
	int		i;
	u32		*srcep, *destp, *destp2;
	
	srcep = (u32 *)hash_entry;
	destp = destp2 = (u32 *)&hash_tables[index][0];
	
	for (i=0; i<(IGMP_HASH_ENTRY_SIZE/sizeof(u32)); i++)
		*destp++ = *srcep++;
	
	consistent_sync(destp2, IGMP_HASH_ENTRY_SIZE, PCI_DMA_TODEVICE);
	return 0;
}

/*----------------------------------------------------------------------
* sl351x_nat_find_ipcfg
*	return NULL if not found
*----------------------------------------------------------------------*/
static NAT_IP_ENTRY_T *sl351x_nat_find_ipcfg(u32 ipaddr, void *gmacdev, unsigned int vlan_id)
{
	int				i;
	NAT_IP_ENTRY_T	*ipcfg;
	
	ipcfg = (NAT_IP_ENTRY_T *)&(((NAT_GMACDEV_T*)gmacdev)->ipcfg.entry[0]);
	for (i=0; i<((NAT_GMACDEV_T*)gmacdev)->ipcfg.total; i++, ipcfg++)
	{
		if ((ipaddr == ipcfg->ipaddr) && (vlan_id == ipcfg->vlan_id))
		{
			return ipcfg;
		}
	}
	return NULL;
}

/*----------------------------------------------------------------------
* sl351x_nat_assign_qid
*----------------------------------------------------------------------*/
static int sl351x_nat_assign_qid(u8 proto, u32 sip, u32 dip, u16 sport, u16 dport)
{
	int 				i, total, qid;
	NAT_WRULE_ENTRY_T	*entry;
	
	for (qid = 0; qid<CONFIG_NAT_TXQ_NUM; qid++)
	{
		if (qid == nat_cfg.default_hw_txq)
			continue;
			
		entry = (NAT_WRULE_ENTRY_T *)&nat_cfg.wrule[qid].entry[0];
		total = nat_cfg.wrule[qid].total;
		for (i=0; i<total; i++, entry++)
		{
			if (!entry->protocol || entry->protocol==proto)
			{
				//if (!entry->sip_start && !entry->dip_start && !entry->sport_start && !entry->dport_start)
				//	continue; // UI take care
				if (entry->sip_start && !((sip >= entry->sip_start) && 
									   (sip <= entry->sip_end)))
					continue;
				if (entry->dip_start && !((dip >= entry->dip_start) && 
									   (dip <= entry->dip_end)))
					continue;
				if (entry->sport_start && !((sport >= entry->sport_start) && 
									   (sport <= entry->sport_end)))
					continue;
				if (entry->dport_start && !((dport >= entry->dport_start)
					 			       && (dport <= entry->dport_end)))
					continue;
				return qid;
				
			}
		}
	}
	return nat_cfg.default_hw_txq;
}

/*----------------------------------------------------------------------
* sl351x_hash_scan_and_invalidate
* Invalidate HW NAT session for ioctl parameter of nat_cfg !
*----------------------------------------------------------------------*/
void sl351x_hash_scan_and_invalidate(u32 src,u32 dst, u16 proto, u32 sport, u32 dport)
{	
	int					 i,cnt = 0,clean = 0;
	NAT_HASH_ENTRY_T 	*nat_entry;
	
	for(i = 0;i < HASH_TOTAL_ENTRIES; i++)	// scan hash table
	{
		if(hash_get_valid_flag(i))		// compare if valid bit on
		{
			nat_entry = hash_get_entry(i);
			if((src != 0) && (dst != 0))	// both sip,dip are specified
			{
				if((nat_entry->key.sip == src) && (nat_entry->key.dip == dst))
				{
					if(nat_entry->key.ip_protocol == proto) {
						if(sport && dport)	// both port are specified and match
						{
							if((nat_entry->key.dport >= (dport & 0x0000FFFF) && nat_entry->key.dport <= ((dport & 0xFFFF0000) >> 16)) && \
								(nat_entry->key.sport >= (sport & 0x0000FFFF) && nat_entry->key.sport <= ((sport & 0xFFFF0000) >> 16)) )
								clean = 1;
						}
						else if(sport)		// only sport specified
						{
							if(nat_entry->key.sport >= (sport & 0x0000FFFF) && nat_entry->key.sport <= ((sport & 0xFFFF0000) >> 16) )
								clean = 1;
						}
						else if(dport)		// only dport specified
						{
							if(nat_entry->key.dport >= (dport & 0x0000FFFF) && nat_entry->key.dport <= ((dport & 0xFFFF0000) >> 16))
								clean = 1;
							else			// no port specified
								clean = 1;
						}
					}
					else if(proto == 0)
						clean = 1;
				}
			}
			else if(src != 0)				// only sip specified
			{
				if( nat_entry->key.sip == src)
				{
					if((nat_entry->key.ip_protocol == proto)){
						if(sport && dport)	// both specified and match
						{
							if((nat_entry->key.dport >= (dport & 0x0000FFFF) && nat_entry->key.dport <= ((dport & 0xFFFF0000) >> 16)) && \
								(nat_entry->key.sport >= (sport & 0x0000FFFF) && nat_entry->key.sport <= ((sport & 0xFFFF0000) >> 16)))
								clean = 1;
						}
						else if(sport)		// only sport specified
						{
							if(nat_entry->key.sport >= (sport & 0x0000FFFF) && nat_entry->key.sport <= ((sport & 0xFFFF0000) >> 16) )
								clean = 1;
						}
						else if(dport)		// only dport specified
						{
							if(nat_entry->key.dport >= (dport & 0x0000FFFF) && nat_entry->key.dport <= ((dport & 0xFFFF0000) >> 16))
								clean = 1;
						}
						else{				// no port specified
							clean = 1;
						}
					}
					else if(proto == 0)
						clean = 1;
				}
			}
			else if(dst != 0)				// only dip specified
			{
				if(nat_entry->key.dip == dst)
				{
					if(nat_entry->key.ip_protocol == proto){
						if(sport && dport)	// both specified and match
						{
							if((nat_entry->key.dport >= (dport & 0x0000FFFF) && nat_entry->key.dport <= ((dport & 0xFFFF0000) >> 16)) && \
								(nat_entry->key.sport >= (sport & 0x0000FFFF) && nat_entry->key.sport <= ((sport & 0xFFFF0000) >> 16)))
								clean = 1;
						}
						else if(sport)		// only sport specified
						{
							if(nat_entry->key.sport >= (sport & 0x0000FFFF) && nat_entry->key.sport <= ((sport & 0xFFFF0000) >> 16))
								clean = 1;
						}
						else if(dport)		// only dport specified
						{
							if(nat_entry->key.dport >= (dport & 0x0000FFFF) && nat_entry->key.dport <= ((dport & 0xFFFF0000) >> 16))
								clean = 1;
						}
						else{				// no port specified
							clean = 1;
						}
					}
					else if(proto == 0)
						clean = 1;
				}
			}
			else						// no ip specified
			{
				if(proto == 0)
					clean = 1 ;
				if( nat_entry->key.ip_protocol == proto)
				{
					if(sport && dport)	// both specified and match
					{
						if((nat_entry->key.dport >= (dport & 0x0000FFFF) && nat_entry->key.dport <= ((dport & 0xFFFF0000) >> 16)) && \
							(nat_entry->key.sport >= (sport & 0x0000FFFF) && nat_entry->key.sport <= ((sport & 0xFFFF0000) >> 16)) )
							clean = 1;
					}
					else if(sport)		// only sport specified
					{
						if(nat_entry->key.sport >= (sport & 0x0000FFFF) && nat_entry->key.sport <= ((sport & 0xFFFF0000) >> 16) )
							clean = 1;
					}
					else if(dport)		// only dport specified
					{
						if(nat_entry->key.dport >= (dport & 0x0000FFFF) && nat_entry->key.dport <= ((dport & 0xFFFF0000) >> 16))
							clean = 1;
					}
					else{				// no port specified
						clean = 1;
					}
				}
			}
			if(clean == 1){
				hash_invalidate_entry(i);
				hash_nat_disable_owner(i);
				cnt++;
			}
			clean = 0;
		}
	}
}

/*----------------------------------------------------------------------
* sl351x_hash_invalid_all
* Invalidate all HW NAT session if "iptalbes -F" was issued !
*----------------------------------------------------------------------*/
void sl351x_hash_invalid_all(void){
	
	volatile u32 *v_ptr;
	u32		 i;
	//printk("Flush all!\n");	
	v_ptr = (volatile u32 *) TOE_V_BIT_BASE;
	
	for (i=0; i < HASH_TOTAL_ENTRIES/32; i++)
		*v_ptr++ = 0;
}
EXPORT_SYMBOL(sl351x_hash_invalid_all);

#if defined(DUAL_BAND_VLAN_APPLY) || defined(CONFIG_CS351X_DUAL_WAN)
/*----------------------------------------------------------------------
* sl351x_vlan_vid
*----------------------------------------------------------------------*/
static short sl351x_vlan_vid(struct sk_buff *skb)
{
    unsigned short      vid_skb = 0;
                   
	if (skb->protocol == __constant_htons(ETH_P_8021Q)) {
		vid_skb = (*(skb->data + 15))|(((*(skb->data + 14)) & 0x0F )<<8);
    }
    return vid_skb;
}
#endif

/*----------------------------------------------------------------------
* sl351x_nat_find_gmacdev
*----------------------------------------------------------------------*/
static NAT_GMACDEV_T * sl351x_nat_find_gmacdev(struct net_device *device)
{
	int i;

	if (device == NULL) return NULL;

	for (i=0; i<CONFIG_GMAC_DEVICE_NUM; i++) {
		if (nat_cfg.gmacDev[i].dev == device) 
			return &(nat_cfg.gmacDev[i]);
	}
	return NULL;
}

/*----------------------------------------------------------------------
* sl351x_nat_find_gmacdev
*----------------------------------------------------------------------*/
static NAT_GMACDEV_T * sl351x_nat_find_gmacdev_byname(char *name)
{
	struct net_device *dev = dev_get_by_name(name);

	if (dev) {
#ifdef CONFIG_CS351X_DUAL_WAN
		if (dev->priv_flags & IFF_802_1Q_VLAN)
			return sl351x_nat_find_gmacdev(VLAN_DEV_INFO(dev)->real_dev);
		else
#endif
			return sl351x_nat_find_gmacdev(dev);
	} else return NULL;
}

/*----------------------------------------------------------------------
* sl351x_nat_lan_wan_status
*----------------------------------------------------------------------*/
static inline int sl351x_nat_lan_wan_status(NAT_GMACDEV_T *gmac_dev, short vid)
{
	if (vid == 0) return gmac_dev->lan_wan_status;
	else {
		if ((gmac_dev->number_vlan == 0) || (vid == 0))
			return gmac_dev->lan_wan_status;
		else {
			int i;
			for (i=0; i<gmac_dev->number_vlan; i++) {
				if (gmac_dev->vlanDev[i].vlan_id == vid) {
					return gmac_dev->vlanDev[i].lan_wan_status;
				}
			}
		}
	}
	return -1;
}

#ifdef CONFIG_CS351X_DUAL_WAN
/*----------------------------------------------------------------------
* sl351x_nat_vlan_status
*----------------------------------------------------------------------*/
static inline int sl351x_nat_vlan_status(NAT_GMACDEV_T *gmac_dev, short vid)
{
	int i=0;
	NAT_GMACDEV_VLAN_T *vlancfg;

	vlancfg = (NAT_GMACDEV_VLAN_T *)&(gmac_dev->vlanDev[0]);
	for (i=0; i<gmac_dev->number_vlan; i++, vlancfg++)
		if (vlancfg->vlan_id == vid)
			return 1;
	return 0;
}
#endif

/*----------------------------------------------------------------------
* sl351x_nat_path_valid
* Description: Find out whether in_dev -> out_dev HW NAT path is valid or not
* Return: 1 = valid, other value = invalid
*----------------------------------------------------------------------*/
static int sl351x_nat_path_valid(struct net_device *in_dev, unsigned int vid_in, struct net_device *out_dev, unsigned int vid_out)
{
	NAT_GMACDEV_T	*gmacdev;
	int i;
	
	gmacdev = sl351x_nat_find_gmacdev(in_dev);

	if (gmacdev == NULL) return -1;

	if (gmacdev->hw_nat_path.total > 0) {
		for (i=0; i<CONFIG_NAT_MAX_PATH; i++) {
			if ((gmacdev->hw_nat_path.entry[i].out_dev == out_dev) 
					&& (gmacdev->hw_nat_path.entry[i].out_vlan_id == vid_out)
					&& (gmacdev->hw_nat_path.entry[i].vlan_id == vid_in))
				return 1;
		}
	}
	else
		return -1;
	return 0;
}

/*----------------------------------------------------------------------
* sl351x_nat_add_dev
* Description: add the device into nat_cfg
* Return: 1 = success, other value = fail
*----------------------------------------------------------------------*/
int sl351x_nat_add_dev(struct net_device *dev)
{
	int i;

	for (i=0; i<CONFIG_GMAC_DEVICE_NUM; i++) {
		if (nat_cfg.gmacDev[i].dev == dev) return 0;
		if (nat_cfg.gmacDev[i].dev == NULL) {
			nat_cfg.gmacDev[i].dev = dev;
			sl351x_nat_allow_all_hw_nat_path();
			return 1;
		}
	}
	return 0;
}

/*----------------------------------------------------------------------
 * sl351x_nat_del_dev
 * Description: del the device from nat_cfg
 * Return: 1 = success, other value = fail
 *--------------------------------------------------------------------*/
int sl351x_nat_del_dev(struct net_device *dev)
{
	int i, j, k;

	for (i=0; i<CONFIG_GMAC_DEVICE_NUM; i++) {
		if (nat_cfg.gmacDev[i].dev == dev) {
			/* found the dev that is going to be deleted */
			/* clean all the info */
			nat_cfg.gmacDev[i].hwNAT_enabled = 0;

			/* clean all the path related to this device */
			for (j=0; j<CONFIG_GMAC_DEVICE_NUM; j++) {
				if ((i != j) && (nat_cfg.gmacDev[j].dev != NULL))
					sl351x_nat_del_path(&nat_cfg.gmacDev[j], 0, &nat_cfg.gmacDev[i], 0);
			}

			nat_cfg.gmacDev[i].dev = NULL;
			nat_cfg.gmacDev[i].lan_wan_status = 0;
			nat_cfg.gmacDev[i].ipcfg.total = 0;
			nat_cfg.gmacDev[i].hw_nat_path.total = 0;

			/* clean all the VLAN related to this device */
			memset(&nat_cfg.gmacDev[i].vlanDev, 0, 
					sizeof(NAT_GMACDEV_VLAN_T) * CONFIG_GMAC_VLAN_NUM);
			nat_cfg.gmacDev[i].number_vlan = 0;

			/* move up all the rest of GMAC dev info */
			for (j=i+1; j<CONFIG_GMAC_DEVICE_NUM; j++) {
				if (nat_cfg.gmacDev[j].dev != NULL) {
					nat_cfg.gmacDev[j-1].hwNAT_enabled = nat_cfg.gmacDev[j].hwNAT_enabled;
					nat_cfg.gmacDev[j-1].dev = nat_cfg.gmacDev[j].dev;
					nat_cfg.gmacDev[j-1].lan_wan_status = nat_cfg.gmacDev[j].lan_wan_status;
					nat_cfg.gmacDev[j-1].ipcfg.total = nat_cfg.gmacDev[j].ipcfg.total;
					for (k=0; k<nat_cfg.gmacDev[j-1].ipcfg.total; k++) {
						nat_cfg.gmacDev[j-1].ipcfg.entry[k].ipaddr = nat_cfg.gmacDev[j].ipcfg.entry[k].ipaddr;
						nat_cfg.gmacDev[j-1].ipcfg.entry[k].netmask = nat_cfg.gmacDev[j].ipcfg.entry[k].netmask;
					}

					nat_cfg.gmacDev[j-1].hw_nat_path.total = nat_cfg.gmacDev[j].hw_nat_path.total;
					for (k=0; k<nat_cfg.gmacDev[j-1].hw_nat_path.total; k++) {
						nat_cfg.gmacDev[j-1].hw_nat_path.entry[k].out_dev = nat_cfg.gmacDev[j].hw_nat_path.entry[k].out_dev;
						memcpy(nat_cfg.gmacDev[j-1].hw_nat_path.entry[k].name, 
								nat_cfg.gmacDev[j].hw_nat_path.entry[k].name, IFNAMSIZ);
						nat_cfg.gmacDev[j-1].hw_nat_path.entry[k].out_vlan_id = nat_cfg.gmacDev[j].hw_nat_path.entry[k].out_vlan_id;
						nat_cfg.gmacDev[j-1].hw_nat_path.entry[k].vlan_id = nat_cfg.gmacDev[j].hw_nat_path.entry[k].vlan_id;
					}
					for (k=0; k<nat_cfg.gmacDev[j-1].number_vlan; k++) {
						nat_cfg.gmacDev[j-1].vlanDev[k].hwNAT_enabled = nat_cfg.gmacDev[j].vlanDev[k].hwNAT_enabled;
						nat_cfg.gmacDev[j-1].vlanDev[k].vlan_id = nat_cfg.gmacDev[j].vlanDev[k].vlan_id;
						nat_cfg.gmacDev[j-1].vlanDev[k].lan_wan_status = nat_cfg.gmacDev[j].vlanDev[k].lan_wan_status;
					}
				}

				if (j == (CONFIG_GMAC_DEVICE_NUM - 1)) {
					nat_cfg.gmacDev[j].hwNAT_enabled = 0;
					nat_cfg.gmacDev[j].dev = NULL;
					nat_cfg.gmacDev[j].lan_wan_status = 0;
					nat_cfg.gmacDev[j].ipcfg.total = 0;
					nat_cfg.gmacDev[j].hw_nat_path.total = 0;
					nat_cfg.gmacDev[j].number_vlan = 0;
				}
				return 1;
			}
		}
	}
	return 0;
}

/*----------------------------------------------------------------------
* sl351x_nat_input
*	Handle NAT input frames
*	Called by SL351x Driver - Handle Default Rx Queue
*	Notes: The caller must make sure that the l3off & l4offset should not be zero.
*	SL351x NAT Frames should meet the following conditions:
*	1. TCP or UDP frame
*	2. Cannot be special ALGs ports which TCP/UDP data is updated
*	3. LAN-IN Frames: 
*		Source IP is in the LAN subnet and Destination is not in the LAN subnet
*	4. WAN-IN Frames
*		Destination IP is in the WAN port IP
*	
*	Example Ports
*	1. TCP/UDP data is updated
*		(a) FTP Control Packet
*		(b) VoIP Packets
*		(c) etc. (add in future)
*	2. UDP Low packet rate, not worth
*		(b) TFTP Destination Port is 69
*		(b) DNS  53
*		(c) NTP  123
*		(d) etc. (add in future)
*----------------------------------------------------------------------*/
void sl351x_nat_input(struct sk_buff *skb, int port, void *l3off, void *l4off)
{
	int 				i, found;
	u32					sip, dip;
	u16					sport, dport;
	struct ethhdr		*ether_hdr;
	struct pppoe_hdr	*pppoe_hdr;
	u16					ppp_proto;
#ifndef SKIP_NAT_CFG	
	NAT_IP_ENTRY_T		*ipcfg;
	NAT_XPORT_ENTRY_T	*xentry;
#endif	
	struct iphdr		*ip_hdr;
	struct tcphdr		*tcp_hdr;
	NAT_CB_T			*nat_cb;
	u8					proto, pppoe_frame=0;
	NAT_CFG_T			*cfg;
	GRE_PKTHDR_T		*gre_hdr;
	NAT_GMACDEV_T		*gmacdev;
	int					lan_wan_status = 0;
	unsigned short		eth_proto, vid_skb = 0;
#ifdef CONFIG_SL351x_NAT_TCP_UDP
	u16 				*port_ptr;
#endif
#ifdef CONFIG_CS351X_DUAL_WAN
	struct vlan_ethhdr	*vlan_ether_hdr;
	unsigned short		nat_cb_vid;
#endif

	cfg = (NAT_CFG_T *)&nat_cfg;

	gmacdev = sl351x_nat_find_gmacdev(skb->dev);
	if (gmacdev == NULL) {
		//nat_printf("Error:%s: Dev is not HW NAT device\n", __func__);
		return;
	}

	if (cfg->enabled == 0) {
		//nat_printf("Error:: HW NAT is not enabled\n");
		return;
	}

	if (gmacdev->hwNAT_enabled == 0) {
		//nat_printf("Error:: HW NAT is not enabled on this device\n");
		return;
	}

	if (gmacdev->ipcfg.total == 0) {
		//nat_printf("Error:: NO IP is configured for this device\n");
		return;
	}

	ip_hdr = (struct iphdr *)&(skb->data[(u32)l3off]);
	tcp_hdr = (struct tcphdr *)&(skb->data[(u32)l4off]);
#ifdef CONFIG_CS351X_DUAL_WAN
	if ((*(skb->data + 12)) == 0x81) {
		skb->protocol = __constant_htons(ETH_P_8021Q);
		vid_skb = sl351x_vlan_vid(skb);
	}
#endif

	proto = ip_hdr->protocol;
	gre_hdr = (GRE_PKTHDR_T *)tcp_hdr;
	sport = ntohs(tcp_hdr->source);
	dport = ntohs(tcp_hdr->dest);

	sip = ntohl(ip_hdr->saddr);
	dip = ntohl(ip_hdr->daddr);

	if (dip == IPIV(255,255,255,255))
		return;
#ifdef CONFIG_CS351X_DUAL_WAN
	/* since this is a vlan device, we have to check if HW NAT on 
	 * this VLAN device is enabled or not */
	if (vid_skb != 0) {
		if (sl351x_nat_vlan_status(gmacdev, vid_skb) == 0)
			return;
	}
#endif

	lan_wan_status = sl351x_nat_lan_wan_status(gmacdev, vid_skb);

	found = 0;
	if (lan_wan_status == HW_NAT_LAN) {
		ipcfg = (NAT_IP_ENTRY_T *)&gmacdev->ipcfg.entry[0];
		for (i=0, found=0; i<gmacdev->ipcfg.total; i++, ipcfg++) {
			u32 subnet = ipcfg->ipaddr & ipcfg->netmask;
			if (((sip & ipcfg->netmask) == subnet) &&
					(ipcfg->vlan_id == vid_skb) &&
					((dip & ipcfg->netmask) != subnet)) {
				found = 1;
				break;
			}
		}
		if (found == 0) return;
	} else {	/* if (gmacdev->lan_wan_status == HW_NAT_WAN) */
#ifndef _NOT_CHECK_SIP_DIP	// enable it if know and get the wan ip address
		if (!sl351x_nat_find_ipcfg(dip, gmacdev, vid_skb)) {
			//printk("WAN->LAN Incorrect Dip %d.%d.%d.%d\n", HIPQUAD(dip));
			return;
		}
#endif
		/* to check if WAN is PPPoE*/
		/* 1st, if VLAN is also enabled */
#ifdef CONFIG_CS351X_DUAL_WAN
		if (vid_skb != 0) {
			vlan_ether_hdr = (struct vlan_ethhdr *)skb->data;
			pppoe_hdr = (struct pppoe_hdr *)(skb->data + VLAN_ETH_HLEN);
			eth_proto = vlan_ether_hdr->h_vlan_encapsulated_proto;
		} else
#endif
		{ /* no VLAN is enabled */
			ether_hdr = (struct ethhdr *)skb->data;
			pppoe_hdr = (struct pppoe_hdr *)(ether_hdr + 1);
			eth_proto = ether_hdr->h_proto;
		}
		ppp_proto = *(u16 *)&pppoe_hdr->tag[0];

		if (eth_proto == __constant_htons(ETH_P_PPP_SES)	/* 0x8864 */
				&& ppp_proto == __constant_htons(PPP_IP)) {	/* 0x21 */
			pppoe_frame = 1;
		}
	}

#ifdef CONFIG_SL351x_NAT_TCP_UDP
	if (proto == IPPROTO_TCP) {
#ifdef	NAT_DEBUG_MSG
#ifdef CONFIG_SL351x_RTLDMZ
		//if (gmacdev->lan_wan_status == HW_NAT_LAN)
		if (port == cfg->lan_port)
			nat_printf("From   GMAC-%d: 0x%-4X rx_vid %d TCP %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]",
				port, ntohs(ip_hdr->id),vid_skb,
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);
		else	/* (gmacdev->lan_wan_status == HW_NAT_WAN) */
			nat_printf("From   GMAC-%d: 0x%-4X TCP %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]",
				port, ntohs(ip_hdr->id),
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);		
				
#else				
		nat_printf("From   GMAC-%d: 0x%-4X TCP %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]",
				port, ntohs(ip_hdr->id),
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);		
#endif	
		if (tcp_flag_word(tcp_hdr) & TCP_FLAG_SYN) nat_printf(" SYN");
		if (tcp_flag_word(tcp_hdr) & TCP_FLAG_FIN) nat_printf(" FIN");
		if (tcp_flag_word(tcp_hdr) & TCP_FLAG_RST) nat_printf(" RST");
		if (tcp_flag_word(tcp_hdr) & TCP_FLAG_ACK) nat_printf(" ACK");
		nat_printf("\n");
#endif
		// if (tcp_flag_word(tcp_hdr) & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST))
		if (tcp_flag_word(tcp_hdr) & (TCP_FLAG_SYN))
			return;
		port_ptr = fixed_tcp_port_list;
		for (i=0; *port_ptr; i++, port_ptr++) {
			if (sport == *port_ptr || dport == *port_ptr)
				return;
		}
#ifdef _HAVE_DYNAMIC_PORT_LIST
		port_ptr = dynamic_tcp_port_list;
		for (i=0; *port_ptr; i++, port_ptr++) {
			if (sport == *port_ptr || dport == *port_ptr)
				return;
		}
#endif	/* _HAVE_DYNAMIC_PORT_LIST */
	} else if (proto == IPPROTO_UDP) {
#ifdef	NAT_DEBUG_MSG
#ifdef CONFIG_SL351x_RTLDMZ
		//if (gmacdev->lan_wan_status == HW_NAT_LAN)
		if (port == cfg->lan_port)
			nat_printf("From   GMAC-%d: 0x%-4X rx_vid %d UDP %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]",
				port, ntohs(ip_hdr->id),vid_skb,
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);
		else // if (gmacdev->lan_wan_status == HW_NAT_WAN)
			nat_printf("From   GMAC-%d: 0x%-4X UDP %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]",
				port, ntohs(ip_hdr->id),
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);
		nat_printf("\n");
#else
		nat_printf("From   GMAC-%d: 0x%-4X UDP %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]", 
				port, ntohs(ip_hdr->id), 
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);
		nat_printf("\n");
#endif
#endif	//NAT_DEBUG_MSG
		port_ptr = fixed_udp_port_list;
		for (i=0; *port_ptr; i++, port_ptr++) {
			if (sport == *port_ptr || dport == *port_ptr)
				return;
		}
#ifdef _HAVE_DYNAMIC_PORT_LIST
		port_ptr = dynamic_udp_port_list;
		for (i=0; *port_ptr; i++, port_ptr++) {
			if (sport == *port_ptr || dport == *port_ptr)
				return;
		}
#endif	//_HAVE_DYNAMIC_PORT_LIST
	} else 
#endif	// CONFIG_SL351x_NAT_TCP_UDP
#ifdef CONFIG_SL351x_NAT_GRE
	if (proto == IPPROTO_GRE) {
		if (gre_hdr->protocol != GRE_PROTOCOL_SWAP)
			return;
#ifdef	NAT_DEBUG_MSG
#ifdef CONFIG_SL351x_RTLDMZ
		nat_printf("From   GMAC-%d: 0x%-4X rx_vid %d GRE %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]",
				port, ntohs(ip_hdr->id),vid_skb,
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);
		nat_printf("\n");		
#else
		nat_printf("From   GMAC-%d: 0x%-4X GRE %d.%d.%d.%d [%d] --> %d.%d.%d.%d",
				port, ntohs(ip_hdr->id),
				NIPQUAD(ip_hdr->saddr), ntohs(gre_hdr->call_id), 
				NIPQUAD(ip_hdr->daddr));
		nat_printf("\n");
#endif
#endif	//NAT_DEBUG_MSG			
	} else
#endif	//CONFIG_SL351x_NAT_GRE
		return;

#ifndef SKIP_NAT_CFG	
	// check xport list
	xentry = (NAT_XPORT_ENTRY_T *)&cfg->xport.entry[0];
	for (i=0; i<cfg->xport.total; i++, xentry++) {
		if (!xentry->protocol || xentry->protocol == proto) {
			//if (!xentry->sport_start && !xentry->dport_start) // UI take care
			//	continue;
			if (xentry->sport_start && !((sport >= xentry->sport_start) && 
									   (sport <= xentry->sport_end)))
				continue;
			if (xentry->dport_start && !((dport >= xentry->dport_start)
					 			       && (dport <= xentry->dport_end)))
				continue;
			return;
		}
	}
#endif  //SKIP_NAT_CFG
	
	nat_cb = NAT_SKB_CB(skb);
	if (((u32)nat_cb & 3)) {
		nat_printf("%s ERROR! nat_cb is not alignment!!!!!!\n", __func__);
		return;
	}
	nat_cb->tag = NAT_CB_TAG;
	memcpy(nat_cb->sa, skb->data+6, 6);
	nat_cb->sip = ip_hdr->saddr;
	nat_cb->dip = ip_hdr->daddr;
	if (proto == IPPROTO_GRE) {
		nat_cb->sport = gre_hdr->protocol;
		nat_cb->dport = gre_hdr->call_id;
	} else {
		nat_cb->sport = tcp_hdr->source;
		nat_cb->dport = tcp_hdr->dest;
	}
	nat_cb->pppoe_frame = pppoe_frame;
	nat_cb->input_dev = (unsigned int)skb->dev;

#ifdef CONFIG_CS351X_DUAL_WAN
	if (vid_skb != 0) {
		nat_cb->reserved[0] = vid_skb & 0x00FF;
		nat_cb->reserved[1] = (vid_skb & 0xFF00) >> 8;
		nat_cb_vid = nat_cb->reserved[0] | nat_cb->reserved[1];
	}
#endif
}

/*----------------------------------------------------------------------
* sl351x_nat_output
*	Handle NAT output frames
*	Called by SL351x Driver - Transmit
*
*	1. If not SL351x NAT frames, return FALSE
*	2. LAN-to-WAN frames
*		(1) Sip must be WAN IP
*	3. If TCP SY/RST/FIN frame, return
*	4. Build the hash key and get the hash index
*	5. If V-Bit is ON, return.
*	6. Write hash entry and validate it
*		
*----------------------------------------------------------------------*/
int sl351x_nat_output(struct sk_buff *skb, int port)
{
	struct iphdr		*ip_hdr;
	u8					proto;
	NAT_CB_T			*nat_cb;
	NAT_CFG_T			*cfg;

	nat_cb = NAT_SKB_CB(skb);
	cfg = (NAT_CFG_T *)&nat_cfg;
	ip_hdr = (struct iphdr *)skb->nh.iph;

	if (nat_cb->tag != NAT_CB_TAG)
		return 0;
		
	if (((u32)nat_cb & 3)) {
		nat_printf("%s ERROR! nat_cb is not alignment!!!!!!\n", __func__);
		return 0;
	}

	proto = ip_hdr->protocol;
	if ((proto == IPPROTO_UDP) && (ip_hdr->frag_off & htons(IP_MF|IP_OFFSET)))
	{
		//nat_printf("UDP IP Fragmenation\n");
		return 0;
	}
	
	switch (proto)
	{
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			if (skb->data[0] == 0x01) {
				return sl351x_igmp_udp_output(skb, port);
			} else {
				return sl351x_nat_tcp_udp_output(skb, port);
			}
		case IPPROTO_GRE:
			return sl351x_nat_gre_output(skb, port);
	}
	return 0;
}

/*----------------------------------------------------------------------
* sl351x_igmp_udp_output
*	Handle NAT IGMP UDP output frames
*----------------------------------------------------------------------*/
int sl351x_igmp_udp_output(struct sk_buff *skb, int port)
{
	u32					sip, dip;
	struct ethhdr		*ether_hdr;
	struct iphdr		*ip_hdr;
	struct tcphdr		*tcp_hdr;
	struct pppoe_hdr	*pppoe_hdr;
	NAT_CB_T			*nat_cb;
	NAT_CFG_T			*cfg;
	u8					proto;
	u16					sport, dport, ppp_proto;
	u32					hash_data[HASH_MAX_DWORDS];
	NAT_0_HASH_ENTRY_T	*hash_entry;
	int					hash_index;
#ifdef CONFIG_CS351X_DUAL_WAN
	struct vlan_ethhdr	*vlan_ether_hdr;
	short				nat_cb_vid, tx_vid;
#endif
	short				eth_proto;
	struct net_device	*nat_input_dev;
	NAT_GMACDEV_T		*out_nat_gmacdev, *in_nat_gmacdev;
	int					in_lan_wan_status, out_lan_wan_status;
	
	nat_cb = NAT_SKB_CB(skb);
	nat_input_dev = (struct net_device*)(nat_cb->input_dev);
	cfg = (NAT_CFG_T *)&nat_cfg;

	ether_hdr = (struct ethhdr *)skb->data;
	ip_hdr = (struct iphdr *)skb->nh.iph;
	tcp_hdr = (struct tcphdr *)((u32)ip_hdr + (ip_hdr->ihl<<2));
	sip = ntohl(ip_hdr->saddr);
	dip = ntohl(ip_hdr->daddr);
	proto = ip_hdr->protocol;
	sport = ntohs(tcp_hdr->source);
	dport = ntohs(tcp_hdr->dest);

#ifdef CONFIG_CS351X_DUAL_WAN
	if (skb->protocol == __constant_htons(ETH_P_8021Q))
		tx_vid = (*(skb->data + 0x0F)) | ((*(skb->data + 0x0E)) << 8);
	else tx_vid = 0;
	nat_cb_vid = nat_cb->reserved[0] | (nat_cb->reserved[1] << 8);
#endif

	/* detect obtain nat_cfg's GMAC dev */
	out_nat_gmacdev = sl351x_nat_find_gmacdev(skb->dev);
	if (out_nat_gmacdev == NULL) {
		//printk("%s::do not find output NAT GMAC device\n", __func__);
		return 0;
	}

	in_nat_gmacdev = sl351x_nat_find_gmacdev(nat_input_dev);
	if (in_nat_gmacdev == NULL) {
		//printk("%s::do not find input NAT GMAC device\n", __func__);
		return 0;
	}

	if (out_nat_gmacdev->ipcfg.total == 0) {
		//nat_printf("%s:: NO IP is configured for this device\n", __func__);
		return 0;
	}

#ifdef CONFIG_CS351X_DUAL_WAN
	/* since this is a vlan device, we have to check if HW NAT on 
	 * this VLAN device is enabled or not */
	if (tx_vid != 0) {
		if (sl351x_nat_vlan_status(out_nat_gmacdev, tx_vid) == 0)
			return 0;
	}

	if (sl351x_nat_path_valid(nat_input_dev, nat_cb_vid, skb->dev, tx_vid) != 1) {
		//nat_printf("%s::This HW NAT path is not enabled\n", __func__);
		return 0;
	}
#else

	if (sl351x_nat_path_valid(nat_input_dev, 0, skb->dev, 0) != 1) {
		//nat_printf("%s::This HW NAT path is not enabled\n", __func__);
		return 0;
	}
#endif

#ifdef	NAT_DEBUG_MSG
	{
		nat_printf("To   GMAC-%d: 0x%-4X [%d] %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]",
				port, ntohs(ip_hdr->id), proto,
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);
		nat_printf("\n");
	}
#endif				
	
	if (proto == IPPROTO_TCP)	/*Assume data packet is UDP */
		return 0;

#ifdef CONFIG_CS351X_DUAL_WAN
	in_lan_wan_status = sl351x_nat_lan_wan_status(in_nat_gmacdev, nat_cb_vid);
	out_lan_wan_status = sl351x_nat_lan_wan_status(out_nat_gmacdev, tx_vid);
#else
	in_lan_wan_status = sl351x_nat_lan_wan_status(in_nat_gmacdev, 0);
	out_lan_wan_status = sl351x_nat_lan_wan_status(out_nat_gmacdev, 0);
#endif
	if ((in_lan_wan_status < 0) || (out_lan_wan_status < 0)) {
		printk("%s::LAN/WAN status isn't set correctly\n", __func__);
		return 0;
	}

	hash_entry = (NAT_0_HASH_ENTRY_T *)&hash_data;

	// Note: unused fields (including rule_id) MUST be zero
	hash_entry->key.Ethertype 	= 0;
	hash_entry->key.port_id 	= ((GMAC_INFO_T *)nat_input_dev->priv)->port_id;
	hash_entry->key.rule_id 	= 0;
	memcpy(hash_entry->key.da, skb->data, 6);
	hash_entry->key.reserved3 	= 0;
#ifdef CONFIG_CS351X_DUAL_WAN
	hash_entry->key.vlan_id     = nat_cb_vid;
	/* note for WAN->LAN:
	 * for PPPoE, even if we choose not to detect/check pppoe session id
	 * hash entry can still be made and be verified */
	hash_entry->key.pppoe_sid 	= 0;
#endif
	hash_entry->key.ip_protocol = proto;
	hash_entry->key.reserved1 	= 0;
	hash_entry->key.reserved2 	= 0;
	hash_entry->key.dip 		= ntohl(nat_cb->dip);

	hash_index = nat_0_build_keys(&hash_entry->key);

	/* handle hash timeout */
	if (hash_get_nat_owner_flag(hash_index))
		return 0;

	/* Check hash collision */
	if (hash_get_valid_flag(hash_index)) {
//		printk("WAN-to-LAN nat_collision =%d\n",nat_collision);
		nat_collision++;
		return 0;
	}

	/* complete hash entry */
	hash_entry->key.rule_id = IGMP_RULE;
	memcpy(hash_entry->param.da, skb->data, 6);
	memcpy(hash_entry->param.sa, skb->data+6, 6);
	hash_entry->param.Sip = sip;
	hash_entry->param.Dip = dip;
	hash_entry->param.Sport = sport;
	hash_entry->param.Dport = dport;
	hash_entry->param.vlan = 0;
	hash_entry->param.pppoe = 0;
	hash_entry->param.sw_id = 0;
	hash_entry->param.mtu = 0;

	/* define hash_entry->action.dword */
	/* case for LAN->WAN */
	if ((in_lan_wan_status == HW_NAT_LAN) 
			&& (out_lan_wan_status == HW_NAT_WAN)) {
		/* check if WAN requires PPPoE */
#ifdef CONFIG_CS351X_DUAL_WAN
		/* 1st, if VLAN is seen in TX */
		if (tx_vid != 0) {
			vlan_ether_hdr = (struct vlan_ethhdr *)skb->data;
			pppoe_hdr = (struct pppoe_hdr *)(skb->data + VLAN_ETH_HLEN);
			eth_proto = vlan_ether_hdr->h_vlan_encapsulated_proto;
		} else
#endif
		{	/* no vlan is seen */
			pppoe_hdr = (struct pppoe_hdr *)(ether_hdr + 1);
			eth_proto = ether_hdr->h_proto;
		}
		ppp_proto = *(u16 *)&pppoe_hdr->tag[0];

		if (eth_proto == __constant_htons(ETH_P_PPP_SES)	/* 0x8864 */
				&& ppp_proto == __constant_htons(PPP_IP)) {	/* 0x21 */
			hash_entry->action.dword = IGMP_PPPOE_ACTION_BITS; 
			hash_entry->param.pppoe = htons(pppoe_hdr->sid);
		} else {
			hash_entry->action.dword = IGMP_ACTION_BITS;
			hash_entry->param.pppoe = 0;
		}
	}
	/* case for WAN->LAN */
	if ((in_lan_wan_status == HW_NAT_WAN) 
			&& (out_lan_wan_status == HW_NAT_LAN))
		hash_entry->action.dword = (nat_cb->pppoe_frame) ? IGMP_PPPOE_ACTION_BITS : IGMP_ACTION_BITS;

	/* define vlan action for hash_entry->action */
#ifdef CONFIG_CS351X_DUAL_WAN
	if (tx_vid != 0)	/* insert/replace vlan header */
	{
		hash_entry->param.vlan = tx_vid;
		hash_entry->action.dword |= ACTION_VLAN_INS_BIT;
	}
	else if ((nat_cb_vid != 0) && (tx_vid == 0))	/* remove vlan header */
		hash_entry->action.dword |= ACTION_VLAN_DEL_BIT;
	else	/* do not do anything */
		hash_entry->action.bits.vlan = 0;
#endif

	/* set destination queue */
	hash_entry->action.bits.dest_qid = sl351x_nat_assign_qid(proto, sip, dip, sport, dport);
	hash_entry->action.bits.dest_qid += (port==0) ? TOE_GMAC0_HW_TXQ2_QID : TOE_GMAC1_HW_TXQ2_QID;

	/* enable timer */
	hash_entry->tmo.counter = hash_entry->tmo.interval = cfg->udp_tmo_interval;

	/* write hash entry to hash table and validate it */
	nat_0_write_hash_entry(hash_index, hash_entry);
	//nat_printf("%lu Validate a IGMP WAN hash entry %d\n", jiffies/HZ, hash_index);
	//hash_dump_entry(hash_index);
	hash_nat_enable_owner(hash_index);
	hash_validate_entry(hash_index); // Must last one, else HW Tx fast SW
	return 0;
}

/*----------------------------------------------------------------------
* sl351x_nat_tcp_udp_output
*	Handle NAT TCP/UDP output frames
*----------------------------------------------------------------------*/
int sl351x_nat_tcp_udp_output(struct sk_buff *skb, int port)
{
	u32					sip, dip , r_sip , r_dip;
	struct ethhdr		*ether_hdr;
	struct iphdr		*ip_hdr;
	struct tcphdr		*tcp_hdr;
	struct pppoe_hdr	*pppoe_hdr;
	NAT_CB_T			*nat_cb;
	NAT_CFG_T			*cfg;
	u8					proto;
	u16					sport, dport, ppp_proto, r_sport, r_dport;
	u32					hash_data[HASH_MAX_DWORDS];
	NAT_HASH_ENTRY_T	*hash_entry;
	int					hash_index;
	struct ip_conntrack *nat_ip_conntrack;
	enum ip_conntrack_info ctinfo;
#ifdef CONFIG_CS351X_DUAL_WAN
	struct vlan_ethhdr	*vlan_ether_hdr;
	short				nat_cb_vid, tx_vid;
#endif
	short				eth_proto;
	struct net_device	*nat_input_dev;
	NAT_GMACDEV_T		*out_nat_gmacdev, *in_nat_gmacdev;
	int					use_lan2wan = 0, use_wan2lan = 0;
	int					in_lan_wan_status, out_lan_wan_status;

	nat_cb = NAT_SKB_CB(skb);
	cfg = (NAT_CFG_T *)&nat_cfg;
	nat_input_dev = (struct net_device*)(nat_cb->input_dev);

	/* detect and obtain nat_cfg's GMAC dev */
	out_nat_gmacdev = sl351x_nat_find_gmacdev(skb->dev);
	if (out_nat_gmacdev == NULL) {
		//printk("%s::do not find output NAT GMAC device\n", __func__);
		return 0;
	}

	in_nat_gmacdev = sl351x_nat_find_gmacdev(nat_input_dev);
	if (in_nat_gmacdev == NULL) {
		//printk("%s::do not find input NAT GMAC device\n", __func__);
		return 0;
	}

	ether_hdr = (struct ethhdr *)skb->data;

	ip_hdr = (struct iphdr *)skb->nh.iph;
	tcp_hdr = (struct tcphdr *)((u32)ip_hdr + (ip_hdr->ihl<<2));
	if (!tcp_hdr) {
//		printk("%s::skb %x, data %x, ", __func__, (u32)skb, (u32)skb->data);
//		printk("ethdr %x, iphdr %x, ", (u32)ether_hdr, (u32)ip_hdr);
//		printk("tcp_hdr %x\n", (u32)tcp_hdr);
		return 0;
	}
	sip = ntohl(ip_hdr->saddr);
	dip = ntohl(ip_hdr->daddr);
	proto = ip_hdr->protocol;
	sport = ntohs(tcp_hdr->source);
	dport = ntohs(tcp_hdr->dest);

#if 0	/* redundant */
	if (skb->input_dev != NULL) {
		if (skb->input_dev != nat_input_dev) {
			//printk("%s::skb->input_dev = %d, nat_input_dev = %d\n", __func__, 
			//		skb->input_dev, nat_input_dev);
			nat_input_dev = skb->input_dev;
		}
	}

	if (nat_input_dev == NULL) {
		//nat_printf("%s::there is no input dev?\n", __func__);
		return 0;
	}
#endif

#ifdef CONFIG_CS351X_DUAL_WAN
	if (skb->protocol == __constant_htons(ETH_P_8021Q))
		tx_vid = (*(skb->data + 0x0F)) | ((*(skb->data + 0x0E)) << 8);
	else tx_vid = 0;
	nat_cb_vid = nat_cb->reserved[0] | (nat_cb->reserved[1] << 8);

	if (sl351x_nat_path_valid(nat_input_dev, nat_cb_vid, skb->dev, tx_vid) != 1) {
		//nat_printf("%s::This HW NAT path is not enabled\n", __func__);
		return 0;
	}
#else

	if (sl351x_nat_path_valid(nat_input_dev, 0, skb->dev, 0) != 1) {
		//nat_printf("%s::This HW NAT path is not enabled\n", __func__);
		return 0;
	}
#endif

	if (out_nat_gmacdev->ipcfg.total == 0) {
		//nat_printf("%s:: NO IP is configured for this device\n", __func__);
		return 0;
	}

#ifdef CONFIG_CS351X_DUAL_WAN
	/* since this is a vlan device, we have to check if HW NAT on 
	 * this VLAN device is enabled or not */
	if (tx_vid != 0) {
		if (sl351x_nat_vlan_status(out_nat_gmacdev, tx_vid) == 0)
			return 0;
	}
#endif

#ifdef	NAT_DEBUG_MSG
	{
#ifdef CONFIG_SL351x_RTLDMZ		
		if (port == cfg->lan_port)	//GMAC_PORT0	
			nat_printf("To   GMAC-%d: 0x%-4X [%d] tx_vid %d %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]",
				port, ntohs(ip_hdr->id), proto,tx_vid,
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);
		else
			nat_printf("To   GMAC-%d: 0x%-4X [%d] %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]",
				port, ntohs(ip_hdr->id), proto,
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);
#else
		nat_printf("To   GMAC-%d: 0x%-4X [%d] %d.%d.%d.%d [%d] --> %d.%d.%d.%d [%d]",
				port, ntohs(ip_hdr->id), proto,
				NIPQUAD(ip_hdr->saddr), sport, 
				NIPQUAD(ip_hdr->daddr), dport);
#endif	
		if (proto == IPPROTO_TCP)
		{
			if (tcp_flag_word(tcp_hdr) & TCP_FLAG_SYN) nat_printf(" SYN");
			if (tcp_flag_word(tcp_hdr) & TCP_FLAG_FIN) nat_printf(" FIN");
			if (tcp_flag_word(tcp_hdr) & TCP_FLAG_RST) nat_printf(" RST");
			if (tcp_flag_word(tcp_hdr) & TCP_FLAG_ACK) nat_printf(" ACK");
		}
		nat_printf("\n");
	}
#endif	//NAT_DEBUG_MSG			
	nat_ip_conntrack = ip_conntrack_get(skb, &ctinfo);

	if (!nat_ip_conntrack) {
		//nat_printf("IP conntrack info is not found!\n");
		return 0;
	}

	// nat_printf("nat_ip_conntrack = 0x%x, status=0x%lx, ctinfo=%d\n", (u32)nat_ip_conntrack, nat_ip_conntrack->status, ctinfo);
	// if (nat_ip_conntrack->master || nat_ip_conntrack->helper)
	if (nat_ip_conntrack->helper) {
		nat_printf("Sport=%d Dport=%d master=0x%x, helper=0x%x\n", sport, dport, (u32)nat_ip_conntrack->master, (u32)nat_ip_conntrack->helper);
		return 0;
	}
	
	//if (proto == IPPROTO_TCP && !(nat_ip_conntrack->status & IPS_ASSURED))
	//	return 0;

#ifdef	NAT_DEBUG_MSG
	nat_printf("nat_ip_conntrack=0x%x, nat_cb->state=%d\n", (u32)nat_ip_conntrack, nat_cb->state);
	nat_printf("lan2wan_hash_index=%d,  wan2lan_hash_index=%d\n", nat_ip_conntrack->lan2wan_hash_index, nat_ip_conntrack->wan2lan_hash_index);
	nat_printf("lan2wan_collision=%d, wan2lan_collision=%d\n", nat_ip_conntrack->lan2wan_collision, nat_ip_conntrack->wan2lan_collision);
#endif
	if (proto == IPPROTO_TCP)
	{
		if (nat_cb->state >= TCP_CONNTRACK_FIN_WAIT && nat_cb->state <= TCP_CONNTRACK_CLOSE)
		{
			if 	(nat_ip_conntrack->lan2wan_hash_index)
			{
#ifdef	NAT_DEBUG_MSG
				nat_printf("Invalidate LAN->WAN hash entry %d\n", nat_ip_conntrack->lan2wan_hash_index - 1);
#endif
				hash_nat_disable_owner(nat_ip_conntrack->lan2wan_hash_index - 1);
				hash_invalidate_entry(nat_ip_conntrack->lan2wan_hash_index - 1);
				nat_ip_conntrack->lan2wan_hash_index = 0;
			}
			if 	(nat_ip_conntrack->wan2lan_hash_index)
			{
#ifdef	NAT_DEBUG_MSG
				nat_printf("Invalidate WAN->LAN hash entry %d\n", nat_ip_conntrack->wan2lan_hash_index - 1);
#endif
				hash_nat_disable_owner(nat_ip_conntrack->wan2lan_hash_index - 1);
				hash_invalidate_entry(nat_ip_conntrack->wan2lan_hash_index - 1);
				nat_ip_conntrack->wan2lan_hash_index = 0;
			}
			return 0;
		}
		else if (nat_cb->state != TCP_CONNTRACK_ESTABLISHED)
			return 0;
	}
	if (proto == IPPROTO_TCP && (tcp_flag_word(tcp_hdr) & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)))
	{
	// if (proto == IPPROTO_TCP &&  (tcp_flag_word(tcp_hdr) & (TCP_FLAG_SYN)))
		return 0;
	}

#ifdef CONFIG_CS351X_DUAL_WAN
	in_lan_wan_status = sl351x_nat_lan_wan_status(in_nat_gmacdev, nat_cb_vid);
	out_lan_wan_status = sl351x_nat_lan_wan_status(out_nat_gmacdev, tx_vid);
#else
	in_lan_wan_status = sl351x_nat_lan_wan_status(in_nat_gmacdev, 0);
	out_lan_wan_status = sl351x_nat_lan_wan_status(out_nat_gmacdev, 0);
#endif
	if ((in_lan_wan_status < 0) || (out_lan_wan_status < 0)) {
		printk("%s::LAN/WAN status isn't set correctly\n", __func__);
		return 0;
	}

	hash_entry = (NAT_HASH_ENTRY_T *)&hash_data;

	/* Check for hash existence!! */

	/* case for LAN->WAN */
	if ((in_lan_wan_status == HW_NAT_LAN) 
			&& (out_lan_wan_status == HW_NAT_WAN)) {
		if ((nat_ip_conntrack->lan2wan_hash_index != 0)
				|| (nat_ip_conntrack->lan2wan_collision != 0))
			return 0;

#ifndef _NOT_CHECK_SIP_DIP	// enable it if know and get the wan ip address	
#ifdef CONFIG_CS351X_DUAL_WAN
		if (!sl351x_nat_find_ipcfg(sip, out_nat_gmacdev, tx_vid)) {
			//nat_printf("LAN->WAN Incorrect Sip %d.%d.%d.%d\n", HIPQUAD(sip));
			return 0;
		}
#else
		if (!sl351x_nat_find_ipcfg(sip, out_nat_gmacdev, 0))
			return 0;
#endif
#endif
		use_lan2wan = 1;
	}

	/* case for WAN->LAN */
	if ((in_lan_wan_status == HW_NAT_WAN) 
			&& (out_lan_wan_status == HW_NAT_LAN)) {
		if ((nat_ip_conntrack->wan2lan_hash_index != 0)
					|| (nat_ip_conntrack->wan2lan_collision != 0))
			return 0;
		use_wan2lan = 1;
	}

	/* case for LAN->LAN IP routing */
	if ((in_lan_wan_status == HW_NAT_LAN) 
			&& (out_lan_wan_status == HW_NAT_LAN)) {
		if ((nat_ip_conntrack->lan2wan_hash_index == 0) 
				&& (nat_ip_conntrack->lan2wan_collision == 0)) {
			use_lan2wan = 1;
			nat_ip_conntrack->lan2wan_hash_index = HASH_OCCUPIED;
		} else if ((nat_ip_conntrack->wan2lan_hash_index == 0) 
				&& (nat_ip_conntrack->wan2lan_collision == 0)) {
			use_wan2lan = 1;
			nat_ip_conntrack->wan2lan_hash_index = HASH_OCCUPIED;
		}
	}

	if ((use_lan2wan == 0) && (use_wan2lan == 0))
		return 0;

	/* filling up information for hash entry */
	hash_entry->key.Ethertype	= 0;	
	hash_entry->key.port_id 	= ((GMAC_INFO_T *)nat_input_dev->priv)->port_id;
	hash_entry->key.rule_id 	= 0;
#ifdef CONFIG_CS351X_DUAL_WAN
	hash_entry->key.vlan_id     = nat_cb_vid;
	/* note for WAN->LAN:
	 * for PPPoE, even if we choose not to detect/check pppoe session id
	 * hash entry can still be made and be verified */
	hash_entry->key.pppoe_sid 	= 0;
#endif
	hash_entry->key.ip_protocol = proto;
	hash_entry->key.reserved1 	= 0;
	hash_entry->key.reserved2 	= 0;
	hash_entry->key.sip 		= ntohl(nat_cb->sip);
	hash_entry->key.dip 		= ntohl(nat_cb->dip);
	hash_entry->key.sport 		= nat_cb->sport;
	hash_entry->key.dport 		= nat_cb->dport;

	r_sip = ntohl(nat_cb->sip);
	r_dip = ntohl(nat_cb->dip);
	r_sport = ntohs(nat_cb->sport);
	r_dport = ntohs(nat_cb->dport);

	hash_index = nat_build_keys(&hash_entry->key);

	/* handle hash timeout */
	if (hash_get_nat_owner_flag(hash_index)) {
		if (use_wan2lan == 1) nat_ip_conntrack->wan2lan_hash_index = 0;
		if (use_lan2wan == 1) nat_ip_conntrack->lan2wan_hash_index = 0;
		return 0;
	}

	/* Check hash collision */
	if (hash_get_valid_flag(hash_index)) {
		if (use_wan2lan == 1) {
			nat_ip_conntrack->wan2lan_collision = 1;
			nat_ip_conntrack->wan2lan_hash_index = 0;
		}
		if (use_lan2wan == 1) {
			nat_ip_conntrack->lan2wan_collision = 1;
			nat_ip_conntrack->lan2wan_hash_index = 0;
		}

		nat_collision++;
		return 0;
	}

	/* 
	 * define the rest of the fields after we calculate the hash key
	 * before writing the hash entry to hash table
	 */
	hash_entry->key.rule_id = cfg->tcp_udp_rule_id;
	memcpy(hash_entry->param.da, skb->data, 6);
	memcpy(hash_entry->param.sa, skb->data+6, 6);
#ifdef CONFIG_CS351X_DUAL_WAN
	hash_entry->param.vlan = tx_vid;
#endif
	hash_entry->param.Sip = sip;
	hash_entry->param.Dip = dip;
	hash_entry->param.Sport = sport;
	hash_entry->param.Dport = dport;
	hash_entry->param.pppoe = 0;
	hash_entry->param.sw_id = 0;
	hash_entry->param.mtu = 0;

	/* define hash_entry->action.dword */
	/* case for LAN->WAN */
	if ((in_lan_wan_status == HW_NAT_LAN) 
			&& (out_lan_wan_status == HW_NAT_WAN)) {
		/* check if WAN requires PPPoE */
#ifdef CONFIG_CS351X_DUAL_WAN
		/* 1st, if VLAN is seen in TX */
		if (tx_vid != 0) {
			vlan_ether_hdr = (struct vlan_ethhdr *)skb->data;
			pppoe_hdr = (struct pppoe_hdr *)(skb->data + VLAN_ETH_HLEN);
			eth_proto = vlan_ether_hdr->h_vlan_encapsulated_proto;
		} else
#endif
		{	/* no vlan is seen */
			pppoe_hdr = (struct pppoe_hdr *)(ether_hdr + 1);
			eth_proto = ether_hdr->h_proto;
		}
		ppp_proto = *(u16 *)&pppoe_hdr->tag[0];

		if (eth_proto == __constant_htons(ETH_P_PPP_SES)	/* 0x8864 */
				&& ppp_proto == __constant_htons(PPP_IP)) {	/* 0x21 */
			hash_entry->action.dword = NAT_PPPOE_LAN2WAN_ACTIONS;
			hash_entry->param.pppoe = htons(pppoe_hdr->sid);
		} else {
			hash_entry->action.dword = NAT_LAN2WAN_ACTIONS;
			hash_entry->param.pppoe = 0;
		}
	}

	/* case for WAN->LAN */
	if ((in_lan_wan_status == HW_NAT_WAN) 
			&& (out_lan_wan_status == HW_NAT_LAN))
		hash_entry->action.dword = (nat_cb->pppoe_frame) ? NAT_PPPOE_WAN2LAN_ACTIONS : NAT_WAN2LAN_ACTIONS;

	/* case for LAN->LAN, use NAT_WAN2LAN_ACTIONS for it */
	if ((in_lan_wan_status == HW_NAT_LAN) 
			&& (out_lan_wan_status == HW_NAT_LAN))
		hash_entry->action.dword = NAT_WAN2LAN_ACTIONS;

	/* define vlan action for hash_entry->action */
#ifdef CONFIG_CS351X_DUAL_WAN
	if (tx_vid != 0)	/* insert/replace vlan header */
		hash_entry->action.dword |= ACTION_VLAN_INS_BIT;
//		hash_entry->action.bits.vlan = 1;
	else if ((nat_cb_vid != 0) && (tx_vid == 0))	/* remove vlan header */
		hash_entry->action.dword |= ACTION_VLAN_DEL_BIT;
//		hash_entry->action.bits.vlan = 2;
	else	/* do not do anything */
		hash_entry->action.bits.vlan = 0;
#endif

#if 0	/* debug message WEN */
	if (use_lan2wan == 1)
		printk("%s::LAN->WAN info\n", __func__);
	else (use_wan2lan == 1)
		printk("%s::WAN->LAN info\n", __func__);
	printk("in gmac port %d, out gmac port %d\n", ((GMAC_INFO_T *)nat_input_dev->priv)->port_id, port);
	printk("nat_cb_vid %d, tx_vid %d, rule_id %d\n", nat_cb_vid, tx_vid, cfg->tcp_udp_rule_id);
	printk("sip:port = %x:%d, dip:port = %x:%d\n", sip, sport, dip, dport);
	printk("src_mac = %2x:%2x:%2x:%2x:%2x:%2x, ", hash_entry->param.sa[0], 
			hash_entry->param.sa[1], hash_entry->param.sa[2], 
			hash_entry->param.sa[3], hash_entry->param.sa[4], 
			hash_entry->param.sa[5]);
	printk("dst_mac = %2x:%2x:%2x:%2x:%2x:%2x\n", hash_entry->param.da[0], 
			hash_entry->param.da[1], hash_entry->param.da[2],
			hash_entry->param.da[3], hash_entry->param.da[4], 
			hash_entry->param.da[5]);
	printk("\n");
#endif

	/* set destination queue */
	hash_entry->action.bits.dest_qid = sl351x_nat_assign_qid(proto, r_sip, dip, r_sport, r_dport);
	hash_entry->action.bits.dest_qid += (port==0) ? TOE_GMAC0_HW_TXQ2_QID : TOE_GMAC1_HW_TXQ2_QID;

	/* enable timer */
	hash_entry->tmo.counter = hash_entry->tmo.interval = 
			(proto == IPPROTO_TCP) ? cfg->tcp_tmo_interval : cfg->udp_tmo_interval;

	/* write hash entry to hash table and validate it */
	nat_write_hash_entry(hash_index, hash_entry);
	hash_nat_enable_owner(hash_index);
	/* Must be the last one, else HW Tx fast SW */
	hash_validate_entry(hash_index); 

	/* keep the info in the connection tracking */
	if (use_lan2wan == 1) {
 		nat_ip_conntrack->lan2wan_hash_index = hash_index + 1;
 		nat_ip_conntrack->hw_nat |= 1;
	}
	if (use_wan2lan == 1) {
		nat_ip_conntrack->wan2lan_hash_index = hash_index + 1;
		nat_ip_conntrack->hw_nat |= 2;
	}
	return 0;
}

/*----------------------------------------------------------------------
* sl351x_nat_gre_output
*	Handle NAT GRE output frames
*----------------------------------------------------------------------*/
int sl351x_nat_gre_output(struct sk_buff *skb, int port)
{
	u32					sip, dip;
	struct ethhdr		*ether_hdr;
	struct iphdr		*ip_hdr;
	struct pppoe_hdr	*pppoe_hdr;
	GRE_PKTHDR_T		*gre_hdr;
	NAT_CB_T			*nat_cb;
	NAT_CFG_T			*cfg;
	u16					ppp_proto;
	u32					hash_data[HASH_MAX_DWORDS];
	GRE_HASH_ENTRY_T	*hash_entry;
	int					hash_index;
	struct ip_conntrack *nat_ip_conntrack;
	enum ip_conntrack_info ctinfo;
#ifdef CONFIG_CS351X_DUAL_WAN
	struct vlan_ethhdr	*vlan_ether_hdr;
	short				nat_cb_vid, tx_vid;
#endif
	short				eth_proto;
	struct net_device	*nat_input_dev;
	NAT_GMACDEV_T		*out_nat_gmacdev, *in_nat_gmacdev;
	int					in_lan_wan_status, out_lan_wan_status;

	nat_cb = NAT_SKB_CB(skb);
	cfg = (NAT_CFG_T *)&nat_cfg;
	nat_input_dev = (struct net_device*)(nat_cb->input_dev);

	out_nat_gmacdev = sl351x_nat_find_gmacdev(skb->dev);
	if (out_nat_gmacdev == NULL) return 0;

	in_nat_gmacdev = sl351x_nat_find_gmacdev(nat_input_dev);
	if (in_nat_gmacdev == NULL) return 0;

	ether_hdr = (struct ethhdr *)skb->data;

	ip_hdr = (struct iphdr *)skb->nh.iph;
	gre_hdr = (GRE_PKTHDR_T *)((u32)ip_hdr + (ip_hdr->ihl<<2));
	sip = ntohl(ip_hdr->saddr);
	dip = ntohl(ip_hdr->daddr);

#ifdef CONFIG_CS351X_DUAL_WAN
	if (skb->protocol == __constant_htons(ETH_P_8021Q))
		tx_vid = (*(skb->data + 0x0F)) | ((*(skb->data + 0x0E)) << 8);
	else tx_vid = 0;
	nat_cb_vid = nat_cb->reserved[0] | (nat_cb->reserved[1] << 8);

	if (sl351x_nat_path_valid(nat_input_dev, nat_cb_vid, skb->dev, tx_vid) != 1) {
		//nat_printf("%s::This HW NAT path is not enabled\n", __func__);
		return 0;
	}
#else
	if (sl351x_nat_path_valid(nat_input_dev, 0, skb->dev, 0) != 1) {
		//nat_printf("%s::This HW NAT path is not enabled\n", __func__);
		return 0;
	}
#endif

	if (out_nat_gmacdev->ipcfg.total == 0) {
		//nat_printf("%s:: NO IP is configured for this device\n", __func__);
		return 0;
	}

#ifdef CONFIG_CS351X_DUAL_WAN
	/* since this is a vlan device, we have to check if HW NAT on 
	 * this VLAN device is enabled or not */
	if (tx_vid != 0) {
		if (sl351x_nat_vlan_status(out_nat_gmacdev, tx_vid) == 0)
			return 0;
	}
#endif

#ifdef	NAT_DEBUG_MSG
	{
		nat_printf("To   GMAC-%d: 0x%-4X GRE %d.%d.%d.%d [%d] --> %d.%d.%d.%d",
				port, ntohs(ip_hdr->id), 
				NIPQUAD(ip_hdr->saddr), ntohs(gre_hdr->call_id), 
				NIPQUAD(ip_hdr->daddr));
		nat_printf("\n");
	}
#endif				
	nat_ip_conntrack = ip_conntrack_get(skb, &ctinfo);

	if (nat_ip_conntrack != NULL) {
		// if (nat_ip_conntrack->master || nat_ip_conntrack->helper)
		if (nat_ip_conntrack->helper)
		{
			nat_printf("GRE Call-ID=%d, master=0x%x, helper=0x%x\n", ntohs(gre_hdr->call_id), (u32)nat_ip_conntrack->master, (u32)nat_ip_conntrack->helper);
			return 0;
		}
		if (!(nat_ip_conntrack->status & IPS_ASSURED))
			return 0;
	}

#ifdef CONFIG_CS351X_DUAL_WAN
	in_lan_wan_status = sl351x_nat_lan_wan_status(in_nat_gmacdev, nat_cb_vid);
	out_lan_wan_status = sl351x_nat_lan_wan_status(out_nat_gmacdev, tx_vid);
#else
	in_lan_wan_status = sl351x_nat_lan_wan_status(in_nat_gmacdev, 0);
	out_lan_wan_status = sl351x_nat_lan_wan_status(out_nat_gmacdev, 0);
#endif
	if ((in_lan_wan_status < 0) || (out_lan_wan_status < 0)) {
		printk("%s::LAN/WAN status isn't set correctly\n", __func__);
		return 0;
	}

	hash_entry = (GRE_HASH_ENTRY_T *)&hash_data;

	/* case of LAN->WAN */
	if ((in_lan_wan_status == HW_NAT_LAN) 
			&& (out_lan_wan_status == HW_NAT_WAN)) {
#ifdef _NOT_CHECK_SIP_DIP	// enable it if know and get the wan ip address	
		if (!sl351x_nat_find_ipcfg(sip, out_nat_gmacdev, 0)) {
			//nat_printf("LAN->WAN Incorrect Sip %d.%d.%d.%d\n", HIPQUAD(sip));
			//nat_printf("LAN->WAN Incorrect Dip %d.%d.%d.%d\n", HIPQUAD(dip));
			return 0;
		}
#endif
	}

	/* Note: unused fields (including rule_id) MUST be zero */
	hash_entry->key.Ethertype 	= 0;
	hash_entry->key.port_id 	= ((GMAC_INFO_T *)nat_input_dev->priv)->port_id;
	hash_entry->key.rule_id 	= 0;
	hash_entry->key.ip_protocol = IPPROTO_GRE;
	hash_entry->key.reserved1 	= 0;
	hash_entry->key.reserved2 	= 0;
	hash_entry->key.reserved3 	= 0;
	hash_entry->key.reserved4 	= 0;
	hash_entry->key.sip 		= ntohl(nat_cb->sip);
	hash_entry->key.dip 		= ntohl(nat_cb->dip);
	hash_entry->key.protocol	= nat_cb->sport;
	hash_entry->key.call_id		= nat_cb->dport;

	hash_index = gre_build_keys(&hash_entry->key);

	/* handle hash timeout */
	if (hash_get_nat_owner_flag(hash_index))
		return 0;

	/* Check hash collision */
	if (hash_get_valid_flag(hash_index)) {
		return 0;
	}

	/* complete the hash entry */
	hash_entry->key.rule_id = cfg->gre_rule_id;
	memcpy(hash_entry->param.da, skb->data, 6);
	memcpy(hash_entry->param.sa, skb->data+6, 6);
	hash_entry->param.Sip = sip;
	hash_entry->param.Dip = dip;
	hash_entry->param.Sport = 0;
	hash_entry->param.Dport = ntohs(gre_hdr->call_id);
#ifdef CONFIG_CS351X_DUAL_WAN
	hash_entry->param.vlan = tx_vid;
#endif
	hash_entry->param.pppoe = 0;
	hash_entry->param.sw_id = 0;
	hash_entry->param.mtu = 0;

	/* define hash_entry->action.dword */
	/* case for LAN->WAN */
	if ((in_lan_wan_status == HW_NAT_LAN) 
			&& (out_lan_wan_status == HW_NAT_WAN)) {
		/* check if WAN requires PPPoE */
#ifdef CONFIG_CS351X_DUAL_WAN
		/* 1st, if VLAN is seen in TX */
		if (tx_vid != 0) {
			vlan_ether_hdr = (struct vlan_ethhdr *)skb->data;
			pppoe_hdr = (struct pppoe_hdr *)(skb->data + VLAN_ETH_HLEN);
			eth_proto = vlan_ether_hdr->h_vlan_encapsulated_proto;
		} else
#endif
		{	/* no vlan is seen */
			pppoe_hdr = (struct pppoe_hdr *)(ether_hdr + 1);
			eth_proto = ether_hdr->h_proto;
		}
		ppp_proto = *(u16 *)&pppoe_hdr->tag[0];

		if (eth_proto == __constant_htons(ETH_P_PPP_SES)	/* 0x8864 */
				&& ppp_proto == __constant_htons(PPP_IP)) {	/* 0x21 */
			hash_entry->action.dword = NAT_PPPOE_PPTP_LAN2WAN_ACTIONS;
			hash_entry->param.pppoe = htons(pppoe_hdr->sid);
		} else {
			hash_entry->action.dword = NAT_PPTP_LAN2WAN_ACTIONS;
			hash_entry->param.pppoe = 0;
		}
	}

	/* case for WAN->LAN */
	if ((in_lan_wan_status == HW_NAT_WAN) 
			&& (out_lan_wan_status == HW_NAT_LAN))
		hash_entry->action.dword = (nat_cb->pppoe_frame) ? NAT_PPPOE_PPTP_WAN2LAN_ACTIONS : NAT_PPTP_WAN2LAN_ACTIONS;

	/* define vlan action for hash_entry->action */
#ifdef CONFIG_CS351X_DUAL_WAN
	if (tx_vid != 0)	/* insert/replace vlan header */
		hash_entry->action.dword |= ACTION_VLAN_INS_BIT;
	else if ((nat_cb_vid != 0) && (tx_vid == 0))	/* remove vlan header */
		hash_entry->action.dword |= ACTION_VLAN_DEL_BIT;
	else	/* do not do anything */
		hash_entry->action.bits.vlan = 0;
#endif

	/* set destination queue */
	hash_entry->action.bits.dest_qid = sl351x_nat_assign_qid(IPPROTO_GRE, sip, dip, 0, ntohs(gre_hdr->call_id));
	hash_entry->action.bits.dest_qid += (port==0) ? TOE_GMAC0_HW_TXQ2_QID : TOE_GMAC1_HW_TXQ2_QID;;

	/* enable timer */
	hash_entry->tmo.counter = hash_entry->tmo.interval = cfg->gre_tmo_interval;

	/* write hash entry to hash table and validate it */
	gre_write_hash_entry(hash_index, hash_entry);
	// hash_dump_entry(hash_index);
	hash_nat_enable_owner(hash_index);
	/* Must last one, else HW Tx fast SW */
	hash_validate_entry(hash_index);

	return 0;
}


#ifdef _HAVE_DYNAMIC_PORT_LIST									   	
/*----------------------------------------------------------------------
* sl_nat_add_port
*----------------------------------------------------------------------*/
void sl_nat_add_port(u8 protocol, u16 port)
{
	int 	i;
	u16		*port_ptr;
	
	if (protocol == IPPROTO_TCP)
		port_ptr = dynamic_tcp_port_list;
	else if (protocol == IPPROTO_UDP)
		port_ptr = dynamic_udp_port_list;
	else
		return;
		
	for (i=0; *port_ptr; i++)
	{
		if (port == *port_ptr)
			return;
		port_ptr++;
	}
	port_ptr++;
	*port_ptr = port;
}

/*----------------------------------------------------------------------
* sl_nat_remove_port
*----------------------------------------------------------------------*/
void sl_nat_remove_port(u8 protocol, u16 port)
{
	int 	i, j;
	u16		*port_ptr, *next;
	
	if (protocol == IPPROTO_TCP)
		port_ptr = dynamic_tcp_port_list;
	else if (protocol == IPPROTO_UDP)
		port_ptr = dynamic_udp_port_list;
	else
		return;
		
	for (i=0; *port_ptr; i++, port_ptr++)
	{
		if (port == *port_ptr)
		{
			port_next = port_ptr + 1;
			for (j=i+1; *port_next; i++, j++)
				*port_ptr++ = *port_next++;
			*port_ptr = 0;
			return;
		}
	}
}
#endif

#if 0
/* 
 *  IGMP packet come from WAN -> LAN.
 *  IGMP Proxy will set DA and DIP let LAN join IGMP group.
 */
void igmp_add_hash_entry(void)
{
	IGMP_HASH_ENTRY_T	*hash_entry;
	u32					hash_data[HASH_MAX_DWORDS];
	NAT_CFG_T			*cfg;
	int					hash_index;
	
	cfg = (NAT_CFG_T *)&nat_cfg;
	hash_entry = (IGMP_HASH_ENTRY_T *)&hash_data;
	hash_entry->key.Ethertype = 0;
	hash_entry->key.port_id = cfg->wan_port;	
	hash_entry->key.rule_id = IGMP_RULE;	
	memcpy(hash_entry->key.da, key_da, 6);
	hash_entry->key.ip_protocol = 0; 
	hash_entry->key.reserved1 	= 0;
	hash_entry->key.dip 		= key_dip; 
	
	hash_entry->action.dword = 0;
	hash_entry->action.bits.srce_qid = TOE_HW_FREE_QID;
	hash_entry->action.bits.dest_qid = (cfg->wan_port == 1) ? TOE_GMAC0_HW_TXQ2_QID : TOE_GMAC1_HW_TXQ2_QID;
	
	if (timeout == 0x1)	
		hash_entry->tmo.counter = hash_entry->tmo.interval = 0x7FFF;
	else
		hash_entry->tmo.counter = hash_entry->tmo.interval = timeout;
	
	hash_index = igmp_build_keys(&hash_entry->key);
	
	if (hash_get_valid_flag(hash_index)) {
		printk("IGMP Hash Collision\n");
		return;
	}
	
	igmp_write_hash_entry(hash_index, hash_entry);
	hash_nat_enable_owner(hash_index);
//	nat_printf("%lu Validate a hash entry %d\n", jiffies/HZ, hash_index);
//	hash_dump_entry(hash_index);
	hash_validate_entry(hash_index); 
	return;
}
#endif	//#if 0, igmp_add_hash_entry

/* 
 *  Given DA,DIP,delete IGMP hash entry.
 */
void igmp_del_hash_entry(u_int8_t port, u_int32_t vlan, u_int32_t protocol)
{
	NAT_0_HASH_ENTRY_T	*hash_entry;
	u32					hash_data[HASH_MAX_DWORDS];
	NAT_CFG_T			*cfg;
	int					hash_index;
	
	cfg = (NAT_CFG_T *)&nat_cfg;
	hash_entry = (NAT_0_HASH_ENTRY_T *)&hash_data;
	hash_entry->key.Ethertype = 0;
	hash_entry->key.port_id = port;	
	hash_entry->key.rule_id = IGMP_RULE;	
	memcpy(hash_entry->key.da, key_da_del, 6);
	hash_entry->key.reserved3 	= 0;
	hash_entry->key.vlan_id     = vlan;
	hash_entry->key.pppoe_sid 	= 0;
	hash_entry->key.ip_protocol = protocol; 
	hash_entry->key.reserved1 	= 0;
	hash_entry->key.reserved2 	= 0;
	hash_entry->key.dip 		= key_dip_del; 
	hash_index = nat_0_build_keys(&hash_entry->key);
	nat_printf("Invalidate a hash entry %d\n", hash_index);
	hash_nat_disable_owner(hash_index);
	hash_invalidate_entry(hash_index);
	
	return;
}

void conntrack_del_hash_entry(int port, u32 srcip, u32 dstip, u16 proto, u32 sport, u32 dport)
{
		NAT_HASH_ENTRY_T	*hash_entry;
		u32					hash_data[HASH_MAX_DWORDS];
		NAT_CFG_T			*cfg;
		int					hash_index;
	
		cfg = (NAT_CFG_T *)&nat_cfg;
		hash_entry = (NAT_HASH_ENTRY_T *)&hash_data;
		hash_entry->key.Ethertype 	= 0;
		hash_entry->key.port_id 	= port;
		hash_entry->key.rule_id 	= CONFIG_SL351x_TCP_UDP_RULE_ID;
#ifdef CONFIG_SL351x_RTLDMZ
		hash_entry->key.vlan_id     = nat_cb_vid;
		hash_entry->key.pppoe_sid 	= 0;	
#endif
		hash_entry->key.ip_protocol = proto;
		hash_entry->key.reserved1 	= 0;
		hash_entry->key.reserved2 	= 0;
		hash_entry->key.sip 		= srcip;
		hash_entry->key.dip 		= dstip;
		hash_entry->key.sport 		= sport;
		hash_entry->key.dport 		= dport;
		hash_index = nat_build_keys(&hash_entry->key);
//		nat_printf("Invalidate a hash entry %d\n", hash_index);
		
		hash_nat_disable_owner(hash_index);
		hash_invalidate_entry(hash_index);
	
	return;
}

#ifdef CONFIG_CS351X_DUAL_WAN
static inline int sl351x_get_vlan_id(struct net_device* dev, char* vlan_dev_name)
{
	struct net_device *vlan_dev = dev_get_by_name(vlan_dev_name);
	int rv = 0;

	if (vlan_dev) {
		if ((vlan_dev->priv_flags & IFF_802_1Q_VLAN)
				&& (VLAN_DEV_INFO(vlan_dev)->real_dev == dev)) {
			rv = VLAN_DEV_INFO(vlan_dev)->vlan_id;
		} else if (vlan_dev == dev) {
			rv = 0;
		} else {
			rv = -EINVAL;
		}
		dev_put(vlan_dev);
	} else {
		rv = -ENODEV;
	}
	return rv;
}
#else
static inline int sl351x_get_vlan_id(struct net_device* dev, char* vlan_dev_name)
{
	return 0;
}
#endif

/*----------------------------------------------------------------------
* sl351x_nat_ioctl
*----------------------------------------------------------------------*/
int sl351x_nat_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	GMAC_INFO_T 		*tp = (GMAC_INFO_T *)dev->priv;
	int 				i, j, port_id, err = 0, vlan_id;
//	int					ii,jj;
    NATCMD_HDR_T		nat_hdr;
    NAT_REQ_E			ctrl;
	unsigned char		*req_datap;
	NAT_IP_ENTRY_T		*ipcfg;
	NAT_XPORT_ENTRY_T	*xport_entry;
	NAT_WRULE_ENTRY_T	*wrule_entry;
	unsigned int		qid,phy_data_s = -1,location_r = -1,length_r = -1,location_w = -1,data_w = -1;
	unsigned int		size_r,size_w;
	unsigned short		phy_addr = -1,phy_reg = -1,phy_len = -1, phy_addr_s = 0, phy_reg_s = 0;
	NAT_GMACDEV_T		*nat_gmacdev;
	NAT_GMACDEV_T		*nat_gmacdev_out;
	NAT_GMACDEV_VLAN_T	*vlancfg;
	u_int8_t 		port;
	uint32_t		vlan, protocol;

	port_id = tp->port_id;
//debug WEN
//printk("%s::device name is %s and %s\n", __func__, dev->name, rq->ifr_name);
	nat_gmacdev = sl351x_nat_find_gmacdev(dev);
	if (nat_gmacdev == NULL) return -ENODEV;

	if (copy_from_user((void *)&nat_hdr, rq->ifr_data, sizeof(nat_hdr)))
		return -EFAULT;
	req_datap = (unsigned char *)rq->ifr_data + sizeof(nat_hdr);

	switch (nat_hdr.cmd) {
	case NATSNATSTATUS:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_STATUS_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.status, req_datap, sizeof(ctrl.status)))
			return -EFAULT;
		if (ctrl.status.enable != 0 && ctrl.status.enable != 1)
			return -EPERM;
		// sl351x_nat_set_enabled_flag(ctrl.status.enable);
		if (nat_cfg.enabled && (ctrl.status.enable == 0))
		{
			for (i=0; i<HASH_TOTAL_ENTRIES; i++)
			{
				if (hash_get_nat_owner_flag(i))
				{
					hash_nat_disable_owner(i);
					hash_invalidate_entry(i);
				}
			}
		}
		nat_cfg.enabled = ctrl.status.enable;
		break;
	case NATGNATSTATUS:	
		if (nat_hdr.len != sizeof(NAT_STATUS_T))
			return -EPERM;
		ctrl.status.enable = nat_cfg.enabled;
		if (copy_to_user(req_datap, (void *)&ctrl.status, sizeof(ctrl.status)))
			return -EFAULT;
		break;
	case NATSETPORT:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_PORTCFG_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.portcfg, req_datap, sizeof(ctrl.portcfg)))
			return -EFAULT;
#ifndef DUAL_BAND_VLAN_APPLY
		if (ctrl.portcfg.portmap == 0)
			nat_cfg.lan_port = port_id;
		else if (ctrl.portcfg.portmap == 1)
			nat_cfg.wan_port = port_id;
#endif	//DUAL_BAND_VLAN_APPLY
#ifndef CONFIG_CS351X_DUAL_WAN
		if (ctrl.portcfg.portmap == 0)
			nat_cfg.lan_port = port_id;
		else if (ctrl.portcfg.portmap == 1)
			nat_cfg.wan_port = port_id;
#endif
		if (ctrl.portcfg.vlan_id == 0) {
			if (ctrl.portcfg.portmap == 0) {
				nat_gmacdev->lan_wan_status = HW_NAT_LAN;
				for (i=0; i<nat_gmacdev->number_vlan; i++)
					nat_gmacdev->vlanDev[i].lan_wan_status = HW_NAT_LAN;
			} else if (ctrl.portcfg.portmap == 1) {
				nat_gmacdev->lan_wan_status = HW_NAT_WAN;
				for (i=0; i<nat_gmacdev->number_vlan; i++)
					nat_gmacdev->vlanDev[i].lan_wan_status = HW_NAT_WAN;
			} else return -EPERM;
		} else {
			j = nat_gmacdev->number_vlan;
			for (i=0; i<nat_gmacdev->number_vlan; i++) {
				if (nat_gmacdev->vlanDev[i].vlan_id == ctrl.portcfg.vlan_id)
					j = i;
			}
			if (ctrl.portcfg.portmap == 0)
				nat_gmacdev->vlanDev[j].lan_wan_status = HW_NAT_LAN;
			else if (ctrl.portcfg.portmap == 1)
				nat_gmacdev->vlanDev[j].lan_wan_status = HW_NAT_WAN;
			else
				return -EPERM;
		}
		break;
	case NATGETPORT:
		if (nat_hdr.len != sizeof(NAT_PORTCFG_T))
			return -EPERM;
		if (nat_gmacdev->lan_wan_status == HW_NAT_LAN)
			ctrl.portcfg.portmap = 0;
		else if (nat_gmacdev->lan_wan_status == HW_NAT_WAN)
			ctrl.portcfg.portmap = 1;
		else
			return -EPERM;
		ctrl.portcfg.vlan_id = nat_gmacdev->number_vlan;
		if (copy_to_user(req_datap, (void *)&ctrl.portcfg, sizeof(ctrl.portcfg)))
			return -EFAULT;
		break;
	case NATADDIP:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_IPCFG_T))
			return -EPERM;
		i = nat_gmacdev->ipcfg.total;
		if (i >= CONFIG_NAT_MAX_IP_NUM)
			return -E2BIG;
		if (copy_from_user((void *)&nat_gmacdev->ipcfg.entry[i], req_datap, sizeof(NAT_IPCFG_T)))
			return -EFAULT;
		nat_gmacdev->ipcfg.total++;
		break;
	case NATDELIP:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_IPCFG_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.ipcfg, req_datap, sizeof(ctrl.ipcfg)))
			return -EFAULT;
		ipcfg = (NAT_IP_ENTRY_T *)&nat_gmacdev->ipcfg.entry[0];
		for (i=0; i<nat_gmacdev->ipcfg.total; i++, ipcfg++)
		{
			if ((ipcfg->ipaddr == ctrl.ipcfg.entry.ipaddr) 
					&& (ipcfg->netmask == ctrl.ipcfg.entry.netmask) 
					&& (ipcfg->vlan_id == ctrl.ipcfg.entry.vlan_id))
			{
				NAT_IP_ENTRY_T *ipcfg_next;
				ipcfg_next = ipcfg + 1;
				for (j=i+1; j < nat_gmacdev->ipcfg.total; i++, j++)
				{
					memcpy((void *)ipcfg, (void *)ipcfg_next, sizeof(NAT_IP_ENTRY_T));
					ipcfg++;
					ipcfg_next++;	
				}
				ipcfg->ipaddr = 0;
				ipcfg->netmask = 0;
				ipcfg->vlan_id = 0;
				nat_gmacdev->ipcfg.total--;
				return 0;
			}
		}
		return -ENOENT;
	case NATGETIP:
		if (nat_hdr.len != sizeof(NAT_IPCFG_ALL_T))
			return -EPERM;
		if (copy_to_user(req_datap, (void *)&nat_gmacdev->ipcfg, sizeof(NAT_IPCFG_ALL_T)))
			return -EFAULT;
		break;
	case NATAXPORT:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_XPORT_T))
			return -EPERM;
		i = nat_cfg.xport.total;
		if (i >= CONFIG_NAT_MAX_XPORT)
			return -E2BIG;
		if (copy_from_user((void *)&nat_cfg.xport.entry[i], req_datap, sizeof(NAT_XPORT_T)))
			return -EFAULT;
		nat_cfg.xport.total++;
		break;
	case NATDXPORT:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_XPORT_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.xport, req_datap, sizeof(NAT_XPORT_T)))
			return -EFAULT;
		xport_entry = (NAT_XPORT_ENTRY_T *)&nat_cfg.xport.entry[0];
		for (i=0; i<nat_cfg.xport.total; i++, xport_entry++)
		{
			if (memcmp((void *)xport_entry, (void *)&ctrl.xport, sizeof(NAT_XPORT_ENTRY_T)) == 0)
			{
				NAT_XPORT_ENTRY_T *xport_next;
				xport_next = xport_entry + 1;
				for (j=i+1; j < nat_cfg.xport.total; i++, j++)
				{
					memcpy((void *)xport_entry, (void *)xport_next, sizeof(NAT_XPORT_ENTRY_T));
					xport_entry++;
					xport_next++;	
				}
				memset((void *)xport_entry, 0, sizeof(NAT_XPORT_ENTRY_T));
				nat_cfg.xport.total--;
				return 0;
			}
		}
		return -ENOENT;
	case NATGXPORT:
		if (nat_hdr.len != sizeof(NAT_XPORT_ALL_T))
			return -EPERM;
		if (copy_to_user(req_datap, (void *)&nat_cfg.xport, sizeof(NAT_XPORT_ALL_T)))
			return -EFAULT;
		break;
	case NATSWEIGHT:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_WEIGHT_T))
			return -EPERM;
		if (copy_from_user((void *)&nat_cfg.weight, req_datap, sizeof(NAT_WEIGHT_T)))
			return -EFAULT;
		mac_set_hw_tx_weight(dev, (char *)&nat_cfg.weight);
		break;
	case NATGWEIGHT:
		if (nat_hdr.len != sizeof(NAT_WEIGHT_T))
			return -EPERM;
		mac_get_hw_tx_weight(dev, (char *)&nat_cfg.weight);
		if (copy_to_user(req_datap, (void *)&nat_cfg.weight, sizeof(NAT_WEIGHT_T)))
			return -EFAULT;
		break;
	case NATAWRULE:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_WRULE_T))
			return -EPERM;
		if (copy_from_user((void *)&qid, req_datap, sizeof(qid)))
			return -EFAULT;
		if (qid > CONFIG_NAT_TXQ_NUM)
			return -EPERM;
		i = nat_cfg.wrule[qid].total;
		if (i >= CONFIG_NAT_MAX_WRULE)
			return -E2BIG;
		if (copy_from_user((void *)&nat_cfg.wrule[qid].entry[i], req_datap+sizeof(qid), sizeof(NAT_WRULE_T)))
			return -EFAULT;
		nat_cfg.wrule[qid].total++;
		break;
	case NATDWRULE:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_WRULE_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.wrule, req_datap, sizeof(NAT_WRULE_T)))
			return -EFAULT;
		qid = ctrl.wrule.qid;
		if (qid >= CONFIG_NAT_TXQ_NUM)
			return -EPERM;
		wrule_entry = (NAT_WRULE_ENTRY_T *)&nat_cfg.wrule[qid].entry[0];
		for (i=0; i<nat_cfg.wrule[qid].total; i++, wrule_entry++)
		{
			if (memcmp((void *)wrule_entry, (void *)&ctrl.wrule.entry, sizeof(NAT_WRULE_ENTRY_T)) == 0)
			{
				NAT_WRULE_ENTRY_T *wrule_next;
				wrule_next = wrule_entry + 1;
				for (j=i+1; j < nat_cfg.wrule[qid].total; i++, j++)
				{
					memcpy((void *)wrule_entry, (void *)wrule_next, sizeof(NAT_WRULE_ENTRY_T));
					wrule_entry++;
					wrule_next++;	
				}
				memset((void *)wrule_entry, 0, sizeof(NAT_WRULE_ENTRY_T));
				nat_cfg.wrule[qid].total--;
				return 0;
			}
		}
		return -ENOENT;
	case NAT_DEL_ENTRY:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_WRULE_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.wrule, req_datap, sizeof(NAT_WRULE_T)))
			return -EFAULT;
//		printk("sip:%x dip:%x pro:%d sport:%d-%d dport:%d-%d \n",
//			ctrl.wrule.entry.sip_start,ctrl.wrule.entry.dip_start,ctrl.wrule.entry.protocol,
//			ctrl.wrule.entry.sport_start,ctrl.wrule.entry.sport_end,ctrl.wrule.entry.dport_start,ctrl.wrule.entry.dport_end);
		
		sl351x_hash_scan_and_invalidate(ctrl.wrule.entry.sip_start,
						ctrl.wrule.entry.dip_start, 
						ctrl.wrule.entry.protocol,
						ctrl.wrule.entry.sport_start | (ctrl.wrule.entry.sport_end) << 16 ,
						ctrl.wrule.entry.dport_start | (ctrl.wrule.entry.dport_end) << 16 );
		
		break;	
	case NATGWRULE:
		if (nat_hdr.len != sizeof(NAT_WRULE_ALL_T))
			return -EPERM;
		if (copy_from_user((void *)&qid, req_datap, sizeof(qid)))
			return -EFAULT;
		if (qid >= CONFIG_NAT_TXQ_NUM)
			return -EPERM;
		if (copy_to_user(req_datap, (void *)&nat_cfg.wrule[qid], sizeof(NAT_WRULE_ALL_T)))
			return -EFAULT;
		break;
	case NATSDEFQ:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_QUEUE_T))
			return -EPERM;
		if (copy_from_user((void *)&nat_cfg.default_hw_txq, req_datap, sizeof(u32)))
			return -EFAULT;
		break;
	case NATGDEFQ:
		if (nat_hdr.len != sizeof(NAT_QUEUE_T))
			return -EPERM;
		if (copy_to_user(req_datap, (void *)&nat_cfg.default_hw_txq, sizeof(u32)))
			return -EFAULT;
		break;
	case NATRMIPCFG:
		nat_gmacdev->ipcfg.total = 0;
		break;
	case NATTESTENTRY:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_TESTENTRY_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.init_entry, req_datap, sizeof(ctrl.init_entry)))
			return -EFAULT;
		if (ctrl.init_entry.init_enable != 0 && ctrl.init_entry.init_enable != 1)
			return -EPERM;
		nat_cfg.init_enabled = ctrl.init_entry.init_enable;
		break;
	case GMIIREG:
		if (nat_hdr.len != sizeof(NAT_GMIIREG_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.get_mii_reg, req_datap, sizeof(ctrl.get_mii_reg)))
			return -EFAULT; //Invalid argument
		
		phy_addr = ctrl.get_mii_reg.phy_addr;
		phy_reg = ctrl.get_mii_reg.phy_reg;
		phy_len = ctrl.get_mii_reg.phy_len;
#if 0	/* Remove sl_switch.c, it is a module now */				
		if (Giga_switch == 1)
		{
			if (phy_addr == 2)
			{
				nat_printf("\n");
				for(jj=0;jj<4;jj++)
				{
					unsigned int data_switch;
					for (ii=0; ii< phy_len ; ii++)
					{
						data_switch = phy_read(jj,phy_reg);
						nat_printf("MII Switch Phy %d Port %d Reg %d Data = 0x%x\n", phy_addr, jj,phy_reg, data_switch);
						phy_reg++;
					}
					phy_reg = phy_reg - phy_len;
					nat_printf("\n");
				}
			}
			else if (phy_addr == 1)
			{
				for (i=0; i< phy_len ; i++)
				{
					unsigned int data;
					data = mii_read(phy_addr,phy_reg); 
					nat_printf("MII Phy %d Reg %d Data = 0x%x\n", phy_addr, phy_reg++, data);
				}
			}
			else
				err = 1;
		}
		else 
#endif //#if 0			
		{
			if ((phy_addr == 1) || (phy_addr == 2))
			{
				for (i=0; i< phy_len ; i++)
				{
					unsigned int data;
					data = mii_read(phy_addr,phy_reg); 
					nat_printf("MII Phy %d Reg %d Data = 0x%x\n", phy_addr, phy_reg++, data);
				}
			}
			else 
				err = 1;
		}
		
		if (err == 1)
		{
			nat_printf("Syntax error!\n");
			nat_printf("Syntax: MII read [-a phy addr] [-r phy reg] [-l length]\n");
			nat_printf("Options:\n");
			nat_printf("\t-a  Phy address\n");
			nat_printf("\t-r  Phy registers\n");
			nat_printf("\t-l  Display total registers\n");
			nat_printf("MII Phy address -a %d error !! Phy address must be 1 or 2.\n", phy_addr);
		}
		break;
		
	case SMIIREG:
		if (nat_hdr.len != sizeof(NAT_SMIIREG_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.set_mii_reg, req_datap, sizeof(ctrl.set_mii_reg)))
			return -EFAULT;
		
		phy_addr_s = ctrl.set_mii_reg.phy_addr;
		phy_reg_s = ctrl.set_mii_reg.phy_reg;
		phy_data_s = ctrl.set_mii_reg.phy_data;
#if 0	/* Remove sl_switch.c, it is a module now */		
		if (Giga_switch == 1)
		{
			if (phy_addr_s == 2)
			{
				nat_printf("\n");
				for(jj=0;jj<4;jj++)
				{
						phy_write(jj,phy_reg_s,phy_data_s);
						phy_write_masked(jj,phy_reg_s,phy_data_s,0xffff);
						nat_printf("Write MII Switch Phy %d Port %d Reg %d Data = 0x%x\n", phy_addr_s, jj,phy_reg_s, phy_data_s);
				}
			}
			else if (phy_addr_s == 1)
			{
					mii_write(phy_addr_s,phy_reg_s,phy_data_s); 
					nat_printf("Write MII Phy %d Reg %d Data = 0x%x\n", phy_addr_s, phy_reg_s, phy_data_s);
			}
			else
				err = 1;
		}
		else
#endif //#if 0			
		{
			if ((phy_addr_s == 1) || (phy_addr_s == 2))
			{
				mii_write(phy_addr_s,phy_reg_s,phy_data_s); 
				nat_printf("Write MII Phy %d Reg %d Data = 0x%x\n", phy_addr_s, phy_reg_s, phy_data_s);
			}
			else 
				err = 1;
		}
		
		if (err == 1)
		{
			nat_printf("Syntax error!\n");
			nat_printf("Syntax: MII write [-a phy addr] [-r phy reg] [-d data]\n");
			nat_printf("Options:\n");
			nat_printf("\t-a  Phy address\n");
			nat_printf("\t-r  Phy registers\n");
			nat_printf("\t-d  date\n");
			nat_printf("MII Phy address -a %d error !! Phy address must be 1 or 2.\n", phy_addr);
		}
		break;	
		
#ifdef GMAC_DEBUG_U			
	case DUMPRX:	
		if (nat_hdr.len != sizeof(NAT_DUMP_RX))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.dump_rx_packet, req_datap, sizeof(ctrl.dump_rx_packet)))
			return -EFAULT;
		if (ctrl.dump_rx_packet.enable != 0 && ctrl.dump_rx_packet.enable != 1)
			return -EPERM;	
		gmac_dump_rxpkt	= ctrl.dump_rx_packet.enable;
		break;	
	case DUMPTX:	
		if (nat_hdr.len != sizeof(NAT_DUMP_TX))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.dump_tx_packet, req_datap, sizeof(ctrl.dump_tx_packet)))
			return -EFAULT;
		if (ctrl.dump_tx_packet.enable != 0 && ctrl.dump_tx_packet.enable != 1)
			return -EPERM;	
		gmac_dump_txpkt	= ctrl.dump_tx_packet.enable;
		break;	
#endif
	case REGREAD:	
		if (nat_hdr.len != sizeof(NAT_REGREAD))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.reg_read, req_datap, sizeof(ctrl.reg_read)))
			return -EFAULT;
		location_r = ctrl.reg_read.location;
		length_r = ctrl.reg_read.length;
		size_r = ctrl.reg_read.size;
    	
    	if (size_r == 1 && ((MIN_READ <= location_r) && (location_r <= MAX_READ)))//IO MEM can not dump use dm_byte.
    		size_r = 4;
		if (size_r == 1)
			dm_byte(location_r, length_r);
		if (size_r == 2)
			dm_short(location_r, length_r);
		if (size_r == 4)
			dm_long_1(location_r, length_r);
		break;		
	case REGWRITE:	
		if (nat_hdr.len != sizeof(NAT_REGWRITE))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.reg_write, req_datap, sizeof(ctrl.reg_write)))
			return -EFAULT;
		location_w = ctrl.reg_write.location;
		data_w = ctrl.reg_write.data;
		size_w = ctrl.reg_write.size;
		if (size_w == 1)
		{
			if (data_w > 0xff)
				err = 1;
			else
			{	
				writeb(data_w,location_w);
				nat_printf("Write Data 0x%X to Location 0x%X\n",(u32)data_w, location_w);
			}
		}
		if (size_w == 2)
		{
			if (data_w > 0xffff)
				err = 1;
			else
			{
				writew(data_w,location_w);
				nat_printf("Write Data 0x%X to Location 0x%X\n",(u32)data_w, location_w);
			}
		}
		if (size_w == 4)
		{
			if (data_w > 0xffffffff)
				err = 1;
			else
			{	
				writel(data_w,location_w);
				nat_printf("Write Data 0x%X to Location 0x%X\n",(u32)data_w, location_w);
			}
		}
		if (err == 1)
		{
			nat_printf("Syntax:	gmac write mem [-b <location>] [-d <data>] [-1|2|4]\n");
			nat_printf("Options:\n");
			nat_printf("\t-b  Register Address\n");
			nat_printf("\t-d  Data Vaule\n");
			if (size_w == 1)
				nat_printf("\t-1  Data 0x%X < 0xFF\n",data_w);
			if (size_w == 2)	
				nat_printf("\t-2  Data 0x%X < 0xFFFF\n",data_w);
			if (size_w == 4)	
				nat_printf("\t-4  Data 0x%X < 0xFFFFFFFF\n",data_w);
		}
		break;

	case WAIT_BLOCKED_URL:
		if (nat_hdr.len != (sizeof(struct iphdr)+sizeof(struct tcphdr) ))
			return -EPERM;
		memset(block_url_info,0,sizeof(struct iphdr)+sizeof(struct tcphdr));
		interruptible_sleep_on(&url_block_wait);
		nat_hdr.len = url_block_len;
		//req_datap -= sizeof(short) ;
		//if (copy_to_user(req_datap, (void *)&nat_hdr.len, sizeof(short)))
		//	return -EFAULT;
		if (copy_to_user(req_datap, (void *)block_url_info, sizeof(struct iphdr)+sizeof(struct tcphdr)))
			return -EFAULT;
		break;
#if 0	/* Remove sl_switch.c, it is a module now */
	case SWITCHSHOWMIB:	
		if (nat_hdr.len != sizeof(NAT_SWITCHSHOWMIB))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.show_switch, req_datap, sizeof(ctrl.show_switch)))
			return -EFAULT;
		if (ctrl.show_switch.enable != 0 && ctrl.show_switch.enable != 1)
			return -EPERM;	
		switch_showing_flag	= ctrl.show_switch.enable;
		if (switch_showing_flag)
			switch_show_statistics(!switch_showing_flag);
		break;

	case SWITCHRESETMIB:	
		if (nat_hdr.len != sizeof(NAT_SWITCHRESETMIB))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.reset_switch, req_datap, sizeof(ctrl.reset_switch)))
			return -EFAULT;
		if (ctrl.reset_switch.enable != 0 && ctrl.reset_switch.enable != 1)
			return -EPERM;	
		switch_reset_flag	= ctrl.reset_switch.enable;
		if (switch_reset_flag)
			switch_show_statistics(switch_reset_flag);
		break;		
#endif	
	case NATSDEVSTATUS:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_STATUS_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.dev_status, req_datap, sizeof(ctrl.dev_status)))
			return -EFAULT;
		if ((ctrl.dev_status.enable != 0) && (ctrl.dev_status.enable != 1))
			return -EPERM;
// NEED TO MODIFY THE FOLLOWING PART!!!!
#if 0
		if (nat_cfg.enabled && (ctrl.dev_status.enable == 0)) {
			for (i=0; i<HASH_TOTAL_ENTRIES; i++) {
				if (hash_get_nat_owner_flag(i)) {
					hash_nat_disable_owner(i);
					hash_invalidate_entry(i);
				}
			}
		}
#endif
		j = nat_gmacdev->number_vlan;
		if (ctrl.dev_status.vlan_id != 0) {
			for (i=0; i<nat_gmacdev->number_vlan; i++) {
				if (nat_gmacdev->vlanDev[i].vlan_id == ctrl.dev_status.vlan_id)
					j = i;
			}
			if (j == nat_gmacdev->number_vlan) return -ENOENT;
			nat_gmacdev->vlanDev[j].hwNAT_enabled = ctrl.dev_status.enable;
		} else {
			nat_gmacdev->hwNAT_enabled = ctrl.dev_status.enable;
			for (i=0; i<nat_gmacdev->number_vlan; i++) {
				nat_gmacdev->vlanDev[i].hwNAT_enabled = ctrl.dev_status.enable;
			}
		}
		break;

	case NATGDEVSTATUS:
		if (nat_hdr.len != sizeof(NAT_STATUS_T))
			return -EPERM;
		ctrl.dev_status.enable = nat_gmacdev->hwNAT_enabled;
		ctrl.dev_status.vlan_id = nat_gmacdev->number_vlan;
		if (copy_to_user(req_datap, (void *)&ctrl.dev_status, sizeof(ctrl.dev_status)))
			return -EFAULT;
		break;

	case NATISGMAC:
		if (nat_hdr.len != sizeof(NAT_STATUS_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.dev_status, req_datap, sizeof(ctrl.dev_status)))
			return -EFAULT;
		if (nat_gmacdev != NULL)
			return 168;
		else 
			return -ENODEV;
		break;

	case NATADDPATH:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_PATH_ENTRY_T))
			return -EPERM;
		i = nat_gmacdev->hw_nat_path.total;
		if (i >= CONFIG_NAT_MAX_PATH)
			return -E2BIG;
		if (copy_from_user((void *)&ctrl.natpath, req_datap, sizeof(NAT_PATH_ENTRY_T)))
			return -EFAULT;
		nat_gmacdev_out = sl351x_nat_find_gmacdev_byname(ctrl.natpath.name);
		if (nat_gmacdev_out != NULL) {
			if ((err = sl351x_nat_add_path(nat_gmacdev, ctrl.natpath.vlan_id, nat_gmacdev_out, ctrl.natpath.out_vlan_id)) == 0)
				return 0;
			else {
				if (err == 1)
					printk("src and dst device are the same\n");
				else if (err == 2)
					printk("a same path is existed already\n");
				else if (err == 3)
					printk("over the size\n");
				return -EFAULT;
			}
		} else {
			printk("Unable to find matched destination device\n");
			return -EFAULT;
		}
		break;

	case NATDELPATH:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_PATH_ENTRY_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.natpath, req_datap, sizeof(NAT_PATH_ENTRY_T)))
			return -EFAULT;
		nat_gmacdev_out = sl351x_nat_find_gmacdev_byname(ctrl.natpath.name);
		if ((nat_gmacdev_out != NULL) &&
				(sl351x_nat_del_path(nat_gmacdev, ctrl.natpath.vlan_id, nat_gmacdev_out, ctrl.natpath.out_vlan_id) == 0))
			return 0;
		else {
			printk("Unable to find matched destination device\n");
			return -EFAULT;
		}
		break;

	case NATGETPATH:
		if (nat_hdr.len != sizeof(NAT_PATH_T))
			return -EPERM;
		if (copy_to_user(req_datap, (void *)&nat_gmacdev->hw_nat_path, sizeof(NAT_PATH_T)))
			return -EFAULT;
		return 0;
		break;

	case NATIGMP:
		if (nat_hdr.len != sizeof(NAT_NATIGMP_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.add_igmp_hash, req_datap, sizeof(ctrl.add_igmp_hash)))
			return -EFAULT;
		for (i=0; i < 6; i++) {
			key_da[i] = ctrl.add_igmp_hash.entry.key_da[i];
    	}	
		key_dip = ctrl.add_igmp_hash.entry.key_dip;
		timeout = ctrl.add_igmp_hash.entry.timeout;
		//igmp_add_hash_entry();
		break;
		
	case NATDELIGMP:
		if (nat_hdr.len != sizeof(NAT_NATIGMP_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.del_igmp_hash, req_datap, sizeof(ctrl.del_igmp_hash)))
			return -EFAULT;
		port = ctrl.del_igmp_hash.port;
		vlan = ctrl.del_igmp_hash.vlan_id;
		protocol = ctrl.del_igmp_hash.protocol;
		for (i=0; i < 6; i++) {
			key_da_del[i] = ctrl.del_igmp_hash.entry.key_da[i];
    	}	
		key_dip_del = ctrl.del_igmp_hash.entry.key_dip;
		igmp_del_hash_entry(port, vlan, protocol);
		break;			
	case NATSWWEIGHT:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_SWWEIGHT_T))
			return -EPERM;
		if (copy_from_user((void *)&nat_cfg.weight, req_datap, sizeof(NAT_SWWEIGHT_T)))
			return -EFAULT;
		mac_set_sw_tx_weight(dev, (char *)&nat_cfg.weight);
		break;	
		
	case NATGSWEIGHT:
		if (nat_hdr.len != sizeof(NAT_SWWEIGHT_T))
			return -EPERM;
		mac_get_sw_tx_weight(dev, (char *)&nat_cfg.weight);
		if (copy_to_user(req_datap, (void *)&nat_cfg.weight, sizeof(NAT_SWWEIGHT_T)))
			return -EFAULT;
		break;	

	case NATADDVLAN:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_GMACDEV_VLAN_T))
			return -EPERM;
		i = nat_gmacdev->number_vlan;
		if (i >= CONFIG_GMAC_VLAN_NUM)
			return -E2BIG;
		if (copy_from_user((void *)&nat_gmacdev->vlanDev[i], req_datap, sizeof(NAT_GMACDEV_VLAN_T)))
			return -EFAULT;
		nat_gmacdev->number_vlan++;
		break;

	case NATDELVLAN:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (nat_hdr.len != sizeof(NAT_GMACDEV_VLAN_T))
			return -EPERM;
		if (copy_from_user((void *)&(ctrl.vlancfg), req_datap, sizeof(NAT_GMACDEV_VLAN_T)))
			return -EFAULT;
		vlancfg = (NAT_GMACDEV_VLAN_T *)&(nat_gmacdev->vlanDev[0]);
		for (i=0; i<nat_gmacdev->number_vlan; i++, vlancfg++) {
			if (vlancfg->vlan_id == ctrl.vlancfg.vlan_id) {
				NAT_GMACDEV_VLAN_T *vlancfg_next;
				vlancfg_next = vlancfg + 1;
				for (j=i+1; j<nat_gmacdev->number_vlan; i++, j++) {
					memcpy((void *)vlancfg, (void *)vlancfg_next, sizeof(NAT_GMACDEV_VLAN_T));
					vlancfg++;
					vlancfg_next++;
				}
				vlancfg->hwNAT_enabled = 0;
				vlancfg->vlan_id = 0;
				vlancfg->lan_wan_status = 0;
				nat_gmacdev->number_vlan--;
				return 0;
			}
		}
		return -ENOENT;

	case NATGETVLAN:
		if (nat_hdr.len != sizeof(NAT_VLANCFG_ALL_T))
			return -EPERM;
		ctrl.vlanallcfg.total = nat_gmacdev->number_vlan;
		memcpy((void *)&(ctrl.vlanallcfg.entry[0]), 
				(void *)&(nat_gmacdev->vlanDev[0]), 
				sizeof(NAT_GMACDEV_VLAN_T) * nat_gmacdev->number_vlan);
		if (copy_to_user(req_datap, (void *)&ctrl.vlanallcfg, sizeof(NAT_VLANCFG_ALL_T)))
			return -EFAULT;
		break;

	case NATGETVLANID:
		if (nat_hdr.len != sizeof(NAT_STATUS_T))
			return -EPERM;
		if (copy_from_user((void *)&ctrl.dev_status, req_datap, sizeof(ctrl.dev_status)))
			return -EFAULT;
		vlan_id = sl351x_get_vlan_id(dev, rq->ifr_name);
		if (vlan_id < 0) return -ENODEV;
		else return vlan_id;
		break;
	default:
		return -EPERM;
	}
	
	return 0;
}

/*----------------------------------------------------------------------
* 	nat_init_test_entry
*	Initialize NAT test hash entries
*
*	SmartBits P1  -----> Lepus GMAC 0 --------------+
*													|
*													|
*             P3  <----- Lepus GMAC 1 -- HW TxQ0 <--+
*									  -- HW TxQ1 <--+
*									  -- HW TxQ2 <--+
*									  -- HW TxQ3 <--+
*
*	SmartBits P1  <----- Lepus GMAC 0 -- HW TxQ0 <--+
*									  -- HW TxQ1 <--+
*                                     -- HW TxQ2 <--+
*									  -- HW TxQ3 <--+
*													|
*													|
*             P3  -----> Lepus GMAC 1 --------------+
*
*   LAN GMAC0 <--------------------------------------------> GMAC1 WAN
*	192.168.[x].[y]:50 --> 168.95.[x].[y]:80 ---TXQ[y-1]---> 192.168.2.254:200[y] --> 168.95.[x].[y]:80
*	192.168.[x].[y]:50 <-- 168.95.[x].[y]:80 <--TXQ[y-1]---- 192.168.2.254:200[y] <-- 168.95.[x].[y]:80
*   where:
*		[x] : Packet Type
*		[y] : Tx Queue, 1 for TxQ0, 2 for TxQ1, 3 for TxQ2, 4 for TxQ3,
*
*
* Packet Type:								 
* 1. TCP Frames <---> TCP Frames
*   LAN GMAC0 <--------------------------------> GMAC1 WAN
*	192.168.1.1:50 --> 168.95.1.1:80 ---TXQ0---> 192.168.2.254:2001 --> 168.95.1.1:80
*	192.168.1.1:50 <-- 168.95.1.1:80 <--TXQ0---- 192.168.2.254:2001 <-- 168.95.1.1:80
*                                                                                 
*	192.168.1.2:50 --> 168.95.1.2:80 ---TXQ1---> 192.168.2.254:2002 --> 168.95.1.2:80
*	192.168.1.2:50 <-- 168.95.1.2:80 <--TXQ1---- 192.168.2.254:2002 <-- 168.95.1.2:80
*                                                                                 
*	192.168.1.3:50 --> 168.95.1.3:80 ---TXQ2---> 192.168.2.254:2003 --> 168.95.1.3:80
*	192.168.1.3:50 <-- 168.95.1.3:80 <--TXQ2---- 192.168.2.254:2003 <-- 168.95.1.3:80
*                                                                                 
*	192.168.1.4:50 --> 168.95.1.4:80 ---TXQ3---> 192.168.2.254:2004 --> 168.95.1.4:80
*	192.168.1.4:50 <-- 168.95.1.4:80 <--TXQ3---- 192.168.2.254:2004 <-- 168.95.1.4:80
*             
* 2 TCP Frames <----> PPPoE + TCP Frames
*   LAN GMAC0 <--------------------------------> GMAC1 WAN
*	192.168.2.1:50 --> 168.95.2.1:80 ---TXQ0---> 192.168.2.254:2001 --> 168.95.2.1:80
*	192.168.2.1:50 <-- 168.95.2.1:80 <--TXQ0---- 192.168.2.254:2001 <-- 168.95.2.1:80
*                                                                                 
*	192.168.2.2:50 --> 168.95.2.2:80 ---TXQ1---> 192.168.2.254:2002 --> 168.95.2.2:80
*	192.168.2.2:50 <-- 168.95.2.2:80 <--TXQ1---- 192.168.2.254:2002 <-- 168.95.2.2:80
*                                                                                 
*	192.168.2.3:50 --> 168.95.2.3:80 ---TXQ2---> 192.168.2.254:2003 --> 168.95.2.3:80
*	192.168.2.3:50 <-- 168.95.2.3:80 <--TXQ2---- 192.168.2.254:2003 <-- 168.95.2.3:80
*                                                                                 
*	192.168.2.4:50 --> 168.95.2.4:80 ---TXQ3---> 192.168.2.254:2004 --> 168.95.2.4:80
*	192.168.2.4:50 <-- 168.95.2.4:80 <--TXQ3---- 192.168.2.254:2004 <-- 168.95.2.4:80
*             
* 3 TCP Frames <----> VLAN + PPPoE + TCP Frames
*   LAN GMAC0 <--------------------------------> GMAC1 WAN
*	192.168.3.1:50 --> 168.95.3.1:80 ---TXQ0---> 192.168.2.254:2001 --> 168.95.3.1:80
*	192.168.3.1:50 <-- 168.95.3.1:80 <--TXQ0---- 192.168.2.254:2001 <-- 168.95.3.1:80
*                                                                                 
*	192.168.3.2:50 --> 168.95.3.2:80 ---TXQ1---> 192.168.2.254:2002 --> 168.95.3.2:80
*	192.168.3.2:50 <-- 168.95.3.2:80 <--TXQ1---- 192.168.2.254:2002 <-- 168.95.3.2:80
*                                                                                 
*	192.168.3.3:50 --> 168.95.3.3:80 ---TXQ2---> 192.168.2.254:2003 --> 168.95.3.3:80
*	192.168.3.3:50 <-- 168.95.3.3:80 <--TXQ2---- 192.168.2.254:2003 <-- 168.95.3.3:80
*                                                                                 
*	192.168.3.4:50 --> 168.95.3.4:80 ---TXQ3---> 192.168.2.254:2004 --> 168.95.3.4:80
*	192.168.3.4:50 <-- 168.95.3.4:80 <--TXQ3---- 192.168.2.254:2004 <-- 168.95.3.4:80
*             
* 4 VLAN-A + TCP Frames <----> VLAN-B + PPPoE + TCP Frames
*   LAN GMAC0 <--------------------------------> GMAC1 WAN
*	192.168.4.1:50 --> 168.95.4.1:80 ---TXQ0---> 192.168.2.254:2001 --> 168.95.4.1:80
*	192.168.4.1:50 <-- 168.95.4.1:80 <--TXQ0---- 192.168.2.254:2001 <-- 168.95.4.1:80
*                                                                                 
*	192.168.4.2:50 --> 168.95.4.2:80 ---TXQ1---> 192.168.2.254:2002 --> 168.95.4.2:80
*	192.168.4.2:50 <-- 168.95.4.2:80 <--TXQ1---- 192.168.2.254:2002 <-- 168.95.4.2:80
*                                                                                 
*	192.168.4.3:50 --> 168.95.4.3:80 ---TXQ2---> 192.168.2.254:2003 --> 168.95.4.3:80
*	192.168.4.3:50 <-- 168.95.4.3:80 <--TXQ2---- 192.168.2.254:2003 <-- 168.95.4.3:80
*                                                                                 
*	192.168.4.4:50 --> 168.95.4.4:80 ---TXQ3---> 192.168.2.254:2004 --> 168.95.4.4:80
*	192.168.4.4:50 <-- 168.95.4.4:80 <--TXQ3---- 192.168.2.254:2004 <-- 168.95.4.4:80
*             
* 
*
*----------------------------------------------------------------------*/
#ifdef SL351x_NAT_TEST_BY_SMARTBITS
#define 	NAT_IPIV(a,b,c,d)			((a<<24)+(b<<16)+(c<<8)+d)
#define     NAT_TEST_CLIENT_IP 			NAT_IPIV(192,168,1,1)	
#define     NAT_TEST_SERVER_IP 			NAT_IPIV(168,95,1,1)
#define		NAT_TEST_LAN_IP				NAT_IPIV(192,168,1,254)
#define		NAT_TEST_WAN_IP				NAT_IPIV(192,168,2,254)
#define     NAT_TEST_MAP_PORT_BASE		2001
#define     NAT_TEST_SPORT				50
#define     NAT_TEST_DPORT				80
#define     NAT_TEST_PROTOCOL			6
u8			nat_test_lan_target_da[6]={0x00,0x11,0x22,0x33,0x44,0x55};
u8			nat_test_wan_target_da[6]={0x00,0xaa,0xbb,0xcc,0xdd,0xee};
u8			nat_test_lan_my_da[6]={0x00,0x11,0x11,0x11,0x11,0x11};
u8			nat_test_wan_my_da[6]={0x00,0x22,0x22,0x22,0x22,0x22};
static void nat_init_test_entry(void)
{
	int 				i, j ;
	NAT_HASH_ENTRY_T	*hash_entry;
	u32					sip, dip;
	u32					hash_data[HASH_MAX_DWORDS];
	NAT_CFG_T			*cfg;
	int					hash_index;
	
	cfg = (NAT_CFG_T *)&nat_cfg;
	hash_entry = (NAT_HASH_ENTRY_T *)&hash_data;
	hash_entry->key.Ethertype 	= 0;
	hash_entry->key.rule_id 	= 0;	
	hash_entry->key.ip_protocol = IPPROTO_TCP;
	hash_entry->key.reserved1 	= 0;
	hash_entry->key.reserved2 	= 0;
	// hash_entry->key.sip 		= NAT_TEST_CLIENT_IP;
	// hash_entry->key.dip 		= NAT_TEST_SERVER_IP;
	hash_entry->key.sport 		= htons(NAT_TEST_SPORT);
	hash_entry->key.dport 		= htons(NAT_TEST_DPORT);
	hash_entry->key.rule_id = cfg->tcp_udp_rule_id;
	hash_entry->action.dword = NAT_LAN2WAN_ACTIONS;
		
	sip = NAT_TEST_CLIENT_IP;
	dip = NAT_TEST_SERVER_IP;
	
	// Init TCP <------> TCP hash entries
	// LAN --> WAN
	// (1) TCP --> TCP
	// (2) TCP --> PPPoE + TCP
	// (3) TCP --> VLAN-B + PPPoE + TCP
	// (4) TCP + VLAN-A --> VLAN-B + PPPoE + TCP
	memcpy(hash_entry->param.da, nat_test_wan_target_da, 6);
	memcpy(hash_entry->param.sa, nat_test_wan_my_da, 6);
	hash_entry->key.port_id = cfg->lan_port;
	for (i=0; i<TOE_HW_TXQ_NUM; i++)
	{
		if (i < 2)
		{
			hash_entry->action.bits.dest_qid = i+2;
		}
		else
		{
			hash_entry->action.bits.dest_qid = i;
		}
		hash_entry->action.bits.dest_qid += (cfg->wan_port==0) ? TOE_GMAC0_HW_TXQ0_QID : TOE_GMAC1_HW_TXQ0_QID;
		hash_entry->param.Sport = NAT_TEST_MAP_PORT_BASE+i;
		hash_entry->param.Dport = NAT_TEST_DPORT;
		for (j=0; j<4; j++)
		{
			hash_entry->key.sip = sip + i + j*0x100;
			hash_entry->key.dip = dip + i + j*0x100;
			hash_entry->param.Dip = hash_entry->key.dip;
			hash_entry->param.Sip = NAT_TEST_WAN_IP;
			switch (j)
			{
			case 0:
				hash_entry->action.bits.pppoe = 0;
				hash_entry->param.pppoe = 0;
				hash_entry->action.bits.vlan = 0;
				hash_entry->param.vlan = 0;
				break;
			case 1:
				hash_entry->action.bits.pppoe = 1;
				hash_entry->param.pppoe = i+1;
				hash_entry->action.bits.vlan = 0;
				hash_entry->param.vlan = 0;
				break;
			case 2:
				hash_entry->action.bits.pppoe = 1;
				hash_entry->param.pppoe = i+1;
				hash_entry->action.bits.vlan = 1;
				hash_entry->param.vlan = i+10;
				break;
			case 3:
				hash_entry->action.bits.pppoe = 1;
				hash_entry->param.pppoe = i+1;
				hash_entry->action.bits.vlan = 1;
				hash_entry->param.vlan = i+10;
				break;
			}
			hash_entry->tmo.counter = hash_entry->tmo.interval = 0x7fff;
			hash_index = nat_build_keys(&hash_entry->key);
			nat_write_hash_entry(hash_index, hash_entry);
			hash_nat_enable_owner(hash_index);
			hash_validate_entry(hash_index); // Must last one, else HW Tx fast than SW 
		}
	}
	
		
	// WAN --> LAN
	hash_entry->key.port_id 	= cfg->wan_port;
	hash_entry->key.sport 		= htons(NAT_TEST_DPORT);
	hash_entry->key.dport 		= htons(NAT_TEST_DPORT);
	hash_entry->key.rule_id		= cfg->tcp_udp_rule_id;
	hash_entry->action.dword	= NAT_WAN2LAN_ACTIONS;
	hash_entry->key.sport		= htons(NAT_TEST_DPORT);
	memcpy(hash_entry->param.da, nat_test_lan_target_da, 6);
	memcpy(hash_entry->param.sa, nat_test_lan_my_da, 6);
	for (i=0; i<TOE_HW_TXQ_NUM; i++)
	{
		hash_entry->key.dport = htons(NAT_TEST_MAP_PORT_BASE + i);  
		if (i < 2)
		{
			hash_entry->action.bits.dest_qid = i+2;
		}
		else
		{
			hash_entry->action.bits.dest_qid = i;
		}
		hash_entry->action.bits.dest_qid += (cfg->lan_port==0) ? TOE_GMAC0_HW_TXQ0_QID : TOE_GMAC1_HW_TXQ0_QID;
		hash_entry->param.Dport = NAT_TEST_SPORT;
		hash_entry->param.Sport = NAT_TEST_DPORT;
		hash_entry->param.da[5] = i;
		for (j=0; j<4; j++)
		{
			hash_entry->key.sip = (dip + i + j*0x100);
			hash_entry->key.dip = (NAT_TEST_WAN_IP);
			hash_entry->param.Sip = hash_entry->key.sip;
			hash_entry->param.Dip = sip + i + j*0x100;
			switch (j)
			{
			case 0:
				hash_entry->action.bits.pppoe = 0;
				hash_entry->param.pppoe = 0;
				hash_entry->action.bits.vlan = 0;
				hash_entry->param.vlan = 0;
				break;
			case 1:
				hash_entry->action.bits.pppoe = 2;
				hash_entry->param.pppoe = i+1;
				hash_entry->action.bits.vlan = 0;
				hash_entry->param.vlan = 0;
				break;
			case 2:
				hash_entry->action.bits.pppoe = 2;
				hash_entry->param.pppoe = i+1;
				hash_entry->action.bits.vlan = 2;
				hash_entry->param.vlan = i+5;
				break;
			case 3:
				hash_entry->action.bits.pppoe = 1;
				hash_entry->param.pppoe = i+1;
				hash_entry->action.bits.vlan = 1;
				hash_entry->param.vlan = i+5;
				break;
			}
			hash_entry->tmo.counter = hash_entry->tmo.interval = 0x7fff;
			hash_index = nat_build_keys(&hash_entry->key);
			nat_write_hash_entry(hash_index, hash_entry);
			hash_nat_enable_owner(hash_index);
			hash_validate_entry(hash_index); // Must last one, else HW Tx fast than SW 
		}
	}
}
#endif	// SL351x_NAT_TEST_BY_SMARTBITS
#endif // CONFIG_SL351x_NAT
