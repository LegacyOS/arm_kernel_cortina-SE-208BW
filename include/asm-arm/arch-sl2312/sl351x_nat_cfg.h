/**************************************************************************
* Copyright 2006 StorLink Semiconductors, Inc.  All rights reserved.                
*--------------------------------------------------------------------------
*	sl351x_nat_cfg.h
*
*	Description:
*		- Define the Device Control Commands for NAT Configuration
*	
*	History:
*
*	4/28/2006	Gary Chen	Create
*   5/01/2007   CH HSU Modify
*-----------------------------------------------------------------------------*/
#ifndef _SL351x_NAT_CFG_H_
#define _SL351x_NAT_CFG_H_	1

/*----------------------------------------------------------------------
* Confiuration
*----------------------------------------------------------------------*/
#ifdef CONFIG_NETFILTER
#define CONFIG_SL351x_NAT			1
#undef 	CONFIG_SL351X_BR
#endif

#define CONFIG_NAT_MAX_IP_NUM		4	// per device (eth0 or eth1)
#define CONFIG_NAT_MAX_XPORT		64
#define CONFIG_NAT_MAX_WRULE		16	// per Queue
#define CONFIG_NAT_TXQ_NUM			4
#define CONFIG_NAT_MAX_PATH			8
#define HW_NAT_LAN					0
#define HW_NAT_WAN					1
#define CONFIG_GMAC_DEVICE_NUM		2
#define CONFIG_GMAC_VLAN_NUM		4
#define IFNAMSIZ					16
#define PORT_NUM					2
#define CONFIG_NAT_SWTXQ_NUM		6
/*----------------------------------------------------------------------
* Command set
*----------------------------------------------------------------------*/
#define SIOCDEVSL351x		(SIOCDEVPRIVATE + 15)	// 0x89FF
#define NATSNATSTATUS		0
#define NATGNATSTATUS		1
#define NATSETPORT			2
#define NATGETPORT			3
#define NATADDIP			4
#define NATDELIP			5
#define NATGETIP			6
#define NATAXPORT			7
#define NATDXPORT			8
#define NATGXPORT			9
#define NATSWEIGHT			10
#define NATGWEIGHT			11
#define NATAWRULE			12
#define NATDWRULE			13
#define NATGWRULE			14
#define NATSDEFQ			15
#define NATGDEFQ			16
#define NATRMIPCFG			17		// remove IP config
#define NATTESTENTRY		18
#define NATSETMEM			19
#define NATSHOWMEM			20
#define	GMIIREG				21
#define SMIIREG				22
#define SWITCHSHOWMIB		23
#define	DUMPRX				24
#define	DUMPTX				25
#define	REGREAD				26
#define	REGWRITE			27
#define NAT_DEL_ENTRY		28
#define WAIT_BLOCKED_URL	29
#define SWITCHRESETMIB		30
#define NATSDEVSTATUS		31
#define NATGDEVSTATUS		32
#define NATISGMAC			33
#define NATADDPATH			34
#define NATDELPATH			35
#define NATGETPATH			36
#define NATIGMP				37
#define NATDELIGMP			38
#define NATSWWEIGHT			39
#define NATGSWEIGHT			40
#define NATADDVLAN			41
#define NATDELVLAN			42
#define NATGETVLAN			43
#define NATGETVLANID		44

/*----------------------------------------------------------------------
* Command Structure
*----------------------------------------------------------------------*/
// Common Header
typedef struct {
	unsigned short		cmd;	// command ID
	unsigned short		len;	// data length, excluding this header
} NATCMD_HDR_T;

// NATSSTATUS & NATGSTATUS commands
typedef struct {
	unsigned char		enable;
	unsigned int		vlan_id;
} NAT_STATUS_T;	

// NATSETPORT & NATGETPORT commands
typedef struct {
	unsigned char		portmap;
	unsigned int		vlan_id;
} NAT_PORTCFG_T;

typedef struct {
	unsigned int		ipaddr;
	unsigned int		netmask;
	unsigned int		vlan_id;
} NAT_IP_ENTRY_T;

typedef struct {
	int	key_da[6];
	int	key_sa[6];
	u_int32_t key_sip;
	u_int32_t key_dip;
	u_int16_t key_sport;
	u_int16_t key_dport;
	int	para_da[6];
	int	para_sa[6];
	u_int32_t para_sip;
	u_int32_t para_dip;
	u_int16_t para_sport;
	u_int16_t para_dport;
	u_int32_t timeout;
} NAT_IGMP_ENTRY_T;

// NATADDIP & NATDELIP commands
typedef struct {
	NAT_IP_ENTRY_T	entry;
} NAT_IPCFG_T;

// NATGETIP command
typedef struct {
	unsigned int	total;
	NAT_IP_ENTRY_T	entry[CONFIG_NAT_MAX_IP_NUM];
} NAT_IPCFG_ALL_T;

typedef struct {
	unsigned int		protocol;
	unsigned short		sport_start;
	unsigned short		sport_end;
	unsigned short		dport_start;
	unsigned short		dport_end;
} NAT_XPORT_ENTRY_T;

// NATAXPORT & NATDXPORT Commands
typedef struct {
	NAT_XPORT_ENTRY_T	entry;
} NAT_XPORT_T;

// NATGXPORT Command
typedef struct {
	unsigned int		total;
	NAT_XPORT_ENTRY_T	entry[CONFIG_NAT_MAX_XPORT];
} NAT_XPORT_ALL_T;

// NATSWEIGHT & NATGWEIGHT Commands
typedef struct {
	unsigned char		weight[CONFIG_NAT_TXQ_NUM];
} NAT_WEIGHT_T;

// NATSWWEIGHT & NATGSWEIGHT 
typedef struct {
	unsigned char		weight[CONFIG_NAT_SWTXQ_NUM];
} NAT_SWWEIGHT_T;

typedef struct {
	unsigned int		protocol;
	unsigned int		sip_start;
	unsigned int		sip_end;
	unsigned int		dip_start;
	unsigned int		dip_end;
	unsigned short		sport_start;
	unsigned short		sport_end;
	unsigned short		dport_start;
	unsigned short		dport_end;
} NAT_WRULE_ENTRY_T;	

// NATAWRULE & NATDWRULE Commands
typedef struct {
	unsigned int		qid;
	NAT_WRULE_ENTRY_T	entry;
} NAT_WRULE_T;

// NATGWRULE Command
typedef struct {
	unsigned int		total;
	NAT_WRULE_ENTRY_T	entry[CONFIG_NAT_MAX_WRULE];
} NAT_WRULE_ALL_T;

// NATSDEFQ & NATGDEFQ commands
typedef struct {
	unsigned int		qid;
} NAT_QUEUE_T;	

// NATTESTENTRY 
typedef struct {
	u_int16_t		cmd;	// command ID
	u_int16_t		len;	// data length, excluding this header
	u_int8_t		init_enable;
} NAT_TESTENTRY_T;	

//GMIIREG
typedef	struct{
	unsigned short		phy_addr;
	unsigned short		phy_reg;
	unsigned short		phy_len;
} NAT_GMIIREG_T;

//SMIIREG
typedef	struct{
	unsigned short		phy_addr;
	unsigned short		phy_reg;
	unsigned int		phy_data;
} NAT_SMIIREG_T;
	
//DUMPRX
typedef struct {
	unsigned char		enable;
} NAT_DUMP_RX;	

//DUMPTX
typedef struct {
	unsigned char		enable;
} NAT_DUMP_TX;
	
//REGREAD
typedef struct {
	unsigned int		location;
	unsigned int		length;
	unsigned int		size;
} NAT_REGREAD;

//REGWRITE
typedef struct {
	unsigned int		location;
	unsigned int		data;
	unsigned int		size;
} NAT_REGWRITE;

//SWITCHRESETMIB
typedef struct {
	unsigned char		enable;
} NAT_SWITCHRESETMIB;	

//SWITCHSHOWMIB
typedef struct {
	unsigned char		enable;
} NAT_SWITCHSHOWMIB;	

// NATADDIP & NATDELIP commands
typedef struct {
	struct net_device	*out_dev;
	char				name[IFNAMSIZ];
	unsigned int		out_vlan_id;
	unsigned int		vlan_id;
} NAT_PATH_ENTRY_T;

// NATGETIP command
typedef struct {
	unsigned int		total;
	NAT_PATH_ENTRY_T	entry[CONFIG_NAT_MAX_PATH];
} NAT_PATH_T;

// NATIGMP
typedef struct {
	u_int8_t mac_addr[PORT_NUM][6];
	u_int8_t 		port;
	u_int32_t		vlan_id;
	u_int32_t		protocol;
	NAT_IGMP_ENTRY_T entry;
} NAT_NATIGMP_T;

typedef struct {
	unsigned int		hwNAT_enabled;
	unsigned int		vlan_id;
	unsigned int		lan_wan_status;
} NAT_GMACDEV_VLAN_T;

// NATGETVLAN command
typedef struct {
	unsigned int		total;
	NAT_GMACDEV_VLAN_T	entry[CONFIG_GMAC_VLAN_NUM];
} NAT_VLANCFG_ALL_T;

typedef union
{
	NAT_STATUS_T		status;
	NAT_STATUS_T		dev_status;
	NAT_PORTCFG_T		portcfg;
	NAT_IPCFG_T			ipcfg;
	NAT_GMACDEV_VLAN_T	vlancfg;
	NAT_VLANCFG_ALL_T	vlanallcfg;
	NAT_PATH_ENTRY_T	natpath;
	NAT_XPORT_T			xport;
	NAT_WEIGHT_T		weight;
	NAT_SWWEIGHT_T  	swweight;
	NAT_WRULE_T			wrule;
	NAT_QUEUE_T			queue;
	NAT_TESTENTRY_T 	init_entry;
	NAT_GMIIREG_T		get_mii_reg;
	NAT_SMIIREG_T		set_mii_reg;
	NAT_DUMP_RX			dump_rx_packet;
	NAT_DUMP_TX			dump_tx_packet;
	NAT_REGREAD			reg_read;
	NAT_REGWRITE		reg_write;
	NAT_SWITCHRESETMIB	reset_switch;
	NAT_SWITCHSHOWMIB	show_switch;
	NAT_NATIGMP_T		add_igmp_hash;
	NAT_NATIGMP_T		del_igmp_hash;
} NAT_REQ_E;

typedef struct {
	unsigned int		hwNAT_enabled;
	struct net_device	*dev;
	unsigned int		lan_wan_status;
	NAT_IPCFG_ALL_T		ipcfg;
	NAT_PATH_T			hw_nat_path;
	unsigned int		number_vlan;
	NAT_GMACDEV_VLAN_T	vlanDev[CONFIG_GMAC_VLAN_NUM];
} NAT_GMACDEV_T;
	
/*----------------------------------------------------------------------
* NAT Configuration
*	- Used by driver only
*----------------------------------------------------------------------*/
typedef struct {
	unsigned int		enabled;
	unsigned int		init_enabled;
	unsigned int		tcp_udp_rule_id;
	unsigned int		gre_rule_id;
	unsigned int		lan_port;
	unsigned int		wan_port;
	unsigned int		default_hw_txq;
	short				tcp_tmo_interval;
	short				udp_tmo_interval;
	short				gre_tmo_interval;
	NAT_GMACDEV_T		gmacDev[CONFIG_GMAC_DEVICE_NUM];
	NAT_XPORT_ALL_T		xport;
	NAT_WEIGHT_T		weight;
	NAT_WRULE_ALL_T		wrule[CONFIG_NAT_TXQ_NUM];
} NAT_CFG_T;

/*----------------------------------------------------------------------
* NAT Control Block
*	- Used by driver only
*	- Stores LAN-IN or WAN-IN information
*	- WAN-OUT and LAN-OUT driver use them to build up a hash entry
*	- NOTES: To update this data structure, MUST take care of alignment issue
*   -		 MUST make sure that the size of skbuff structure must 
*            be larger than (40 + sizof(NAT_CB_T))
*----------------------------------------------------------------------*/
typedef struct {
	unsigned short		tag;
	unsigned char		sa[6];
	unsigned int		sip;
	unsigned int		dip;
	unsigned short		sport;
	unsigned short		dport;
	unsigned char		pppoe_frame;
	unsigned char		state;			// same to enum tcp_conntrack
	unsigned char		reserved[2];
	unsigned int		input_dev;
	unsigned short		vpn_tag;		/* for IPsec VPN acceleration */
	unsigned int		vpn_spi;		/* for IPsec VPN acceleration */
	unsigned char		in_proto;		/* for IPsec VPN acceleration */
} NAT_CB_T;

#define NAT_CB_TAG		0x4C53	// "SL"
#define NAT_CB_VPN_TAG	0x5343	/* "CS" */
#define NAT_CB_VPN2_TAG	0x5344	/* "CT" */
#define NAT_CB_SIZE		sizeof(NAT_CB_T)
// #define NAT_SKB_CB(skb)	(NAT_CB_T *)(((unsigned int)&((skb)->cb[40]) + 3) & ~3)  // for align 4
#define NAT_SKB_CB(skb)	(NAT_CB_T *)&((skb)->cb[40])  // for align 4
#define HIPQUAD3(addr) 	((unsigned char *)&addr)[3]
#define HIPQUAD2(addr) 	((unsigned char *)&addr)[2]
#define HIPQUAD1(addr) 	((unsigned char *)&addr)[1]
#define HIPQUAD0(addr) 	((unsigned char *)&addr)[0]
#endif // _SL351x_NAT_CFG_H_
