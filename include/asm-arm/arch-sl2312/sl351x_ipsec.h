/***********************************************************************
* Name			: sl351x_ipsec.h
* Description	: 
*		Define for SL351x IPSEC functions, specifically for VPN application
*
* History
*
* 	Date	Writer		Description
*-----------------------------------------------------------------------
*		Feng Liu	Original Implementation
*		Wen Hsu		
***********************************************************************/

#ifndef _SL351x_IPSEC_H_
#define _SL351x_IPSEC_H_

#include <linux/interrupt.h>
#include <asm/arch/sl351x_gmac.h>

#define MAX_IPSEC_TUNNEL				200
#define MAX_SKB_SIZE					2048
	/* 1536 is a bit too small, sometimes causes problem */

/* cipher:
 *  ECB_DES(0), ECB_3DES(1), ECB_AES(2), 
 *  CBC_DES(4), CBC_3DES(5), CBC_AES(6)
 * auth:
 *  SHA1(0), MD5(1), 
 *  HMAC_SHA1(2), HMAC_MD5(3), FCS(4) */

/* make sure outbound_qid is 1 smaller than inbound_qid */
#define IPSEC_OUTBOUND_QID				0
#define IPSEC_INBOUND_QID				1
#define IPSEC_INBOUND_QID_2				2

#define MODE_ENCRYPTION					0
#define MODE_DECRYPTION					1
#define MODE_DECRYPTION_FAST_NET		2

#define WAN_RULE_ID						0
#define	IPSEC_WAN_PRIORITY				WAN_RULE_ID

#define	SYSCTL_VPN_ENABLE				0x01
#define	SYSCTL_VPN_PPPOE				0x02
#define SYSCTL_VPN_NFHOOK				0x04
#define	SYSCTL_VPN_DEBUG				0x10

#define IPSEC_CB_HW_PROCESSED			0x01
#define IPSEC_CB_SKIP_FASTNET			0x02

#define ERR_MATCH_RULE					-1

struct IPSEC_VPN_TUNNEL_CONFIG {
	unsigned int	tableID;		/* it's also SA ID */
	__u8		enable;				/* whether this VPN is enabled or disabled
									   it is used to turn on/off hash */

	/* connection info */
	__u32		src_LAN;
	__u32		src_netmask;		/* only allow netmask of 255.255.255.0 */
	__u32		src_LAN_GW;
	__u32		dst_LAN;
	__u32		dst_netmask;		/* only allow netmask of 255.255.255.0 */
	__u32		src_WAN_IP;
	__u32		dst_WAN_IP;
	/* Encryption / Authentication select */
	__u8		cipher_alg;
	__u8		auth_alg;
	__u8		protocol;			/* IPPROTO_ESP or IPPROTO_AH */
	__u8		mode;				/* Encryption (0) or Decryption (1) */

	__u8		auth_key[64];	/* authentication key */
	__u8		enc_key[32];	/* cipher key */
	__u8		enc_iv[16];		/* Initial vector used for DES,3DES,AES */
    
	__u32		auth_key_len;
	__u8		enc_key_len;
	__u8		enc_iv_len;
	__u32		spi;
	__u8		icv_full_len;
	__u8		icv_trunc_len;

    unsigned int current_sequence;
	struct pppox_sock *pppoe_sock;

	/* Hash */
	__u16		sa_hash_entry;	// can take it out
	__u8		sa_hash_flag;	// can take it out

	struct xfrm_state *xfrm;
};

struct IPSEC_VPN_IP_PAIR_CONFIG {
	__u8		enable;
	__u8		direction;		/* 0: out, 1: in */
	__u32		src_LAN;
	__u32		src_netmask;
	__u32		src_LAN_GW;
	__u32		dst_LAN;
	__u32		dst_netmask;
	__u32		src_WAN_IP;
	__u32		dst_WAN_IP;
};
#define IPSEC_CLASSIFICATION_QID(x)      (0x22 + x)

#endif
