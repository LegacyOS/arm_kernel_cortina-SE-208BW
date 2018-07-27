#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "../../net/bridge/br_private.h"
#include <linux/tcp.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#ifdef	CONFIG_NETFILTER
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_protocol.h>

#include <linux/netfilter_ipv4/ip_conntrack_helper.h>
#include <linux/netfilter_ipv4/ip_conntrack_core.h>
#include <net/ip.h>
#include <linux/netfilter_ipv4/ip_nat.h>
#include <linux/netfilter_ipv4/ip_nat_core.h>
#endif
#include <asm/arch/sl351x_gmac.h>
#include <linux/sysctl_storlink.h>
#include <asm/arch/sl351x_nat_cfg.h>

#ifdef CONFIG_VLAN_8021Q
#include <linux/if_vlan.h>
#include "/source/kernel/linux/net/8021q/vlan.h"
#define KERNEL_1QVLAN
extern int vlan_dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev);
#endif

extern int sl_ip_route_cache(struct sk_buff *skb, u32 daddr, u32 saddr,
		u8 tos, struct net_device *dev, int iif, int oif);
extern int manip_pkt(u_int16_t proto, struct sk_buff **pskb,
		unsigned int iphdroff, const struct ip_conntrack_tuple *target,
		enum ip_nat_manip_type maniptype);


#include <net/flow.h>
#include <net/xfrm.h>
extern void xfrm_policy_lookup(struct flowi *fl, u16 family, u8 dir,
                               void **objp, atomic_t **obj_refp);
extern struct xfrm_policy_afinfo *xfrm_policy_get_afinfo(unsigned short family);
extern void xfrm_policy_put_afinfo(struct xfrm_policy_afinfo *afinfo);

#ifdef CONFIG_SL351X_IPSEC
extern int sl_fast_ipsec(struct sk_buff *skb);
extern int ipsec_handle_skb_finish(void);
#endif
/*
// in route.c
int sl_ip_route_cache(struct sk_buff *skb, u32 daddr, u32 saddr,
		   u8 tos, struct net_device *dev, int iif, int oif);
*/
/*
//in ip_nat_core.c
int
manip_pkt(u_int16_t proto,
	  struct sk_buff **pskb,
	  unsigned int iphdroff,
	  const struct ip_conntrack_tuple *target,
	  enum ip_nat_manip_type maniptype);
*/

/* storlink_ctl.fast_net bits
	bit 1  enable / disable 2^0=1
	bit 2  transmit through device tx queue / through Linux TC 2^1=2
	bit 5  GMAC and other PCI devices are combined into a bridge device / Not 2^4=16
	bit 7  fast_ipsec_vpn enable / disable 2^6=64
*/

int sl_fast_bridging(struct sk_buff *skb, int in_device_gmac_index);
int sl_fast_nat_route(struct sk_buff *skb, int in_device_gmac_index);
int find_pppoe = 0;

int sl_fast_net(struct sk_buff *skb) {
	int in_device_gmac_index = -1;
#if defined(CONFIG_SL351x_NAT) ||defined(CONFIG_SL351X_BR)
	TOE_INFO_T	*toe;
	struct ethhdr *eth;
	struct pppoe_hdr	*pppoe_hdr;
	u16	 ppp_proto;
	NAT_CB_T			*nat_cb;

	toe = (TOE_INFO_T *)&toe_private_data;
	eth = (struct ethhdr*)(skb->mac.raw);
	pppoe_hdr = (struct pppoe_hdr *)(eth + 1);
	ppp_proto = *(u16 *)&pppoe_hdr->tag[0];
	nat_cb = NAT_SKB_CB(skb);

	if(toe->gmac[0].dev == skb->dev) {
		in_device_gmac_index = 0;
	}
	else if(toe->gmac[1].dev == skb->dev) {
		in_device_gmac_index = 1;
	}
#endif

	if (in_irq())
		return 0;
	
	/* Skip multicast packet */	
	if (skb->data[0] == 0x01 && skb->data[2] == 0x5e)
		return 0;	

	if(unlikely(!(storlink_ctl.fast_net & 1))) {
		return 0;
	}

	if(sl_fast_bridging(skb, in_device_gmac_index)) {
		return 1;
	}

#ifdef CONFIG_RTL8366SR_PHY
	if (likely(eth->h_proto == __constant_htons(ETH_P_PPP_SES)		// 0x8864
			&& ppp_proto == __constant_htons(PPP_IP))) 				// 0x21
		{
			find_pppoe = 1;
			return 0;
		}
	if (likely((find_pppoe == 1) && (nat_cb->tag != NAT_CB_TAG)))
		return 0;
#endif

#ifdef	CONFIG_NETFILTER
	if(sl_fast_nat_route(skb, in_device_gmac_index)) {
		return 1;
	}
#endif
#ifdef	CONFIG_SL351X_IPSEC
	if((storlink_ctl.fast_net & 64) && ((__u8)(skb->cb[28]) != 0x2) && (sl_fast_ipsec(skb))) {
		ipsec_handle_skb_finish();
		return 1;
	}
#endif
	return 0;
}
EXPORT_SYMBOL(sl_fast_net);

/**
 * Fast bridging. Michael Wu
 **/

int sl_fast_bridging(struct sk_buff *skb, int in_device_gmac_index) {
	struct net_bridge_fdb_entry *br_fdb, *br_fdb_sa;
	struct net_bridge_port *br_port;
	struct net_device *dst_nic;
	unsigned char	*sa, *da;
#ifdef KERNEL_1QVLAN
	struct ethhdr *eth;
	struct net_device *vlan_dev = NULL,*orig_dev = skb->dev;
	int from_vlan=0;
	struct vlan_hdr *vhdr = NULL;
	unsigned short vlan_TCI, vid;
	struct net_device_stats *stats;

	eth = (struct ethhdr*)(skb->mac.raw);
	if( likely(eth->h_proto == __constant_htons(ETH_P_8021Q)))
		from_vlan = 1;

	/* for packet with vlan tag, find the real vlan device */
	if (from_vlan == 1) {		/* VLAN tag */
		vhdr = (struct vlan_hdr *)(skb->data);
		vlan_TCI = ntohs(vhdr->h_vlan_TCI);
		vid = (vlan_TCI & VLAN_VID_MASK);
		skb->dev = vlan_dev = __find_vlan_dev(orig_dev, vid);
		if (skb->dev == NULL)	/* Something wrong, skip fast path */
			goto no_bridge;
         }
#endif

	da = (unsigned char*)(skb->mac.raw);
	sa = da + ETH_ALEN;

	if( (br_port = rcu_dereference(skb->dev->br_port)) == NULL) {
		goto no_bridge;
	}

	if (unlikely((br_fdb = br_fdb_get(br_port->br, da)) == NULL))
		goto no_hash_1;

	if (unlikely((br_fdb_sa = br_fdb_get(br_port->br, sa)) == NULL))
		goto no_hash_2;

	if( unlikely(br_fdb->is_local))
		goto not_local;

	dst_nic = br_fdb->dst->dev;

#if defined(CONFIG_SL351X_BR)
	// If the skb origin from gmac and destinate to gmac then we need to skip handling this packet.
	if(unlikely(in_device_gmac_index!=-1) && toe->gmac[1-in_device_gmac_index].dev == dst_nic) {
		return 0;
	}
#endif

	br_fdb_sa->ageing_timer = jiffies;
	skb->dev = dst_nic;
	skb->data = skb->data - ETH_HLEN;
	skb->len += ETH_HLEN;

#ifdef KERNEL_1QVLAN
         if(from_vlan==1){
		memmove( skb->data + VLAN_HLEN, skb->data , 2 * ETH_ALEN);
		skb->data = skb->data + VLAN_HLEN;
		skb->len -= VLAN_HLEN;

		vlan_dev->last_rx = jiffies;
		stats = vlan_dev_get_stats(vlan_dev);
		stats->rx_packets++;
		stats->rx_bytes += skb->len;
	}
#endif

	if(likely(storlink_ctl.fast_net & 2)) {
		// transmit packet directly to device tx queue
		if(unlikely(dst_nic->hard_start_xmit(skb, dst_nic))) {
			dev_kfree_skb(skb);
			printk("%s::fast bridging %s->hard_start_xmit failed\n",  __func__, dst_nic->name);
		};
	}
	else {
		if(unlikely(dev_queue_xmit(skb))) {
			printk("%s %s fast bridging dev_queue_xmit failed\n", __func__, dst_nic->name);
		}
	}

	return 1;

not_local:
	br_fdb_put(br_fdb_sa);
no_hash_2:
	br_fdb_put(br_fdb);
no_hash_1:
no_bridge:
#ifdef KERNEL_1QVLAN
	if(from_vlan==1)
		skb->dev = orig_dev;
#endif
	return 0;
}

#ifdef	CONFIG_NETFILTER
int rnd = 0;

/*
 * to check the input skb is not a IPsec VPN packet
 * return 1 if it is, return 0 if it's not
 */
static inline int sl_fast_net_check_xfrm(struct sk_buff *skb)
{
	struct xfrm_policy_afinfo * afinfo = xfrm_policy_get_afinfo(AF_INET);
	struct flowi fl;
	struct xfrm_policy *policy = NULL;
	struct dst_entry *dst_orig = skb->dst;
	u32 genid;

	if (afinfo != NULL) {
		afinfo->decode_session(skb, &fl);
		xfrm_policy_put_afinfo(afinfo);
	}

	genid = atomic_read(&flow_cache_genid);

	if ((dst_orig->flags & DST_NOXFRM) || !xfrm_policy_list[XFRM_POLICY_OUT])
		return 0;

	policy = flow_cache_lookup(&fl, AF_INET, FLOW_DIR_OUT, xfrm_policy_lookup);

	if (policy == NULL) return 0;

	if (policy->action == XFRM_POLICY_ALLOW) {
		//printk("%s::this is vpn packet\n", __func__);
		return 1;
	}

#if 0 // old code
	xfrm_policy_lookup(&fl, AF_INET, FLOW_DIR_FWD, &obj, &obj_ref);
	if (obj != NULL) {
		printk("%s::found matching policy 1\n", __func__);
		goto skip_fast_nat;
	}
	xfrm_policy_lookup(&fl, AF_INET, FLOW_DIR_IN, &obj, &obj_ref);
	if (obj != NULL) {
		printk("%s::found matching policy 2\n", __func__);
		goto skip_fast_nat;
	}
	
	if (pol) {
		printk("%s::found xfrm policy\n", __func__);
		if (pol->action == XFRM_POLICY_ALLOW) {
			printk("%s::got here, xfrm found and it's allowed\n", __func__);
			goto skip_fast_nat;
		}
	}
#endif
	return 0;
}

/*
 * Fast NAT and Routing. Michael Wu
 */
int sl_fast_nat_route(struct sk_buff *skb, int in_device_gmac_index) {
	struct ethhdr *eth, ehdr;
	struct iphdr *iph;
	u32	sip, dip;
	u16	sport, dport;
	int i;
	/* to store the original net device that skb->dev points to */
	struct net_device *orig_dev = skb->dev;
	/* to store the "input" net device that skb is originally from */
	struct net_device *input_dev = skb->dev;
#ifdef CONFIG_SL351x_NAT
	struct net_device *output_dev;
#endif
#ifdef KERNEL_1QVLAN
	struct vlan_hdr *vhdr = NULL;
	unsigned short vlan_TCI = 0, vid = 0;
	struct net_device_stats *stats;
	int from_vlan=0, to_vlan=0;
#endif

	/*I've seen packets with nr_frags!=0 from RT2860. It shouldn't happen...*/
	if(skb_shinfo(skb)->nr_frags) {
		printk("%s::frags %d\n", __func__, skb_shinfo(skb)->nr_frags);
		return 0;
	}
	eth = (struct ethhdr*)(skb->mac.raw);

#ifdef KERNEL_1QVLAN
	if( likely(eth->h_proto == __constant_htons(ETH_P_8021Q))) {	/* VLAN tag */
		vhdr = (struct vlan_hdr *)(skb->data);
		vlan_TCI = ntohs(vhdr->h_vlan_TCI);
		vid = (vlan_TCI & VLAN_VID_MASK);
		iph = (struct iphdr*)&(skb->data[VLAN_HLEN]);
		from_vlan = 1;
		//printk("[orig] skb len:%x\n",skb->len);
		//printk("[orig] ip len:%x\n",iph->tot_len);
	}
	else
#endif
	iph = (struct iphdr*)&(skb->data[0]);

	for (i=0; i<ETH_ALEN; i++) {
		ehdr.h_dest[i]=eth->h_dest[i];
		ehdr.h_source[i]=eth->h_source[i];
	}

	if (skb->input_dev != NULL)
		input_dev = skb->input_dev;
	else
		input_dev = orig_dev;

#ifndef KERNEL_1QVLAN
	if( likely(eth->h_proto == __constant_htons(ETH_P_IP)) &&
			likely(! (iph->frag_off & __constant_htons(IP_OFFSET))) &&
			likely(iph->ihl == 5) ) {
#else
	if( (((from_vlan==1) &&
				likely(vhdr->h_vlan_encapsulated_proto == __constant_htons(ETH_P_IP))) ||
		 	likely(eth->h_proto == __constant_htons(ETH_P_IP))) &&
			likely(! (iph->frag_off & __constant_htons(IP_OFFSET))) &&
			likely(iph->ihl == 5) ) {
#endif
		struct ip_conntrack_tuple tuple;
		struct ip_conntrack_protocol *protocol;
		struct ip_conntrack_tuple_hash *h;
		struct ip_conntrack *ct;
		struct ip_conntrack_tuple target;
		int ips_src_nat_manip;  // What to do for IPS_SRC_NAT? Depends on CT_DIR direction
		int ips_dst_nat_manip;  // What to do for IPS_DST_NAT?
		int nat_change_dst = 0;	// will NAT change the destination IP?
		struct net_bridge_port *br_port=NULL;
		struct hh_cache *hh = NULL;
		int hh_alen = 0;
		struct net_bridge_fdb_entry *br_fdb=NULL;
		struct net_bridge *br=NULL;

		// only handle ETH_P_IP frames that are not Fragmented
		// and without IP options (iph->ihl == 5)
		sip = iph->saddr;
		dip = iph->daddr;

		skb->nh.iph = iph;
		if (unlikely(skb->len < ntohs(iph->tot_len))) {
			printk("ERROR %s %s:: skb->len(%d) < iph->tot_len %d\n",
				skb->dev->name, __func__, skb->len, ntohs(iph->tot_len));
		}

		if( unlikely(iph->ihl*4 > ntohs(iph->tot_len) ) ) {

			printk("ERROR %s %s:: iph->ihl*4 (%d) > ntohs(iph->tot_len) (%d) \n",
				skb->dev->name, __func__, iph->ihl*4, ntohs(iph->tot_len) );
			return 0;
		}
		protocol = __ip_conntrack_proto_find(iph->protocol);

#ifdef KERNEL_1QVLAN
		if(from_vlan ==1) {
			/* take off the VLAN header (4 bytes currently) */
			skb_pull(skb, VLAN_HLEN);
		}
#endif
		// The following code references ip_conntrack_core.c ip_ct_get_tuple
		// set up tuple
		tuple.src.ip = iph->saddr;
		tuple.dst.ip = iph->daddr;
		tuple.dst.protonum = iph->protocol;
		tuple.dst.dir = IP_CT_DIR_ORIGINAL;

		if( unlikely(!protocol->pkt_to_tuple(skb, iph->ihl*4, &tuple)) ) {
			printk("%s:: protocol->pkt_to_tuple failed protocol = %d\n", __func__, iph->protocol);
			goto skip_fast_nat;
		}

		// The following code references ip_conntrack_core.c resolve_normal_ct

		// ct->ct_general.use is incremented in ip_conntrack_find_get()
		// We need to remember to release it.
		// see resolve_normal_ct in ip_conntrck_core and nf_conntrack_put in skbuff.h for detail.

		if( unlikely(!(h = ip_conntrack_find_get(&tuple, NULL))) ) {
			//printk("%s::cannot find ip_conntrack!\n", __func__);
			goto skip_fast_nat;
		}

		// From this point on, we need to decrement ct_general.use before leaving
		ct = tuplehash_to_ctrack(h);

//		printk("ct->ct_general.use = %d\n", ct->ct_general.use);

		if(ct->helper) {
			/* We do not handle connections that have a helper method. For example, FTP control session. */
/*
			printk("ct->helper!=NULL\n");
			printk("src=%u.%u.%u.%u dst=%u.%u.%u.%u \n",
					NIPQUAD(tuple.src.ip), NIPQUAD(tuple.dst.ip));

			printk("sport=%hu dport=%hu \n",
					ntohs(tuple.src.u.tcp.port),
					ntohs(tuple.dst.u.tcp.port));
*/
			goto release_ct;
		}

		// In below, we filter out special cases that we don't want to do fast-NAT. Let Linux handle these cases.

		if(iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcp_hdr;
#ifdef CONFIG_SL351x_NAT
			NAT_CB_T *nat_cb = NAT_SKB_CB(skb);
#endif

			tcp_hdr = (struct tcphdr *)((u32)iph + (iph->ihl*4));

			// skip fast nat if TCP not in TCP_CONNTRACK_ESTABLISHED state
			// we let Kernel handle other special cases
			if( unlikely(ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED) ) {
				goto release_ct;
			}

			// ugly, workaround for URL filter , Jason
			if( unlikely((tcp_flag_word(tcp_hdr) & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST))==TCP_FLAG_ACK && (ntohs(tcp_hdr->dest)==80))) {
//				printk("TCP flag:%d from GMAC%d\n",tcp_flag_word(tcp_hdr),in_device_gmac_index);
				goto release_ct;
			}

			if( unlikely(tcp_flag_word(tcp_hdr) & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)) ) {
				goto release_ct;
			}
			sport = tcp_hdr->source;
			dport = tcp_hdr->dest;
#ifdef CONFIG_SL351x_NAT
			nat_cb->state = TCP_CONNTRACK_ESTABLISHED;
#endif
		}

		/* Fast-NAT seems to be able to handle ICMP packets, but
		they are handled specially in Kernel,
		so we don't want to do fast NAT on ICMP packets.
		see ip_nat_standalone.c/ip_nat_fn for detail
		*/
		else if(unlikely(iph->protocol == IPPROTO_ICMP)) {
			goto release_ct;
		}

		// Do the real NAT work. If no NAT is needed, then it is equivalent to fast routing.

		// Below is condensed version of ip_nat_packet in ip_nat_core.c
		// Instead of mimicking of calling it from PRE ROUTING and POST ROUTING twice
		// and let ip_nat_packet to filter out the unneeded call, instead we derived the needed NAT action directly

		/* We are aiming to look like inverse of other direction. */
		invert_tuplepr(&target, &ct->tuplehash[!DIRECTION(h)].tuple);

		/* Lookup routing cache.
		  * On successful return, reference to skb->dst will be incremented.
		  * Kernel will release skb->dst when freeing skb, but if we failed to transmit the packet,
		  * we need to release skb->dst our self.
		  */

		/*
		  * if ((ct->status & IPS_SRC_NAT) && DIRECTION(h) == IP_CT_DIR_REPLY) ||
		  *     ((ct->status & IPS_DST_NAT) && DIRECTION(h) == IP_CT_DIR_ORIGINAL)
		  * then NAT will change destination IP
		  */
		if(DIRECTION(h) == IP_CT_DIR_ORIGINAL) {
			if(ct->status & IPS_DST_NAT) {
				nat_change_dst = 1;
			}
			ips_src_nat_manip = IP_NAT_MANIP_SRC;
			ips_dst_nat_manip = IP_NAT_MANIP_DST;
		} else { //(DIRECTION(h) == IP_CT_DIR_REPLY)
			if(ct->status & IPS_SRC_NAT) {
				nat_change_dst = 1;
			}
			ips_src_nat_manip = IP_NAT_MANIP_DST;
			ips_dst_nat_manip = IP_NAT_MANIP_SRC;
		}

#ifdef KERNEL_1QVLAN
		/* for packet with vlan tag, find the real vlan device */
		if (from_vlan == 1) {		/* VLAN tag */
			skb->dev = __find_vlan_dev(orig_dev, vid);
			if (skb->dev == NULL)
				goto release_ct;
			skb->dev->last_rx = jiffies;
			stats = vlan_dev_get_stats(skb->dev);
			stats->rx_packets++;
			stats->rx_bytes += skb->len;
		}
#endif

		/* for packets origing from a device that's part of a bridge,
		 * we need to change skb->dev to the bridge device */
		if( likely(storlink_ctl.fast_net & 16) && (br_port = rcu_dereference(skb->dev->br_port)) != NULL ) {
			skb->dev = br_port->br->dev;
		}

		if( unlikely(!sl_ip_route_cache(skb,
							nat_change_dst ? target.dst.ip : skb->nh.iph->daddr,
							skb->nh.iph->saddr,
							skb->nh.iph->tos, skb->dev, skb->dev->ifindex, 0)) ) {
			goto release_ct;
		}

		/* 
		 * to check if the packet is VPN packet,
		 * if it is, don't handle this packet in sl_fast_nat_route
		 */
		if (sl_fast_net_check_xfrm(skb) != 0) goto release_ct;

		if(ct->status & IPS_SRC_NAT) {
			if( unlikely (!manip_pkt(target.dst.protonum, &skb, 0, &target, ips_src_nat_manip)) ) {

				dst_release(skb->dst);	// release the dst previously acquired by sl_ip_route_cache
				goto release_ct;
			}
		}

		if(ct->status & IPS_DST_NAT) {
			if( unlikely (!manip_pkt(target.dst.protonum, &skb, 0, &target, ips_dst_nat_manip)) ) {

				dst_release(skb->dst);	// release the dst previously acquired by sl_ip_route_cache
				goto release_ct;
			}
		}

		/* Original code
		// #define DIRECTION(h) ((enum ip_conntrack_dir)(h)->tuple.dst.dir)
		if (DIRECTION(h) == IP_CT_DIR_ORIGINAL) {
			if(sl_nat_packet (ct, IP_CT_DIR_ORIGINAL, IP_NAT_MANIP_SRC, skb)) {
				goto transmit_packet;
			}
			else if(sl_nat_packet (ct, IP_CT_DIR_ORIGINAL, IP_NAT_MANIP_DST, skb)) {
				goto transmit_packet;
			}
			else {
				goto release_ct;
			}
		}
		else if(DIRECTION(h) == IP_CT_DIR_REPLY) {
			if(sl_nat_packet (ct, IP_CT_DIR_REPLY, IP_NAT_MANIP_DST, skb)) {
				goto transmit_packet;
			}
			else if(sl_nat_packet (ct, IP_CT_DIR_REPLY, IP_NAT_MANIP_SRC, skb)) {
				goto transmit_packet;
			}
			else
			{
				goto release_ct;
			}
		}
		*/

		//transmit_packet:;
		nf_conntrack_put(&ct->ct_general);

		hh = skb->dst->hh;

		// The following code references ip_finish_output2 in ip_output.c
#ifdef KERNEL_1QVLAN
		if (hh) {
#endif
			read_lock_bh(&hh->hh_lock);
			hh_alen = HH_DATA_ALIGN(hh->hh_len);
#ifdef KERNEL_1QVLAN
		}
#endif
		// Originally should be:
		// memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
		//skb_push(skb, hh->hh_len);
#ifdef KERNEL_1QVLAN
		if (skb->dst->dev->hard_start_xmit == vlan_dev_hard_start_xmit)
			to_vlan = 1;

		if (to_vlan==1) {
			/* DA */
			memcpy(skb->data - ETH_HLEN, skb->dst->neighbour->ha,
					skb->dst->dev->addr_len);
			/* SA */
			memcpy(skb->data - ETH_HLEN + skb->dst->dev->addr_len,
					skb->dst->dev->dev_addr , skb->dst->dev->addr_len);
		} else
#endif
		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
#ifdef KERNEL_1QVLAN
		if(hh)
#endif
		read_unlock_bh(&hh->hh_lock);

	/*
			if(unlikely(printk_ratelimit())) {
				printk("%s:: header cache hit!\n", __func__);
			}
	*/

		skb->dev = skb->dst->dev;
/*
			if((rnd++) == 100) {
				rnd = 0;
				printk("freeing skb. skb.skb_shinfo->nr_frags=%d\n", skb_shinfo(skb)->nr_frags);
				dev_kfree_skb(skb);
				printk("end freeing skb\n");
			}
*/

#ifdef CONFIG_SL351x_NAT
		output_dev = skb->dev;
#endif
		/* 
		 * check to see if destination device is a bridge device. send packet
		 * directly to the real device.
		 */
		if (likely(storlink_ctl.fast_net & 16) && skb->dev->hard_start_xmit == br_dev_xmit ) {
			unsigned char* da = (unsigned char*)(skb->data - ETH_HLEN);
			br = netdev_priv(skb->dev);
			if ((br_fdb = br_fdb_get(br, da)) != NULL) {
				if (likely(storlink_ctl.fast_net & 2))
					skb->dev = br_fdb->dst->dev;
				output_dev = br_fdb->dst->dev;
				br_fdb_put(br_fdb);
			}
		}

#if defined (CONFIG_SL351x_NAT)
#ifdef CONFIG_VLAN_8021Q
		if (output_dev->priv_flags & IFF_802_1Q_VLAN)
			output_dev = VLAN_DEV_INFO(output_dev)->real_dev;

		if (input_dev->priv_flags & IFF_802_1Q_VLAN)
			input_dev = VLAN_DEV_INFO(input_dev)->real_dev;
#endif

		if ((input_dev->features & NETIF_F_HWNAT) && (output_dev->features & NETIF_F_HWNAT)) {
//			skb->dev = orig_dev;
//			goto skip_fast_nat;
			if ((ct != NULL) && (h!= NULL)) {
				//printk("%s::got here! yes ct %x, in use = %d!\n", __func__, ct, ct->ct_general.use);

				nf_conntrack_get(&ct->ct_general);
				skb->nfct = &ct->ct_general;
				if (DIRECTION(h) == IP_CT_DIR_REPLY)
					skb->nfctinfo = IP_CT_ESTABLISHED + IP_CT_IS_REPLY;
				else if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status))
					skb->nfctinfo = IP_CT_ESTABLISHED;
				else if (test_bit(IPS_EXPECTED_BIT, &ct->status))
					skb->nfctinfo = IP_CT_RELATED;
				else
					skb->nfctinfo = IP_CT_NEW;
			} else {
				//printk("%s::cannot find ip conntrack!\n", __func__);
				skb->dev = orig_dev;
				goto skip_fast_nat;
			}
		}
#endif

#ifdef KERNEL_1QVLAN
		/* We must trim skb or gmac modify iph->tot_len, this cause wrong TCP ACK number */
		__pskb_trim(skb, ntohs(iph->tot_len));
		//if((ntohs(iph->tot_len) <= 50))
		//	skb->len = ntohs(iph->tot_len) + ETH_HLEN;
#endif
		skb->data -= ETH_HLEN;
		skb->len  += ETH_HLEN;

#ifdef KERNEL_1QVLAN
			/* We must trim skb or gmac modify iph->tot_len, this cause wrong TCP ACK number */
//			if((ntohs(iph->tot_len) <= 50) && (from_vlan==1))
//				skb->len = ntohs(iph->tot_len) + ETH_HLEN;
			//skb->dev = output_dev;
#endif
		if (likely(storlink_ctl.fast_net & 2)) {
			if (unlikely(skb->dev->hard_start_xmit(skb, skb->dev)))
				dev_kfree_skb(skb);
		} else {
			if (unlikely(dev_queue_xmit(skb))) {
				printk("%s %s fast routing dev_queue_xmit failed\n", __func__,
						skb->dev->name);
				dev_kfree_skb(skb);
			}
		}
		return 1;

release_ct:;
		nf_conntrack_put(&ct->ct_general);

skip_fast_nat:;
#ifdef KERNEL_1QVLAN
		if (from_vlan == 1) {
			/* Put back the VLAN header (4 bytes currently) */
			skb_push(skb, VLAN_HLEN);

			if (likely(vhdr->h_vlan_encapsulated_proto == __constant_htons(ETH_P_IP))) {
					skb->nh.iph->saddr = sip;
					skb->nh.iph->daddr = dip;
			}
			vhdr->h_vlan_TCI = __constant_htons(vlan_TCI);
			eth->h_proto = __constant_htons(ETH_P_8021Q);
			//skb->dst = dst;
		} else {
			if (eth->h_proto == __constant_htons(ETH_P_IP)) {
				skb->nh.iph->saddr = sip;
				skb->nh.iph->daddr = dip;
			}
		}
#else
		if (eth->h_proto == __constant_htons(ETH_P_IP)) {
			skb->nh.iph->saddr = sip;
			skb->nh.iph->daddr = dip;
		}
#endif
		skb->dev = orig_dev;
		for (i=0; i<ETH_ALEN; i++) {
			eth->h_dest[i] = ehdr.h_dest[i];
			eth->h_source[i] = ehdr.h_source[i];
		}
	} else {
	}
	return 0;
}
#endif

