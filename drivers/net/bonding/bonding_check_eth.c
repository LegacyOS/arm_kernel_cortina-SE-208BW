/*
 * originally based on the dummy device.
 *
 * Copyright 1999, Thomas Davis, tadavis@lbl.gov.
 * Licensed under the GPL. Based on dummy.c, and eql.c devices.
 *
 * bonding.c: an Ethernet Bonding driver
 *
 * This is useful to talk to a Cisco EtherChannel compatible equipment:
 *	Cisco 5500
 *	Sun Trunking (Solaris)
 *	Alteon AceDirector Trunks
 *	Linux Bonding
 *	and probably many L2 switches ...
 *
 * How it works:
 *    ifconfig bond0 ipaddress netmask up
 *      will setup a network device, with an ip address.  No mac address
 *	will be assigned at this time.  The hw mac address will come from
 *	the first slave bonded to the channel.  All slaves will then use
 *	this hw mac address.
 *
 *    ifconfig bond0 down
 *         will release all slaves, marking them as down.
 *
 *    ifenslave bond0 eth0
 *	will attach eth0 to bond0 as a slave.  eth0 hw mac address will either
 *	a: be used as initial mac address
 *	b: if a hw mac address already is there, eth0's hw mac address
 *	   will then be set from bond0.
 *
 * v0.1 - first working version.
 * v0.2 - changed stats to be calculated by summing slaves stats.
 *
 * Changes:
 * Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 * - fix leaks on failure at bond_init
 *
 * 2000/09/30 - Willy Tarreau <willy at meta-x.org>
 *     - added trivial code to release a slave device.
 *     - fixed security bug (CAP_NET_ADMIN not checked)
 *     - implemented MII link monitoring to disable dead links :
 *       All MII capable slaves are checked every <miimon> milliseconds
 *       (100 ms seems good). This value can be changed by passing it to
 *       insmod. A value of zero disables the monitoring (default).
 *     - fixed an infinite loop in bond_xmit_roundrobin() when there's no
 *       good slave.
 *     - made the code hopefully SMP safe
 *
 * 2000/10/03 - Willy Tarreau <willy at meta-x.org>
 *     - optimized slave lists based on relevant suggestions from Thomas Davis
 *     - implemented active-backup method to obtain HA with two switches:
 *       stay as long as possible on the same active interface, while we
 *       also monitor the backup one (MII link status) because we want to know
 *       if we are able to switch at any time. ( pass "mode=1" to insmod )
 *     - lots of stress testings because we need it to be more robust than the
 *       wires ! :->
 *
 * 2000/10/09 - Willy Tarreau <willy at meta-x.org>
 *     - added up and down delays after link state change.
 *     - optimized the slaves chaining so that when we run forward, we never
 *       repass through the bond itself, but we can find it by searching
 *       backwards. Renders the deletion more difficult, but accelerates the
 *       scan.
 *     - smarter enslaving and releasing.
 *     - finer and more robust SMP locking
 *
 * 2000/10/17 - Willy Tarreau <willy at meta-x.org>
 *     - fixed two potential SMP race conditions
 *
 * 2000/10/18 - Willy Tarreau <willy at meta-x.org>
 *     - small fixes to the monitoring FSM in case of zero delays
 * 2000/11/01 - Willy Tarreau <willy at meta-x.org>
 *     - fixed first slave not automatically used in trunk mode.
 * 2000/11/10 : spelling of "EtherChannel" corrected.
 * 2000/11/13 : fixed a race condition in case of concurrent accesses to ioctl().
 * 2000/12/16 : fixed improper usage of rtnl_exlock_nowait().
 *
 * 2001/1/3 - Chad N. Tindel <ctindel at ieee dot org>
 *     - The bonding driver now simulates MII status monitoring, just like
 *       a normal network device.  It will show that the link is down iff
 *       every slave in the bond shows that their links are down.  If at least
 *       one slave is up, the bond's MII status will appear as up.
 *
 * 2001/2/7 - Chad N. Tindel <ctindel at ieee dot org>
 *     - Applications can now query the bond from user space to get
 *       information which may be useful.  They do this by calling
 *       the BOND_INFO_QUERY ioctl.  Once the app knows how many slaves
 *       are in the bond, it can call the BOND_SLAVE_INFO_QUERY ioctl to
 *       get slave specific information (# link failures, etc).  See
 *       <linux/if_bonding.h> for more details.  The structs of interest
 *       are ifbond and ifslave.
 *
 * 2001/4/5 - Chad N. Tindel <ctindel at ieee dot org>
 *     - Ported to 2.4 Kernel
 *
 * 2001/5/2 - Jeffrey E. Mast <jeff at mastfamily dot com>
 *     - When a device is detached from a bond, the slave device is no longer
 *       left thinking that is has a master.
 *
 * 2001/5/16 - Jeffrey E. Mast <jeff at mastfamily dot com>
 *     - memset did not appropriately initialized the bond rw_locks. Used
 *       rwlock_init to initialize to unlocked state to prevent deadlock when
 *       first attempting a lock
 *     - Called SET_MODULE_OWNER for bond device
 *
 * 2001/5/17 - Tim Anderson <tsa at mvista.com>
 *     - 2 paths for releasing for slave release; 1 through ioctl
 *       and 2) through close. Both paths need to release the same way.
 *     - the free slave in bond release is changing slave status before
 *       the free. The netdev_set_master() is intended to change slave state
 *       so it should not be done as part of the release process.
 *     - Simple rule for slave state at release: only the active in A/B and
 *       only one in the trunked case.
 *
 * 2001/6/01 - Tim Anderson <tsa at mvista.com>
 *     - Now call dev_close when releasing a slave so it doesn't screw up
 *       out routing table.
 *
 * 2001/6/01 - Chad N. Tindel <ctindel at ieee dot org>
 *     - Added /proc support for getting bond and slave information.
 *       Information is in /proc/net/<bond device>/info.
 *     - Changed the locking when calling bond_close to prevent deadlock.
 *
 * 2001/8/05 - Janice Girouard <girouard at us.ibm.com>
 *     - correct problem where refcnt of slave is not incremented in bond_ioctl
 *       so the system hangs when halting.
 *     - correct locking problem when unable to malloc in bond_enslave.
 *     - adding bond_xmit_xor logic.
 *     - adding multiple bond device support.
 *
 * 2001/8/13 - Erik Habbinga <erik_habbinga at hp dot com>
 *     - correct locking problem with rtnl_exlock_nowait
 *
 * 2001/8/23 - Janice Girouard <girouard at us.ibm.com>
 *     - bzero initial dev_bonds, to correct oops
 *     - convert SIOCDEVPRIVATE to new MII ioctl calls
 *
 * 2001/9/13 - Takao Indoh <indou dot takao at jp dot fujitsu dot com>
 *     - Add the BOND_CHANGE_ACTIVE ioctl implementation
 *
 * 2001/9/14 - Mark Huth <mhuth at mvista dot com>
 *     - Change MII_LINK_READY to not check for end of auto-negotiation,
 *       but only for an up link.
 *
 * 2001/9/20 - Chad N. Tindel <ctindel at ieee dot org>
 *     - Add the device field to bonding_t.  Previously the net_device
 *       corresponding to a bond wasn't available from the bonding_t
 *       structure.
 *
 * 2001/9/25 - Janice Girouard <girouard at us.ibm.com>
 *     - add arp_monitor for active backup mode
 *
 * 2001/10/23 - Takao Indoh <indou dot takao at jp dot fujitsu dot com>
 *     - Various memory leak fixes
 *
 * 2001/11/5 - Mark Huth <mark dot huth at mvista dot com>
 *     - Don't take rtnl lock in bond_mii_monitor as it deadlocks under
 *       certain hotswap conditions.
 *       Note:  this same change may be required in bond_arp_monitor ???
 *     - Remove possibility of calling bond_sethwaddr with NULL slave_dev ptr
 *     - Handle hot swap ethernet interface deregistration events to remove
 *       kernel oops following hot swap of enslaved interface
 *
 * 2002/1/2 - Chad N. Tindel <ctindel at ieee dot org>
 *     - Restore original slave flags at release time.
 *
 * 2002/02/18 - Erik Habbinga <erik_habbinga at hp dot com>
 *     - bond_release(): calling kfree on our_slave after call to
 *       bond_restore_slave_flags, not before
 *     - bond_enslave(): saving slave flags into original_flags before
 *       call to netdev_set_master, so the IFF_SLAVE flag doesn't end
 *       up in original_flags
 *
 * 2002/04/05 - Mark Smith <mark.smith at comdev dot cc> and
 *              Steve Mead <steve.mead at comdev dot cc>
 *     - Port Gleb Natapov's multicast support patchs from 2.4.12
 *       to 2.4.18 adding support for multicast.
 *
 * 2002/06/10 - Tony Cureington <tony.cureington * hp_com>
 *     - corrected uninitialized pointer (ifr.ifr_data) in bond_check_dev_link;
 *       actually changed function to use MIIPHY, then MIIREG, and finally
 *       ETHTOOL to determine the link status
 *     - fixed bad ifr_data pointer assignments in bond_ioctl
 *     - corrected mode 1 being reported as active-backup in bond_get_info;
 *       also added text to distinguish type of load balancing (rr or xor)
 *     - change arp_ip_target module param from "1-12s" (array of 12 ptrs)
 *       to "s" (a single ptr)
 *
 * 2002/08/30 - Jay Vosburgh <fubar at us dot ibm dot com>
 *     - Removed acquisition of xmit_lock in set_multicast_list; caused
 *       deadlock on SMP (lock is held by caller).
 *     - Revamped SIOCGMIIPHY, SIOCGMIIREG portion of bond_check_dev_link().
 *
 * 2002/09/18 - Jay Vosburgh <fubar at us dot ibm dot com>
 *     - Fixed up bond_check_dev_link() (and callers): removed some magic
 *	 numbers, banished local MII_ defines, wrapped ioctl calls to
 *	 prevent EFAULT errors
 *
 * 2002/9/30 - Jay Vosburgh <fubar at us dot ibm dot com>
 *     - make sure the ip target matches the arp_target before saving the
 *	 hw address.
 *
 * 2002/9/30 - Dan Eisner <eisner at 2robots dot com>
 *     - make sure my_ip is set before taking down the link, since
 *	 not all switches respond if the source ip is not set.
 *
 * 2002/10/8 - Janice Girouard <girouard at us dot ibm dot com>
 *     - read in the local ip address when enslaving a device
 *     - add primary support
 *     - make sure 2*arp_interval has passed when a new device
 *       is brought on-line before taking it down.
 *
 * 2002/09/11 - Philippe De Muyter <phdm at macqel dot be>
 *     - Added bond_xmit_broadcast logic.
 *     - Added bond_mode() support function.
 *
 * 2002/10/26 - Laurent Deniel <laurent.deniel at free.fr>
 *     - allow to register multicast addresses only on active slave
 *       (useful in active-backup mode)
 *     - add multicast module parameter
 *     - fix deletion of multicast groups after unloading module
 *
 * 2002/11/06 - Kameshwara Rayaprolu <kameshwara.rao * wipro_com>
 *     - Changes to prevent panic from closing the device twice; if we close
 *       the device in bond_release, we must set the original_flags to down
 *       so it won't be closed again by the network layer.
 *
 * 2002/11/07 - Tony Cureington <tony.cureington * hp_com>
 *     - Fix arp_target_hw_addr memory leak
 *     - Created activebackup_arp_monitor function to handle arp monitoring
 *       in active backup mode - the bond_arp_monitor had several problems...
 *       such as allowing slaves to tx arps sequentially without any delay
 *       for a response
 *     - Renamed bond_arp_monitor to loadbalance_arp_monitor and re-wrote
 *       this function to just handle arp monitoring in load-balancing mode;
 *       it is a lot more compact now
 *     - Changes to ensure one and only one slave transmits in active-backup
 *       mode
 *     - Robustesize parameters; warn users about bad combinations of
 *       parameters; also if miimon is specified and a network driver does
 *       not support MII or ETHTOOL, inform the user of this
 *     - Changes to support link_failure_count when in arp monitoring mode
 *     - Fix up/down delay reported in /proc
 *     - Added version; log version; make version available from "modinfo -d"
 *     - Fixed problem in bond_check_dev_link - if the first IOCTL (SIOCGMIIPH)
 *	 failed, the ETHTOOL ioctl never got a chance
 *
 * 2002/11/16 - Laurent Deniel <laurent.deniel at free.fr>
 *     - fix multicast handling in activebackup_arp_monitor
 *     - remove one unnecessary and confusing curr_active_slave == slave test
 *	 in activebackup_arp_monitor
 *
 *  2002/11/17 - Laurent Deniel <laurent.deniel at free.fr>
 *     - fix bond_slave_info_query when slave_id = num_slaves
 *
 *  2002/11/19 - Janice Girouard <girouard at us dot ibm dot com>
 *     - correct ifr_data reference.  Update ifr_data reference
 *       to mii_ioctl_data struct values to avoid confusion.
 *
 *  2002/11/22 - Bert Barbe <bert.barbe at oracle dot com>
 *      - Add support for multiple arp_ip_target
 *
 *  2002/12/13 - Jay Vosburgh <fubar at us dot ibm dot com>
 *	- Changed to allow text strings for mode and multicast, e.g.,
 *	  insmod bonding mode=active-backup.  The numbers still work.
 *	  One change: an invalid choice will cause module load failure,
 *	  rather than the previous behavior of just picking one.
 *	- Minor cleanups; got rid of dup ctype stuff, atoi function
 *
 * 2003/02/07 - Jay Vosburgh <fubar at us dot ibm dot com>
 *	- Added use_carrier module parameter that causes miimon to
 *	  use netif_carrier_ok() test instead of MII/ETHTOOL ioctls.
 *	- Minor cleanups; consolidated ioctl calls to one function.
 *
 * 2003/02/07 - Tony Cureington <tony.cureington * hp_com>
 *	- Fix bond_mii_monitor() logic error that could result in
 *	  bonding round-robin mode ignoring links after failover/recovery
 *
 * 2003/03/17 - Jay Vosburgh <fubar at us dot ibm dot com>
 *	- kmalloc fix (GFP_KERNEL to GFP_ATOMIC) reported by
 *	  Shmulik dot Hen at intel.com.
 *	- Based on discussion on mailing list, changed use of
 *	  update_slave_cnt(), created wrapper functions for adding/removing
 *	  slaves, changed bond_xmit_xor() to check slave_cnt instead of
 *	  checking slave and slave->dev (which only worked by accident).
 *	- Misc code cleanup: get arp_send() prototype from header file,
 *	  add max_bonds to bonding.txt.
 *
 * 2003/03/18 - Tsippy Mendelson <tsippy.mendelson at intel dot com> and
 *		Shmulik Hen <shmulik.hen at intel dot com>
 *	- Make sure only bond_attach_slave() and bond_detach_slave() can
 *	  manipulate the slave list, including slave_cnt, even when in
 *	  bond_release_all().
 *	- Fixed hang in bond_release() with traffic running:
 *	  netdev_set_master() must not be called from within the bond lock.
 *
 * 2003/03/18 - Tsippy Mendelson <tsippy.mendelson at intel dot com> and
 *		Shmulik Hen <shmulik.hen at intel dot com>
 *	- Fixed hang in bond_enslave() with traffic running:
 *	  netdev_set_master() must not be called from within the bond lock.
 *
 * 2003/03/18 - Amir Noam <amir.noam at intel dot com>
 *	- Added support for getting slave's speed and duplex via ethtool.
 *	  Needed for 802.3ad and other future modes.
 *
 * 2003/03/18 - Tsippy Mendelson <tsippy.mendelson at intel dot com> and
 *		Shmulik Hen <shmulik.hen at intel dot com>
 *	- Enable support of modes that need to use the unique mac address of
 *	  each slave.
 *	  * bond_enslave(): Moved setting the slave's mac address, and
 *	    openning it, from the application to the driver. This breaks
 *	    backward comaptibility with old versions of ifenslave that open
 *	     the slave before enalsving it !!!.
 *	  * bond_release(): The driver also takes care of closing the slave
 *	    and restoring its original mac address.
 *	- Removed the code that restores all base driver's flags.
 *	  Flags are automatically restored once all undo stages are done
 *	  properly.
 *	- Block possibility of enslaving before the master is up. This
 *	  prevents putting the system in an unstable state.
 *
 * 2003/03/18 - Amir Noam <amir.noam at intel dot com>,
 *		Tsippy Mendelson <tsippy.mendelson at intel dot com> and
 *		Shmulik Hen <shmulik.hen at intel dot com>
 *	- Added support for IEEE 802.3ad Dynamic link aggregation mode.
 *
 * 2003/05/01 - Amir Noam <amir.noam at intel dot com>
 *	- Added ABI version control to restore compatibility between
 *	  new/old ifenslave and new/old bonding.
 *
 * 2003/05/01 - Shmulik Hen <shmulik.hen at intel dot com>
 *	- Fixed bug in bond_release_all(): save old value of curr_active_slave
 *	  before setting it to NULL.
 *	- Changed driver versioning scheme to include version number instead
 *	  of release date (that is already in another field). There are 3
 *	  fields X.Y.Z where:
 *		X - Major version - big behavior changes
 *		Y - Minor version - addition of features
 *		Z - Extra version - minor changes and bug fixes
 *	  The current version is 1.0.0 as a base line.
 *
 * 2003/05/01 - Tsippy Mendelson <tsippy.mendelson at intel dot com> and
 *		Amir Noam <amir.noam at intel dot com>
 *	- Added support for lacp_rate module param.
 *	- Code beautification and style changes (mainly in comments).
 *	  new version - 1.0.1
 *
 * 2003/05/01 - Shmulik Hen <shmulik.hen at intel dot com>
 *	- Based on discussion on mailing list, changed locking scheme
 *	  to use lock/unlock or lock_bh/unlock_bh appropriately instead
 *	  of lock_irqsave/unlock_irqrestore. The new scheme helps exposing
 *	  hidden bugs and solves system hangs that occurred due to the fact
 *	  that holding lock_irqsave doesn't prevent softirqs from running.
 *	  This also increases total throughput since interrupts are not
 *	  blocked on each transmitted packets or monitor timeout.
 *	  new version - 2.0.0
 *
 * 2003/05/01 - Shmulik Hen <shmulik.hen at intel dot com>
 *	- Added support for Transmit load balancing mode.
 *	- Concentrate all assignments of curr_active_slave to a single point
 *	  so specific modes can take actions when the primary adapter is
 *	  changed.
 *	- Take the updelay parameter into consideration during bond_enslave
 *	  since some adapters loose their link during setting the device.
 *	- Renamed bond_3ad_link_status_changed() to
 *	  bond_3ad_handle_link_change() for compatibility with TLB.
 *	  new version - 2.1.0
 *
 * 2003/05/01 - Tsippy Mendelson <tsippy.mendelson at intel dot com>
 *	- Added support for Adaptive load balancing mode which is
 *	  equivalent to Transmit load balancing + Receive load balancing.
 *	  new version - 2.2.0
 *
 * 2003/05/15 - Jay Vosburgh <fubar at us dot ibm dot com>
 *	- Applied fix to activebackup_arp_monitor posted to bonding-devel
 *	  by Tony Cureington <tony.cureington * hp_com>.  Fixes ARP
 *	  monitor endless failover bug.  Version to 2.2.10
 *
 * 2003/05/20 - Amir Noam <amir.noam at intel dot com>
 *	- Fixed bug in ABI version control - Don't commit to a specific
 *	  ABI version if receiving unsupported ioctl commands.
 *
 * 2003/05/22 - Jay Vosburgh <fubar at us dot ibm dot com>
 *	- Fix ifenslave -c causing bond to loose existing routes;
 *	  added bond_set_mac_address() that doesn't require the
 *	  bond to be down.
 *	- In conjunction with fix for ifenslave -c, in
 *	  bond_change_active(), changing to the already active slave
 *	  is no longer an error (it successfully does nothing).
 *
 * 2003/06/30 - Amir Noam <amir.noam at intel dot com>
 * 	- Fixed bond_change_active() for ALB/TLB modes.
 *	  Version to 2.2.14.
 *
 * 2003/07/29 - Amir Noam <amir.noam at intel dot com>
 * 	- Fixed ARP monitoring bug.
 *	  Version to 2.2.15.
 *
 * 2003/07/31 - Willy Tarreau <willy at ods dot org>
 * 	- Fixed kernel panic when using ARP monitoring without
 *	  setting bond's IP address.
 *	  Version to 2.2.16.
 *
 * 2003/08/06 - Amir Noam <amir.noam at intel dot com>
 * 	- Back port from 2.6: use alloc_netdev(); fix /proc handling;
 *	  made stats a part of bond struct so no need to allocate
 *	  and free it separately; use standard list operations instead
 *	  of pre-allocated array of bonds.
 *	  Version to 2.3.0.
 *
 * 2003/08/07 - Jay Vosburgh <fubar at us dot ibm dot com>,
 *	       Amir Noam <amir.noam at intel dot com> and
 *	       Shmulik Hen <shmulik.hen at intel dot com>
 *	- Propagating master's settings: Distinguish between modes that
 *	  use a primary slave from those that don't, and propagate settings
 *	  accordingly; Consolidate change_active opeartions and add
 *	  reselect_active and find_best opeartions; Decouple promiscuous
 *	  handling from the multicast mode setting; Add support for changing
 *	  HW address and MTU with proper unwind; Consolidate procfs code,
 *	  add CHANGENAME handler; Enhance netdev notification handling.
 *	  Version to 2.4.0.
 *
 * 2003/09/15 - Stephen Hemminger <shemminger at osdl dot org>,
 *	       Amir Noam <amir.noam at intel dot com>
 *	- Convert /proc to seq_file interface.
 *	  Change /proc/net/bondX/info to /proc/net/bonding/bondX.
 *	  Set version to 2.4.1.
 *
 * 2003/11/20 - Amir Noam <amir.noam at intel dot com>
 *	- Fix /proc creation/destruction.
 *
 * 2003/12/01 - Shmulik Hen <shmulik.hen at intel dot com>
 *	- Massive cleanup - Set version to 2.5.0
 *	  Code changes:
 *	  o Consolidate format of prints and debug prints.
 *	  o Remove bonding_t/slave_t typedefs and consolidate all casts.
 *	  o Remove dead code and unnecessary checks.
 *	  o Consolidate starting/stopping timers.
 *	  o Consolidate handling of primary module param throughout the code.
 *	  o Removed multicast module param support - all settings are done
 *	    according to mode.
 *	  o Slave list iteration - bond is no longer part of the list,
 *	    added cyclic list iteration macros.
 *	  o Consolidate error handling in all xmit functions.
 *	  Style changes:
 *	  o Consolidate function naming and declarations.
 *	  o Consolidate function params and local variables names.
 *	  o Consolidate return values.
 *	  o Consolidate curly braces.
 *	  o Consolidate conditionals format.
 *	  o Change struct member names and types.
 *	  o Chomp trailing spaces, remove empty lines, fix indentations.
 *	  o Re-organize code according to context.
 *
 * 2003/12/30 - Amir Noam <amir.noam at intel dot com>
 *	- Fixed: Cannot remove and re-enslave the original active slave.
 *	- Fixed: Releasing the original active slave causes mac address
 *		 duplication.
 *	- Add support for slaves that use ethtool_ops.
 *	  Set version to 2.5.3.
 *
 * 2004/01/05 - Amir Noam <amir.noam at intel dot com>
 *	- Save bonding parameters per bond instead of using the global values.
 *	  Set version to 2.5.4.
 *
 * 2004/01/14 - Shmulik Hen <shmulik.hen at intel dot com>
 *	- Enhance VLAN support:
 *	  * Add support for VLAN hardware acceleration capable slaves.
 *	  * Add capability to tag self generated packets in ALB/TLB modes.
 *	  Set version to 2.6.0.
 * 2004/10/29 - Mitch Williams <mitch.a.williams at intel dot com>
 *      - Fixed bug when unloading module while using 802.3ad.  If
 *        spinlock debugging is turned on, this causes a stack dump.
 *        Solution is to move call to dev_remove_pack outside of the
 *        spinlock.
 *        Set version to 2.6.1.
 * 2005/06/05 - Jay Vosburgh <fubar@us.ibm.com>
 * 	- Support for generating gratuitous ARPs in active-backup mode.
 * 	  Includes support for VLAN tagging all bonding-generated ARPs
 * 	  as needed.  Set version to 2.6.2.
 * 2005/06/08 - Jason Gabler <jygabler at lbl dot gov>
 *	- alternate hashing policy support for mode 2
 *	  * Added kernel parameter "xmit_hash_policy" to allow the selection
 *	    of different hashing policies for mode 2.  The original mode 2
 *	    policy is the default, now found in xmit_hash_policy_layer2().
 *	  * Added xmit_hash_policy_layer34()
 *	- Modified by Jay Vosburgh <fubar@us.ibm.com> to also support mode 4.
 *	  Set version to 2.6.3.
 * 2005/09/26 - Jay Vosburgh <fubar@us.ibm.com>
 *	- Removed backwards compatibility for old ifenslaves.  Version 2.6.4.
 */

//#define BONDING_DEBUG 1

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <net/ip.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/socket.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/bitops.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/if_ether.h>
#include <net/arp.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/if_bonding.h>
#include <net/route.h>
#include "bonding.h"
#include "bond_3ad.h"
#include "bond_alb.h"



int bond_check_eth0(struct net_device *bond_dev)
{
	struct bonding *bond = bond_dev->priv;
	struct slave *slave, *start_at;
	int i;
	int retval=0;

	read_lock(&bond->lock);

	if (!BOND_IS_OK(bond)) {
		goto out;
	}

	read_lock(&bond->curr_slave_lock);
	slave = start_at = bond->curr_active_slave;
	read_unlock(&bond->curr_slave_lock);

	if (!slave) {
		goto out;
	}

	bond_for_each_slave_from(bond, slave, i, start_at) {
		if (IS_UP(slave->dev) &&
		    (slave->link == BOND_LINK_UP) &&
		    (slave->state == BOND_STATE_ACTIVE)) {
			if (!strcmp(slave->dev->name,"eth0"))
				retval=1;
			break;
		}
	}


out:
	read_unlock(&bond->lock);
	return retval;
}


