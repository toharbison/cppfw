#ifndef TARGETS_H
#define TARGETS_H

#include <string>
#include "target_headers.hpp"
typedef std::string string;
typedef xt_audit_info xt_audit_target;
typedef xt_CHECKSUM_info xt_checksum_target;
typedef xt_classify_target_info xt_classify_target;
typedef xt_connmark_tginfo1 xt_connmark_target;
typedef xt_connsecmark_target_info xt_connsecmark_target;
typedef xt_ct_target_info_v1 xt_ct_target;
typedef xt_DSCP_info xt_dscp_target;
typedef xt_tos_target_info xt_tos_target;
typedef xt_tos_target_info xt_hmark_target;
typedef idletimer_tg_info xt_idletimer_target; 
typedef xt_led_info xt_led_target;
typedef xt_log_info xt_log_target;
typedef xt_mark_tginfo2 xt_mark_target;
typedef xt_nflog_info xt_nflog_target;
typedef xt_NFQ_info_v3 xt_nfqueue_target;
typedef xt_rateest_target_info xt_rateest_target;
typedef xt_secmark_target_info xt_secmark_target;
typedef xt_synproxy_info xt_synproxy_target;
typedef xt_tcpmss_info xt_tcpmss_target;
typedef xt_tcpoptstrip_target_info xt_tcpoptstrip_target;
typedef xt_tee_tginfo xt_tee_target;
typedef xt_tproxy_target_info_v1 xt_tproxy_target;
typedef ipt_reject_info ipt_reject_target;
typedef ipt_TTL_info ipt_ttl_target;
typedef ip6t_HL_info ip6t_hl_target;
typedef ip6t_npt_tginfo ip6t_npt_target;
typedef ip6t_reject_info ip6t_reject_target;

#if 0
class TemplateTarget : Target{
  public:
  /* Constructors */
  TemplateTarget();
  TemplateTarget(args);

  /* Setter functions */

  /* Returns target specs */
  ip6t_template_target getSpecs();

  private:
  ip6t_template_target specs;
};

#endif

class Target{
  public:
  /* Returns name of target */
  virtual string getName() = 0;
  virtual int getSize() = 0;
};

class AuditTarget : Target{
  public:
  /* Constuctors */
  AuditTarget();
  AuditTarget(unsigned char type);

  /**
   * Sets the type of audit record. Depracated and has no effect on messages since linux-4.12
   * "type" can be the macro XT_AUDIT_TYPE_* where * is ACCEPT, DROP, or REJECT
   */
  void setType(unsigned char type);

  /* Returns target specs */
  xt_audit_target getSpecs();

  private:
  xt_audit_target specs;
};

/* Used only in mangle table */
class ChecksumTarget : Target{
  public:
  /* Constructors */
  ChecksumTarget();
  ChecksumTarget(bool op);

  /** Sets whether to fill checksum in packet
   * "op" true to fill, false to not
   */
  void setOp(bool op);

  /* Returns target specs */
  xt_checksum_target getSpecs();

  private:
  xt_checksum_target specs;
};

class ClassifyTarget : Target{
  public:
  /* Constuctors */
  ClassifyTarget();
  ClassifyTarget(unsigned int major, unsigned int minor);

  /**
   * Sets the major and minor class values of the CBQ class
   * "major" the major class value
   * "minor" the minor class value
   */
  void setClass(unsigned int major, unsigned int minor);

  /* Returns target specs */
  xt_classify_target getSpecs();

  private:
  xt_classify_target specs;
};

class ConnmarkTarget : Target{
  public:
  /* Constructors */
  ConnmarkTarget();
  ConnmarkTarget(unsigned char mode, unsigned int ctmark, unsigned int ctmask, unsigned int nfmask);

  /**
   * Zeros bit give by mask and XOR ctmark with value
   * "value" bit XORed with ctmark
   * "mask" bits to zero out
   */
  void setMark(unsigned int value, unsigned int mask);

  /**
   * Copy the packet nfmark to the ctmark with masks. Equation used is
   * ctmark = (ctmark * ~ctmask) ^ (nfmark & nfmask)
   * "ctmask" value of the ctmask
   * "nfmask" value of nfmask
   */
  void saveMark(unsigned int ctmask, unsigned int nfmask);

  /**
   * Copy the packet ctmark to the nfmark with give masks. Equation used is
   * nfmark = (nfmark & ~ nfmask) ^ (ctmark & ctmask)
   * Can only be used in mangle table
   * "ctmask" value of ctmask
   * "nfmask" value of nfmask
   */
  void restoreMark(unsigned int ctmask, unsigned int nfmask);

  /* Return target specs */
  xt_connmark_target getSpecs();

  private:
  xt_connmark_target specs;
};

/* Valid in security table (and mangle table for older kernels) */
class ConnsecmarkTarget : Target{
  public:
  /* Constructors */
  ConnsecmarkTarget();
  ConnsecmarkTarget(unsigned char mode);

  /**
   * Sets the mode of the target
   * "mode" The mode of the target, can be macros:
   * CONNSECMARK_SAVE which copies the security marking on packet to the connection if it doesn't have
   * a marking
   * CONNSECMARK_RESTORE which copies the security marking on the connection to the packet if it
   * doesn't have a marking
   */
  void setMode(unsigned char mode);

  /* Returns target specs */
  xt_connsecmark_target getSpecs();

  private:
  xt_connsecmark_target specs;
};

/* Only valid in raw table */
class CTTarget : Target{
  public:
  /* Constructors */
  CTTarget();
  CTTarget(bool noTrack, string helper, string timeout, unsigned int ctEvents, unsigned int expEvents, 
      unsigned char flags, unsigned int zone);

  /* Disables tracking on this packet */
  void setNoTrack();

  /**
   * Use helper IDed by "name" for the connection
   * "name" identifies helper
   */
  void setHelper(string name);

  /**
   * Use timeout policy IDed by "name" for the connection
   * "name" identifies timeout policy
   */
  void setTimeout(string name);

  /**
   * Only generate specific conntrack "events" for this connection. Event types are: new, related, destroy.
   * reply, assured, protoinfo, helper, mark (ctmark), natseqinfo, secmark (ctsecmark)
   * "events" specified events
   */
  void setCTEvents(int events);

  /**
   * Only generate speceific expectation events for this connection. Event types are: new
   * "events" specified events
   */
  void setExpEvents(int events);

  /**
   * Assigns packet to a zone and only does lookups in that zone. Can set mode to specify packets
   * coming from ORIGINAL or REPLY direction. Can also specify deriving zone from nfmark instead of
   * "id" Id of the zone to do lookups
   * "flags" Specifies the direction of desired packet and if using nfmark to derive zone. Values
   * can be: XT_CT_ZONE_DIR_ORIG, XT_CT_ZONE_DIR_REPL, or XT_CT_ZONE_MARK. XT_CT_ZONE_MARK can be
   * bitwise ORed with the previous two. 
   */
  void setZone(unsigned char flags, unsigned int id);

  /* Returns target specs */
  xt_ct_target getSpecs();

  private:
  xt_ct_target specs;
};

/* Only valid in mangle table */
class DscpTarget : Target{
  public:
  /* Constructors */
  DscpTarget();
  DscpTarget(unsigned char value);

  /**
   * Sets DSCP field to replace the filed in the TOS header of the IPv4 packet
   * "value" value of the DSCP field
   */
  void setDscp(unsigned char value);

  /* Returns target specs */
  xt_dscp_target getSpecs();

  private:
  xt_dscp_target specs;
};

// Valid only in mangle table
class TosTarget : Target{
  public:
  /* Constructors */
  TosTarget();
  TosTarget(unsigned char value, unsigned char mask);

  /**
   * Zeroes out bits give by "mask" and XORs "value" into TOS/Priority field of the packet
   * "value" value to XOR into TOS/Priority field
   * "mask" bits to zero out before XOR
   */
  void setTos(unsigned char value, unsigned char mask);

  /* Returns target specs */
  xt_tos_target getSpecs();

  private:
  xt_tos_target specs;
};

/**
 * Sets fwmark with a mark calculated for hashing packet selector at choice
 * Valid in PREROUTING and OUTPUT of mangle table
 */
class HmarkTarget : Target{
  public:
  /* Constructor */
  HmarkTarget();

  /* Sets the source and/or destination address mask */
  void setSrc(string mask);
  void setDst(string mask);

  /* Sets the source and/or destination port mask */
  void setSPort(unsigned int mask);
  void setDPort(unsigned int mask);

  /* Sets the spi mask */
  void setSpi(unsigned int mask);

  /* Sets a layer 4 protocol number mask */
  void setProto(unsigned char mask);

  /* Sets a random costum value to feed hash calculations */
  void setRnd(unsigned int value);

  /* Sets modulus for hash caluclations */
  void setMod(unsigned int value);

  /* Offset the start marks from */
  void setOffset(unsigned int value);

  /* Returns target specs */
  xt_hmark_target getSpecs();

  private:
  xt_hmark_target specs;
};

/**
 * Can be used to set a timer for when an interface has been idle for a certain amount of time
 * Timers are created when a new label is added. When time expires a sysfs notifcation is sent to
 * the userspace.
 */
class IdletimerTarget : Target{
  public:
  /* Constructors */
  IdletimerTarget();
  IdletimerTarget(string label, unsigned int timeout);

  /* Sets the label of the timer. Maximum length is 27 characters */
  void setLabel(string label);
  
  /* Sets amount of time in seconds a notification will trigger */
  void setTimeout(unsigned int timeout);

  /* Returns target specs */
  xt_idletimer_target getSpecs();

  private:
  xt_idletimer_target specs;
};

/**
 * Creates an LED trigger that can be attached to system indicator lights. This can be used to blink
 * when ever a certain connection is made.
 */
class LedTarget : Target{
  public:
  /* Constructors */
  LedTarget();
  LedTarget(string name, unsigned int delay, bool alwaysBlink);

  /** 
   * Sets the name of the trigger. Actual name will be  prefixed with "netfilter-". Limit of 26
   * charaters 
   */
  void setName(string name);

  /* Sets how long in milliseconds the LED stays on should be illuminated for when triggered */
  void setDelay(unsigned int delay);

  /* Sets whether the led blinks when triggered, even if the LED is already on */
  void setAlwaysBlink(bool alwaysBlink);

  /* Returns target specs */
  xt_led_target getSpecs();

  private:
  xt_led_target specs;
};

/**
 * Used to kernel log matching packets. Log can be read in dmesg of syslog. Non-terminating target
 * rule traversal will continue next rule in chain.
 */
class LogTarget : Target{
  public:
  /* Constructors */
  LogTarget();
  LogTarget(string prefix, unsigned char level, unsigned char flags);

  /* Sets prefix of log message. Limit of 30 characters */
  void setPrefix(string prefix);

  /* Sets level of logging */
  void setLevel(unsigned char level);

  /**
   * Sets flags to parts of the packet to log. Options prefixed by "XT_LOG_" are
   * "TCPSEQ" : Logs tcp sequence numbers. Security risk if log is visible to users
   * "TCPOPT" : Logs options of the tcp packet header
   * "IPOPT"  : Logs options from ip/ipv6 packet header
   * "UID"    : Logs userid of process which generated the packet
   */
  void setFlags(unsigned char flags);

  /* Returns target specs */
  xt_log_target getSpecs();

  private:
  xt_log_target specs;
};

/**
 * Used to set the nfmark of a packet. Mark should be set in PREROUTING or OUTPUT chain of the
 * mangle table to affect routing
 */
class MarkTarget : Target{
  public:
  /* Constructors */
  MarkTarget();
  MarkTarget(unsigned int mark, unsigned int mask);

  /* Set the mark to be XORed onto nfmark of packet */
  void setMark(unsigned int mark);

  /* Set bits to be zeroed out before XOR function */
  void setMask(unsigned int mask);

  /* Returns target specs */
  xt_mark_target getSpecs();

  private:
  xt_mark_target specs;
};

/**
 * Provides logging of matching packets. Works like LOG but can be used with a loaded logging
 * backend (usually nfnetlink_log) which can allow userspace processes to recieve the packets.
 */
class NFLogTarget : Target{
  public:
  /* Constructors */
  NFLogTarget();
  NFLogTarget(string prefix, unsigned int group, unsigned int threshold);

  /* Sets prefix to log message. Limit of 64 characters */
  void setPrefix(string prefix);

  /* Sets the netlink group to which packets are. Only applicable to nfnetlink_log */
  void setGroup(unsigned int group);

  /* Sets number of packets to hold in kernel before sending them to userspace. Only applicable to
   * nfnetlink_log */
  void setThreshold(unsigned int threshold);

  /* Sets number of bytes to be copied to userspace. Only used with nfnetlink_log */
  void setSize(unsigned int size);

  /* Returns target specs */
  xt_nflog_target getSpecs();

  private:
  xt_nflog_target specs;
};

class NFQueueTarget : Target{
  public:
  /* Constructors */
  NFQueueTarget();
  NFQueueTarget(unsigned int num);
  NFQueueTarget(unsigned int first, unsigned int last);

  /* Set the queue number to use */
  void setNum(unsigned int num);

  /* Set a range of queues to balance packets */
  void setBalance(unsigned int first, unsigned int last);

  /* Sets target to ACCEPT packets when no program is listening to NFQUEUE instead of DROP */
  void setBypass();

  /* When balance option is used, sets the cpud id as an index to map packets */
  void setCpuFanout();

  /* Returns target specs */
  xt_nfqueue_target getSpecs();

  private:
  xt_nfqueue_target specs;
};

/**
 * Collects statistics and rate estimation calculations and saves results to be used by rateest
 * match
 */
class RateEstTarget : Target{
  public:
  /* Constructors */
  RateEstTarget();
  RateEstTarget(string name, char interval, unsigned char ewmalog);

  /* Set the name of the pool matched packets are counted */
  void setName(string name);

  /* Set rate measurement intervals in microseconds */
  void setInterval(char interval);

  /* Set rate measurement averaging time constant */
  void setEwmaLog(unsigned char ewmalog);

  /* Returns target specs */
  xt_rateest_target getSpecs();

  private:
  xt_rateest_target specs;
};

/** 
 * Used with SELinux, allows for security marks and security context to be set on matching packets
 */
class SecMarkTarget : Target{
  public:
  /* Constructors */
  SecMarkTarget();
  SecMarkTarget(unsigned int secid, string context);

  /* Set the security mark or secid of the packet */
  void setSecID(unsigned int secid);

  /* Set security context to be caught by SELinux */
  void setContext(string context);

  /* Returns target specs */
  xt_secmark_target getSpecs();

  private:
  xt_secmark_target specs;
};

/**
 * Process tcp three-way-handshake in parallel in netfilter context to protect local or backend
 * system. Requires connection tracking because sequence numbers need to be tracked. Should not be
 * needed to protect linux servers after Linux 4.4.
 */
class SynproxyTarget : Target{
  public:
  /* Constructors */
  SynproxyTarget();
  SynproxyTarget(unsigned int mss, unsigned char wscale);

  /* Sets maximum segment size announced to clients. Must match backend */
  void setMss(unsigned int mss);

  /* Sets window scale announced to clients. Must match backend */
  void setWinScale(unsigned char wscale);

  /* Enables passing client acknoledgement option to backend */
  void setSackPerm();

  /* Enables passing client timestamp option to backend */
  void setTimestamps();

  /* Returns target specs */
  xt_synproxy_target getSpecs();

  private:
  xt_synproxy_target specs;
};

/**
 * Alters MSS value of tcp syn packets to control maximum size for that connection. Needed to
 * overcome certain ISPs and servers which block "ICMP Fragmentation Needed" or "ICMPv6 Packet Too
 * Big" packets.
 * Requires matching tcp protocol
 * Default clamps mss to path_MTU - 40/60 (ipv4/ipv6)
 */
class TcpmssTarget : Target{
  public:
  /* Constructors */
  TcpmssTarget();
  TcpmssTarget(unsigned int mss);

  /* Sets MSS option to a specific value */
  void setMss(unsigned int mss);

  /* Returns target specs */
  xt_tcpmss_target getSpecs();

  private:
  xt_tcpmss_target specs;
};

/**
 * Strips designated options from the tcp header.
 * Requires matching to tcp protocol
 */
class TcpOptStripTarget : Target{
  public:
  /* Constructors */
  TcpOptStripTarget();
  TcpOptStripTarget(unsigned int* options, int size);

  /**
   * Set what options should be stripped from matched packets
   * "options" array of tcp option numbers to be stripped
   * "size" size of array
   */
  void setOptions(unsigned int* options, int size);

  /* Returns target specs */
  xt_tcpoptstrip_target getSpecs();

  private:
  xt_tcpoptstrip_target specs;
};

/**
 * Clones the matched packet and redirects it to another machine.
 */
class TeeTarget : Target{
  public:
  /* Constructors */
  TeeTarget();
  TeeTarget(string ip);

  /* Set the ip address to send the packet */
  void setIp(string ip);

  /* Returns target specs */
  xt_tee_target getSpecs();

  private:
  xt_tee_target specs;
};

/**
 * Redirects packet to a local socket without changing the packet header
 * Only valid in the mangle table's PREROUTING chain or user defined chains
 * Only valid if matching tcp or udp protocols
 */
class TproxyTarget : Target{
  public:
  /* Constructors */
  TproxyTarget();
  TproxyTarget(unsigned int port);
  TproxyTarget(unsigned int port, string ip);

  /* Sets destination port. 0 means desination port stays the same */
  void setPort(unsigned int port);

  /* Sets destination ip address. Ip of incoming interface is default */
  void setIp(string ip);

  /* Sets mark and mask to set the fwmark of the packet */
  void setMark(unsigned int mark, unsigned int mask);

  /* Returns target specs */
  xt_tproxy_target getSpecs();

  private:
  xt_tproxy_target specs;
};

/**
 * Works like DROP but sends back a error packet.
 * Only valid in INPUT, FOWARD, and OUTPUT chains
 */
class RejectIPTarget : Target{
  public:
  /* Constructors */
  RejectIPTarget();
  RejectIPTarget(ipt_reject_with type);

  /**
   * Sets what error message will send. Types prefixed with "IPT_ICMP_" are
   * NET_UNREACHABLE, HOST_UNREACHABLE, PROT_UNREACHABLE, PORT_UNREACHABLE, ECHOREPLY,
   * NET_PROHIBITED, HOST_PROHIBITED, ADMIN_PROHIBITED.
   * IPT_TCP_RESET is also an option but requires matching tcp protocol
   */
  void setType(ipt_reject_with type);

  /* Returns target specs */
  ipt_reject_target getSpecs();

  private:
  ipt_reject_target specs;
};

/**
 * Used to modify the TTL header field of IPv4 header. TTL sets how many hops a packet can make
 * before it's time to live is exceeded. This can be very dangerous so only use this target when
 * absolutely nessacary.
 * Never set or increment the TTL of packets leaving you local network!!!
 * Only valid in mangle table
 */
class TtlTarget : Target{
  public:
  /* Constructors */
  TtlTarget();
  TtlTarget(unsigned char value, unsigned char mode);

  /**
   * Sets how to edit the TTL field
   * "value" value used to operate on TTL
   * "mode"  how the value should be used. Options are
   * * "IPT_TTL_SET" : sets TTL field to "value"
   * * "IPT_TTL_INC" : increments TTL by "value"
   * * "IPT_TTL_DEC" : decrements TTL by "value"
   */
  void setEdit(unsigned char value, unsigned char mode);

  /* Returns target specs */
  ipt_ttl_target getSpecs();

  private:
  ipt_ttl_target specs;
};

/**
 * Used to modify the HL (Hop Limit) header field of IPv6 header. HL sets how many hops a packet can make
 * before it's time to live is exceeded. This can be very dangerous so only use this target when
 * absolutely nessacary.
 * Never set or increment the HL of packets leaving you local network!!!
 * Only valid in mangle table
 */
class HlTarget : Target{
  public:
  /* Constructors */
  HlTarget();
  HlTarget(unsigned char value, unsigned char mode);

  /**
   * Sets how to edit the HL field
   * "value" value used to operate on HL
   * "mode"  how the value should be used. Options are
   * * "IP6T_HL_SET" : sets HL field to "value"
   * * "IP6T_HL_INC" : increments HL by "value"
   * * "IP6T_HL_DEC" : decrements HL by "value"
   */
  void setEdit(unsigned char value, unsigned char mode);

  /* Returns target specs */
  ip6t_hl_target getSpecs();

  private:
  ip6t_hl_target specs;
};

/**
 * Used for Network Prefix Translation for IPv6 packets
 * Only valid in mangle table
 */
class NptTarget : Target{
  public:
  /* Constructors */
  NptTarget();
  NptTarget(string src, string dst);

  /**
   * Define how the translation will work
   * "src" ip prefix you want to translate and length. In form prefix/length
   * "dst" ip prefix you want to use in translation. In form prefix/length
   */
  void setTranslate(string src, string dst);

  /* Returns target specs */
  ip6t_npt_target getSpecs();

  private:
  ip6t_npt_target specs;
};

/**
 * Works like DROP but sends back a error packet.
 * Only valid in INPUT, FOWARD, and OUTPUT chains
 */
class RejectIP6Target : Target{
  public:
  /* Constructors */
  RejectIP6Target();
  RejectIP6Target(ip6t_reject_with type);

  /**
   * Sets what error message will send. Types prefixed with "IP6T_ICMP6_" are
   * NOROUTE, NOT_NEIGHBOR, ADDR_UNREACH, PORT_UNREACH, ECHOREPLY,
   * POLICY_FAIL, REJECT_ROUTE, ADM_PROHIBITED.
   * IP6T_TCP_RESET is also an option but requires matching tcp protocol
   */
  void setType(ip6t_reject_with type);

  /* Returns target specs */
  ip6t_reject_target getSpecs();

  private:
  ip6t_reject_target specs;
};

#endif
