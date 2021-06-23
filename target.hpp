#ifndef TARGETS_H
#define TARGETS_H

#include "target_headers.h"
typedef xt_audit_target xt_audit_info;
typedef xt_checksum_target xt_CHECKSUM_info;
typedef xt_classify_target xt_classify_target_info;
typedef xt_connmark_target xt_connmark_tginfo1;
typedef xt_connsecmark_target xt_connsecmark_target_info;
typedef xt_ct_target xt_ct_target_info_v1;
typedef xt_dscp_target xt_DSCP_info;
typedef xt_tos_target xt_tos_target_info;
typedef xt_hmark_target xt_hmark_info;

#if 0
class TemplateTarget : Target{
  public:
  /* Constructors */
  TemplateTarget();
  TemplateTarget(args);

  /* Setter functions */

  /* Returns target specs */
  xt_template_target getSpecs();

  private:
  xt_template_target specs;
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
  AuditTarget(unsigned char type)

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
  xt_connmark_target specs
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
  CTTarget(bool noTrack);
  CTTarget(string helper);
  CTTarget(string timeout);
  CTTarget(unsigned int ctEvents);
  CTTarget(unsigned int expEvents);
  CTTarget(unsigned char flags, unsigned int zone);

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

#endif
