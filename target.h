#ifndef TARGET_H
#define TARGET_H

#include "target_headers.h"
typedef xt_audit_target xt_audit_info
typedef xt_checksum_target xt_CHECKSUM_info
typedef xt_classify_target xt_classify_target_info
typedef xt_connmark_target xt_connmark_tginfo1

class Target{
  public:
  /* Returns name of target */
  virtual string getName() = 0;
};

class AuditTarget : Target{
  public:
  /* Constuctors */
  AuditTarget();
  AuditTarget(char type)

  /**
   * Sets the type of audit record. Depracated and has no effect on messages since linux-4.12
   * "type" can be the macro XT_AUDIT_TYPE_* where * is ACCEPT, DROP, or REJECT
   */
  void setType(char type);

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
  ClassifyTarget(int major, int minor);

  /**
   * Sets the major and minor class values of the CBQ class
   * "major" the major class value
   * "minor" the minor class value
   */
  void setClass(int major, int minor);

  /* Returns target specs */
  xt_classify_target getSpecs();

  private:
  xt_classify_target specs;
};

class ConnmarkTarget : Target{
  /* Constructors */
  ConnmarkTarget();
  ConnmarkTarget(char mode, int ctmark, int ctmask, int nfmask);

  /**
   * Zeros bit give by mask and XOR ctmark with value
   * "value" bit XORed with ctmark
   * "mask" bits to zero out
   */
  void setMark(int value, int mask);

  /**
   * Copy the packet nfmark to the ctmark with masks. Equation used is
   * ctmark = (ctmark * ~ctmask) ^ (nfmark & nfmask)
   * "ctmask" value of the ctmask
   * "nfmask" value of nfmask
   */
  void saveMark(int ctmask, int nfmask);

  /**
   * Copy the packet ctmark to the nfmark with give masks. Equation used is
   * nfmark = (nfmark & ~ nfmask) ^ (ctmark & ctmask)
   * Can only be used in mangle table
   * "ctmask" value of ctmask
   * "nfmask" value of nfmask
   */
  void restoreMark(int ctmask, int nfmask);

  /* Return target specs */
  xt_connmark_target getSpecs();

  private:
  xt_connmark_target specs
};

#endif
