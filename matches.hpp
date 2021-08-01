#ifndef MATCH_H
#define MATCH_H

#include <string>
#include <nlohmann/json.hpp>
#include "match_headers.hpp"

using json = nlohmann::json;
using string = std::string;

typedef xt_addrtype_info_v1 xt_addrtype_match;
typedef xt_bpf_info_v1 xt_bpf_match;
typedef xt_cgroup_info_v2 xt_cgroup_match;
typedef xt_cluster_match_info xt_cluster_match;
typedef xt_comment_info xt_comment_match;
typedef xt_tcp xt_tcp_match;
typedef xt_udp xt_udp_match;
typedef ipt_icmp ipt_icmp_match;
typedef ip6t_icmp ip6t_icmp_match;

#if 0
class Temp2Match : public TemplateMatch<xt_temp2_match>{
  /* Constructors */
  Temp2Match();
  Temp2Match(args);

  /* Setters */

  /* Returns name of match */
  string getName() const;
};

#endif

class Match{
  public:
  /* Returns name of match */
  virtual string getName() const = 0;
  /* Returns size of match */
  virtual unsigned int getSize() const = 0;
  /* Returns pointer to match specifications */
  virtual const void* getSpecs() const = 0;
  /* Returns this object in json format */
  virtual json asJson() const = 0;
};

template<class T>
class TemplateMatch : public Match{
  public:
  /* Constructor */
  TemplateMatch(){}
  TemplateMatch(const T* s) { memcpy(&specs, s, getSize()); }
  /* Returns size of struct */
  unsigned int getSize() const{ return sizeof(T); }
  /* Returns pointer to match specifications */
  const void* getSpecs() const{ return &specs; }

  protected:
  T specs;
};

class AddrtypeMatch : public TemplateMatch<xt_addrtype_match>{
  public:
  /* Constructors */
  AddrtypeMatch();
  AddrtypeMatch(unsigned short src, unsigned short dst);
  AddrtypeMatch(xt_addrtype_match* s) : TemplateMatch<xt_addrtype_match>(s) {}
  AddrtypeMatch(json j);

  /** 
   * Sets address type of source/destination ip, address types prefixed with "XT_ADDRTYPE_" are:
   * UNSPEC, UNICAST, LOCAL, BROADCAST, ANYCAST, MULTICAST, BLACKHOLE, UNREACHABLE, PROHIBIT,
   * THROW, NAT, and XRESOLVE
   * "src" Source address type
   * "dst" Destination address type
   * "inv" Set to true to inverse sense of source/destination address type
   */
  void setSrc(unsigned short src, bool inv = false);
  void setDst(unsigned short dst, bool inv = false);

  /* Limits matching to incoming interface */
  void limitIFace();
  /* Limits matching to outgoing interface */
  void limitOFace();

  /* Returns name of match */
  string getName() const;
  /* Returns this object in json format */
  virtual json asJson() const;
};

class BpfMatch : public TemplateMatch<xt_bpf_match>{
  public:
  /* Constructors */
  BpfMatch();
  BpfMatch(xt_bpf_match* s) : TemplateMatch<xt_bpf_match>(s) {}
  BpfMatch(json j);

  /* Sets program path of BPF object */
  void setPath(string progPath);
  /* Sets path of pinned BPF program */
  void setPinPath(string progPath);
  /* Sets byte code of a BPF program */
  void setProg(string code);

  /* Returns name of match */
  string getName() const;
  /* Returns this object in json format */
  virtual json asJson() const;

  private:
  sock_fprog strToCode(string code) const;
};

class CgroupMatch : public TemplateMatch<xt_cgroup_match>{
  public:
  /* Constructors */
  CgroupMatch();
  CgroupMatch(string path, bool inv = false);
  CgroupMatch(unsigned int classid, bool inv = false);
  CgroupMatch(xt_cgroup_match* s) : TemplateMatch<xt_cgroup_match>(s) {}
  CgroupMatch(json j);

  /* Sets path of cgroup2 membership */
  void setPath(string path, bool inv = false);
  /* Sets cgroup net_cls classid */
  void setClassId(unsigned int classid, bool inv = false);

  /* Returns name of match */
  string getName() const;
  /* Returns this object in json format */
  virtual json asJson() const;
};

class ClusterMatch : public TemplateMatch<xt_cluster_match>{
  public:
  /* Constuctors */
  ClusterMatch();
  ClusterMatch(unsigned int total, unsigned int nodeMask, unsigned int hashSeed);
  ClusterMatch(xt_cluster_match* s) : TemplateMatch<xt_cluster_match>(s) {}
  ClusterMatch(json j);

  /* Sets total number of nodes */
  void setNumNodes(unsigned int total);
  /* Sets local node mask */
  void setNodeMask(unsigned int nodeMask);
  /* Sets seed of Jenkins hash */
  void setSeed(unsigned int hashSeed);
  
  /* Inverts node mask */
  void invertMask();

  /* Returns name of match */
  string getName() const;
  /* Returns this object in json format */
  virtual json asJson() const;
};

class CommentMatch : public TemplateMatch<xt_comment_match>{
  public:
  /* Constructor */
  CommentMatch();
  CommentMatch(string comment);
  CommentMatch(xt_comment_match* s) : TemplateMatch<xt_comment_match>(s) {}
  CommentMatch(json j);

  /* Sets comment */
  void setComment(string comment);

  /* Returns name of match */
  string getName() const;
  /* Returns this object in json format */
  virtual json asJson() const;
};

// Tcp flags
enum {
  FIN = 1 << 0,
  SYN = 1 << 1,
  RST = 1 << 2,
  PSH = 1 << 3,
  ACK = 1 << 4,
  URG = 1 << 5,
  ECN = 1 << 6,
  CWR = 1 << 7
};


class TcpMatch : public TemplateMatch<xt_tcp_match>{
  public:
  /* Constructors */
  TcpMatch();
  TcpMatch(xt_tcp_match* s) : TemplateMatch<xt_tcp_match>(s) {}
  TcpMatch(json j);

  /**
   * Sets range of source ports to match
   * "first" first port in range
   * "last" last port in range
   * "inv" set true to invert sense of source ports
   */
  void setSrcPorts(unsigned short first, unsigned short last, bool inv = false);

  /**
   * Sets range of destination ports to match
   * "first" first port in range
   * "last" last port in range
   * "inv" set true to invert sense of destination ports
   */
  void setDstPorts(unsigned short first, unsigned short last, bool inv = false);

  /**
   * Sets tcp option to match if option is set
   * "num" option to match
   * "inv" set to true to invert sense of options test
   */
  void setOptions(unsigned char num, bool inv = false);

  /**
   * Set tcp flags to match against
   * "mask" flags to examine
   * "cmp" flags to be set to match
   * "inv" set to true to invert sense of flags
   */
  void setFlags(unsigned char mask, unsigned char cmp, bool inv = false);

  /* Returns name of match */
  string getName() const;
  /* Returns this object in json format */
  virtual json asJson() const;
};

class UdpMatch : public TemplateMatch<xt_udp_match>{
  public:
  /* Constructors */
  UdpMatch();
  UdpMatch(xt_udp_match* s) : TemplateMatch<xt_udp_match>(s) {}
  UdpMatch(json j);

  /**
   * Sets range of source ports to match
   * "first" first port in range
   * "last" last port in range
   * "inv" set true to invert sense of source ports
   */
  void setSrcPorts(unsigned short first, unsigned short last, bool inv = false);

  /**
   * Sets range of destination ports to match
   * "first" first port in range
   * "last" last port in range
   * "inv" set true to invert sense of destination ports
   */
  void setDstPorts(unsigned short first, unsigned short last, bool inv = false);

  /* Returns name of match */
  string getName() const;
  /* Returns this object in json format */
  virtual json asJson() const;
};

// ICMP types
enum Icmp4Type : unsigned char{
  ECHO_REPLY = 0,
  DEST_UNREA = 3,
  SRC_QUENCH = 4,
  REDIRECT   = 5,
  ECHO       = 8,
  ROUTER_ADV = 9,
  ROUTER_SEL = 10,
  TIME_EXCEE = 11,
  PARAM_PROB = 12,
  TIMSTMP    = 13,
  TIMSTMP_RE = 14,
  INFO_REQUE = 15,
  INFO_REPLY = 16,
  ADDR_M_REQ = 17,
  ADDR_M_RPL = 18,
  TRACEROUTE = 30
};

// Destination unreachable codes
enum {
  NET_UNREACH = 0,
  HST_UNREACH,
  PRO_UNREACH,
  POR_UNREACH,
  FRAG_NEEDED,
  SRC_RT_FAIL,
  DST_NET_UNK,
  DST_HST_UNK,
  SRC_HST_ISO,
  DST_NET_PRO,
  DST_HST_PRO,
  NET_UNR_TOS,
  HST_UNR_TOS,
  ADMIN_PROHI,
  PRECED_VIOL,
  PRECED_CUTO
};

// Redirect codes
enum {
  NETWORK = 0,
  HOST,
  TOS_NET,
  TOS_HST
};

// Time exceeded codes
enum {
  TTL_EXCEED = 0,
  FRG_EXCEED
};

// Parameter problems codes
enum {
  PNTR_ERR = 0,
  MISS_OPT,
  BAD_LEN
};

class Icmp4Match : public TemplateMatch<ipt_icmp_match>{
  public:
  /* Constructors */
  Icmp4Match();
  Icmp4Match(Icmp4Type type, bool inv = false);
  Icmp4Match(Icmp4Type type, unsigned char code, bool inv = false);
  Icmp4Match(Icmp4Type type, unsigned char first, unsigned char last, bool inv = false);
  Icmp4Match(ipt_icmp_match* s) : TemplateMatch<ipt_icmp_match>(s) {}
  Icmp4Match(json j);

  /** 
   * Sets type of icmp packet to match
   * "type" type to match
   * "inv" set to true to invert sense of type
   */
  void setType(Icmp4Type type, bool inv = false);

  /**
   * Sets type and code(s) of icmp packet to match
   * "type" type to match
   * "code" code to match for it specified type
   * "first" first code in range to match
   * "last" last code in range to match
   * "inv" set to true to invert sense of type/code test
   */
  void setTypeCode(Icmp4Type type, unsigned char code, bool inv = false);
  void setTypeCode(Icmp4Type type, unsigned char first, unsigned char last, bool inv = false);

  /* Returns name of match */
  string getName() const;
  /* Returns this object in json format */
  virtual json asJson() const;
};

enum Icmp6Type{
  DEST_UNREACH = 1,
  PCKT_TOO_BIG = 2,
  TIME_EXCEED  = 3,
  PARAM_PROBLM = 4,
  IP6ECHO      = 128,
  IP6ECHO_REPL = 129,
  ROUTER_SOLIC = 133,
  ROUTER_ADVER = 134,
  NEIGHB_SOLIC = 135,
  NEIGHB_ADVER = 136,
  REDIRECTIP6  = 137
};

// Destination unreachable codes
enum {
  NO_ROUTE = 0,
  ADM_PROH,
  NOT_ASGN,
  ADDR_UNR,
  PORT_UNR
};

// Time limit exceeded codes
enum {
  HL_EXCEED = 0,
  FRAG_EXCEED
};

// Parameter problem codes
enum {
  ERR_HEAD = 0,
  UNR_HEAD,
  UNR_OPT
};

class Icmp6Match : public TemplateMatch<ip6t_icmp_match>{
  public:
  /* Constructors */
  Icmp6Match();
  Icmp6Match(Icmp6Type type, bool inv = false);
  Icmp6Match(Icmp6Type type, unsigned char code, bool inv = false);
  Icmp6Match(Icmp6Type type, unsigned char first, unsigned char last, bool inv = false);
  Icmp6Match(ip6t_icmp_match* s) : TemplateMatch<ip6t_icmp_match>(s) {}
  Icmp6Match(json j);

  /** 
   * Sets type of icmp packet to match
   * "type" type to match
   * "inv" set to true to invert sense of type
   */
  void setType(Icmp6Type type, bool inv = false);

  /**
   * Sets type and code(s) of icmp packet to match
   * "type" type to match
   * "code" code to match for it specified type
   * "first" first code in range to match
   * "last" last code in range to match
   * "inv" set to true to invert sense of type/code test
   */
  void setTypeCode(Icmp6Type type, unsigned char code, bool inv = false);
  void setTypeCode(Icmp6Type type, unsigned char first, unsigned char last, bool inv = false);

  /* Returns name of match */
  string getName() const;
  /* Returns this object in json format */
  virtual json asJson() const;
};

#endif
