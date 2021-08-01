#include <stdexcept>
#include <cstring>
#include <fcntl.h>
#include "matches.hpp"

typedef std::runtime_error runtime_error;

AddrtypeMatch::AddrtypeMatch(){
  setSrc(XT_ADDRTYPE_UNSPEC);
  setDst(XT_ADDRTYPE_UNSPEC);
  this->specs.flags = 0;
}

AddrtypeMatch::AddrtypeMatch(unsigned short src, unsigned short dst){
  setSrc(src);
  setDst(dst);
  this->specs.flags = 0;
}

AddrtypeMatch::AddrtypeMatch(json j){
  this->specs.source = j["source"].get<unsigned short>();
  this->specs.dest = j["dest"].get<unsigned short>();
  this->specs.flags = j["flags"].get<unsigned>();
}

void AddrtypeMatch::setSrc(unsigned short src, bool inv){
  if(src < (1 << 12) && src > 0)
    this->specs.source = src;
  else
    throw runtime_error("Addrtype match address type not recognized");
  if(inv)
    this->specs.flags |= XT_ADDRTYPE_INVERT_SOURCE;
}

void AddrtypeMatch::setDst(unsigned short dst, bool inv){
  if(dst < (1 << 12) && dst > 0)
    this->specs.dest = dst;
  else
    throw runtime_error("Addrtype match address type not recognized");
  if(inv)
    this->specs.flags |= XT_ADDRTYPE_INVERT_DEST;
}

void AddrtypeMatch::limitIFace(){
  this->specs.flags |= XT_ADDRTYPE_LIMIT_IFACE_IN;
}

void AddrtypeMatch::limitOFace(){
  this->specs.flags |= XT_ADDRTYPE_LIMIT_IFACE_OUT;
}

string AddrtypeMatch::getName() const{
  return "addrtype";
}

json AddrtypeMatch::asJson() const{
  json j;
  j["source"] = this->specs.source;
  j["dest"] = this->specs.dest;
  j["flags"] = this->specs.flags;
  return j;
}

BpfMatch::BpfMatch(){
  this->specs.mode = 0;
  this->specs.bpf_program_num_elem = 0;
  this->specs.fd = 0;
  memset(this->specs.path, 0, XT_BPF_PATH_MAX);
}

BpfMatch::BpfMatch(json j){
  this->specs.mode = j["mode"].get<unsigned short>();
  this->specs.bpf_program_num_elem = j["bpf_program_num_elem"].get<unsigned short>();
  this->specs.fd = j["fd"].get<int>();
  strcpy(this->specs.path, j["path"].get<string>().c_str());
}

void BpfMatch::setPath(string progPath){
  strncpy(this->specs.path, progPath.c_str(), XT_BPF_PATH_MAX);
  this->specs.mode = XT_BPF_MODE_FD_ELF;
  this->specs.fd = open(progPath.c_str(), O_RDONLY);
}

void BpfMatch::setPinPath(string progPath){
  strncpy(this->specs.path, progPath.c_str(), XT_BPF_PATH_MAX);
  this->specs.mode = XT_BPF_MODE_FD_PINNED;
  this->specs.fd = open(progPath.c_str(), O_RDONLY);
}

void BpfMatch::setProg(string code){
  this->specs.mode = XT_BPF_MODE_BYTECODE;
  sock_fprog prog = strToCode(code);
  if(prog.len < XT_BPF_MAX_NUM_INSTR)
    throw runtime_error("BPF program size to large");
  this->specs.bpf_program_num_elem = prog.len;
  memcpy(this->specs.bpf_program, prog.filter, prog.len * sizeof(sock_filter));
}

json BpfMatch::asJson() const{
  json j;
  j["mode"] = this->specs.mode;
  j["bpf_program_num_elem"] = this->specs.bpf_program_num_elem;
  j["fd"] = this->specs.fd;
  j["path"] = string(this->specs.path);
  return j;
}


string BpfMatch::getName() const{
  return "bpf";
}

sock_fprog BpfMatch::strToCode(string code) const{
  sock_fprog ret;
  int pos = code.find(',');
  ret.len = stoul(code.substr(0, pos));
  ret.filter = new sock_filter[ret.len];
  for(int i = 0, j = ++pos; i < ret.len; i++, j = ++pos){
    pos = code.find(' ', j);
    ret.filter[i].code = stoul(code.substr(j, pos));
    j = ++pos;
    pos = code.find(' ', j);
    ret.filter[i].jt = stoul(code.substr(j,pos));
    j = ++pos;
    pos = code.find(' ', j);
    ret.filter[i].jf = stoul(code.substr(j,pos));
    j = ++pos;
    pos = code.find(',', j);
    ret.filter[i].k = stoul(code.substr(j,pos));
  }
  return ret;
}

CgroupMatch::CgroupMatch(){
  this->specs.has_path = 0;
  this->specs.has_classid = 0;
  this->specs.invert_path = 0;
  this->specs.invert_classid = 0;
  memset(this->specs.path, 0, XT_CGROUP_PATH_MAX);
}

CgroupMatch::CgroupMatch(json j){
  this->specs.has_path = j["has_path"].get<bool>();
  this->specs.has_classid = j["has_classid"].get<bool>();
  this->specs.invert_path = j["invert_path"].get<bool>();
  this->specs.invert_classid = j["invert_classid"].get<bool>();
  strcpy(this->specs.path, j["path"].get<string>().c_str());
}

CgroupMatch::CgroupMatch(string path, bool inv){
  setPath(path, inv);
}

CgroupMatch::CgroupMatch(unsigned classid, bool inv){
  setClassId(classid, inv);
}

json CgroupMatch::asJson() const{
  json j;
  j["has_path"] = this->specs.has_path;
  j["has_classid"] = this->specs.has_classid;
  j["invert_path"] = this->specs.invert_path;
  j["invert_classid"] = this->specs.invert_classid;
  j["path"] = string(this->specs.path);
  return j;
}

void CgroupMatch::setPath(string path, bool inv){
  this->specs.has_path = 1;
  this->specs.has_classid = 0;
  this->specs.invert_path = inv;
  this->specs.invert_classid = 0;
  strncpy(this->specs.path, path.c_str(), XT_CGROUP_PATH_MAX);
}

void CgroupMatch::setClassId(unsigned classid, bool inv){
  this->specs.has_path = 0;
  this->specs.has_classid = 1;
  this->specs.invert_path = 0;
  this->specs.invert_classid = inv;
  this->specs.classid = classid;
}

string CgroupMatch::getName() const{
  return "cgroup";
}

ClusterMatch::ClusterMatch(){
  setNumNodes(0);
  setNodeMask(0);
  setSeed(0);
  this->specs.flags = 0;
}

ClusterMatch::ClusterMatch(unsigned total, unsigned nodeMask, unsigned hashSeed){
  setNumNodes(total);
  setNodeMask(nodeMask);
  setSeed(hashSeed);
  this->specs.flags = 0;
}

ClusterMatch::ClusterMatch(json j){
  this->specs.total_nodes = j["total_nodes"].get<unsigned>();
  this->specs.node_mask = j["node_mask"].get<unsigned>();
  this->specs.hash_seed = j["hash_seed"].get<unsigned>();
  this->specs.flags = j["flags"].get<unsigned>();
}

json ClusterMatch::asJson() const{
  json j;
  j["total_nodes"] = this->specs.total_nodes;
  j["node_mask"] = this->specs.node_mask;
  j["hash_seed"] = this->specs.hash_seed;
  j["flags"] = this->specs.flags;
  return j;
}

void ClusterMatch::setNumNodes(unsigned total){
  this->specs.total_nodes = total;
}

void ClusterMatch::setNodeMask(unsigned nodeMask){
  this->specs.node_mask = nodeMask;
}

void ClusterMatch::setSeed(unsigned hashSeed){
  this->specs.hash_seed = hashSeed;
}

void ClusterMatch::invertMask(){
  this->specs.flags = XT_CLUSTER_F_INV;
}

string ClusterMatch::getName() const{
  return "cluster";
}

CommentMatch::CommentMatch(){
  memset(this->specs.comment, 0, XT_MAX_COMMENT_LEN);
}

CommentMatch::CommentMatch(string comment){
  setComment(comment);
}

CommentMatch::CommentMatch(json j){
  strcpy(this->specs.comment, j["comment"].get<string>().c_str());
}

void CommentMatch::setComment(string comment){
  strncpy(this->specs.comment, comment.c_str(), XT_MAX_COMMENT_LEN);
}

json CommentMatch::asJson() const{
  json j;
  j["comment"] = string(this->specs.comment);
  return j;
}

string CommentMatch::getName() const{
  return "comment";
}

TcpMatch::TcpMatch(){
  this->specs.spts[0] = 0;
  this->specs.spts[1] = 0xffff;
  this->specs.dpts[0] = 0;
  this->specs.dpts[1] = 0xffff;
  this->specs.option = 0;
  this->specs.flg_mask = 0;
  this->specs.flg_cmp = 0;
  this->specs.invflags = 0;
}

TcpMatch::TcpMatch(json j){
  this->specs.spts[0] = j["spts"][0].get<unsigned short>();
  this->specs.spts[1] = j["spts"][1].get<unsigned short>();
  this->specs.dpts[0] = j["dpts"][0].get<unsigned short>();
  this->specs.dpts[1] = j["dpts"][1].get<unsigned short>();
  this->specs.invflags = j["invflags"].get<unsigned char>();
  this->specs.option = j["option"].get<unsigned char>();
  this->specs.flg_mask = j["flg_mask"].get<unsigned char>();
  this->specs.flg_cmp = j["flg_cmp"].get<unsigned char>();
}

void TcpMatch::setSrcPorts(unsigned short first, unsigned short last, bool inv){
  if(first <= last){
    this->specs.spts[0] = first;
    this->specs.spts[1] = last;
  }
  else{
    this->specs.spts[0] = last;
    this->specs.spts[1] = first;
  }
  if(inv)
    this->specs.invflags |= XT_TCP_INV_SRCPT;
}

void TcpMatch::setDstPorts(unsigned short first, unsigned short last, bool inv){
  if(first <= last){
    this->specs.dpts[0] = first;
    this->specs.dpts[1] = last;
  }
  else{
    this->specs.dpts[0] = last;
    this->specs.dpts[1] = first;
  }
  if(inv)
    this->specs.invflags |= XT_TCP_INV_DSTPT;
}

void TcpMatch::setOptions(unsigned char num, bool inv){
  this->specs.option = num;
  if(inv)
    this->specs.invflags |= XT_TCP_INV_OPTION;
}

void TcpMatch::setFlags(unsigned char mask, unsigned char cmp, bool inv){
  if(mask < cmp)
    throw runtime_error("TCP flag mask/cmp improperly set");
  this->specs.flg_mask = mask;
  this->specs.flg_cmp = cmp;
  if(inv)
    this->specs.invflags |= XT_TCP_INV_FLAGS;
}

string TcpMatch::getName() const{
  return "tcp";
}

json TcpMatch::asJson() const{
  json j;
  j["option"] = this->specs.option;
  j["flg_mask"] = this->specs.flg_mask;
  j["flg_cmp"] = this->specs.flg_cmp;
  j["invflags"] = this->specs.invflags;
  j["spts"][0] = this->specs.spts[0];
  j["spts"][1] = this->specs.spts[1];
  j["dpts"][0] = this->specs.dpts[0];
  j["dpts"][1] = this->specs.dpts[1];
  return j;
}

UdpMatch::UdpMatch(){
  setSrcPorts(0, 0xffff);
  setDstPorts(0, 0xffff);
  this->specs.invflags = 0;
}

UdpMatch::UdpMatch(json j){
  this->specs.spts[0] = j["spts"][0].get<unsigned short>();
  this->specs.spts[1] = j["spts"][1].get<unsigned short>();
  this->specs.dpts[0] = j["dpts"][0].get<unsigned short>();
  this->specs.dpts[1] = j["dpts"][1].get<unsigned short>();
  this->specs.invflags = j["invflags"].get<unsigned char>();
}
 
void UdpMatch::setSrcPorts(unsigned short first, unsigned short last, bool inv){
  if(first <= last){
    this->specs.spts[0] = first;
    this->specs.spts[1] = last;
  }
  else{
    this->specs.spts[0] = last;
    this->specs.spts[1] = first;
  }
  if(inv)
    this->specs.invflags |= XT_UDP_INV_SRCPT;
}

void UdpMatch::setDstPorts(unsigned short first, unsigned short last, bool inv){
  if(first <= last){
    this->specs.dpts[0] = first;
    this->specs.dpts[1] = last;
  }
  else{
    this->specs.dpts[0] = last;
    this->specs.dpts[1] = first;
  }
  if(inv)
    this->specs.invflags |= XT_UDP_INV_DSTPT;
}

string UdpMatch::getName() const{
  return "udp";
}

json UdpMatch::asJson() const{
  json j;
  j["invflags"] = this->specs.invflags;
  j["spts"][0] = this->specs.spts[0];
  j["spts"][1] = this->specs.spts[1];
  j["dpts"][0] = this->specs.dpts[0];
  j["dpts"][1] = this->specs.dpts[1];
  return j;
}


Icmp4Match::Icmp4Match(){
  this->specs.type = 0;
  memset(this->specs.code, 0, 2);
  this->specs.invflags = 0;
}

Icmp4Match::Icmp4Match(Icmp4Type type, bool inv){
  memset(this->specs.code, 0, 2);
  this->specs.invflags = 0;
  setType(type, inv);
}

Icmp4Match::Icmp4Match(Icmp4Type type, unsigned char code, bool inv){
  memset(this->specs.code, 0, 2);
  this->specs.invflags = 0;
  setTypeCode(type, code, inv);
}

Icmp4Match::Icmp4Match(Icmp4Type type, unsigned char first, unsigned char last, bool inv){
  memset(this->specs.code, 0, 2);
  this->specs.invflags = 0;
  setTypeCode(type, first, last, inv);
}

Icmp4Match::Icmp4Match(json j){
  this->specs.code[0] = j["code"][0].get<unsigned char>();
  this->specs.code[1] = j["code"][0].get<unsigned char>();
  this->specs.invflags = j["invflags"].get<unsigned char>();
  this->specs.type = j["type"].get<unsigned char>();
}

void Icmp4Match::setType(Icmp4Type type, bool inv){
  this->specs.type = type;
  switch(type){
    DEST_UNREA:
      this->specs.code[0] = NET_UNREACH; 
      this->specs.code[1] = PRECED_CUTO;
      break;
    REDIRECT:
      this->specs.code[0] = NETWORK;
      this->specs.code[1] = TOS_HST;
      break;
    TIME_EXCEE:
      this->specs.code[0] = TTL_EXCEED;
      this->specs.code[1] = FRG_EXCEED;
      break;
    PARAM_PROB:
      this->specs.code[0] = PNTR_ERR;
      this->specs.code[1] = BAD_LEN;
      break;
    default:
      break;
  }
  if(inv)
    this->specs.invflags |= IPT_ICMP_INV;
}

void Icmp4Match::setTypeCode(Icmp4Type type, unsigned char code, bool inv){
  this->specs.type = type;
  switch(type){
    DEST_UNREA:
      if(code <= PRECED_CUTO)
	memset(this->specs.code, code, 2);
      else
	throw runtime_error("Unrecognized icmp4 destination unreachable code");
      break;
    REDIRECT:
      if(code <= TOS_HST)
	memset(this->specs.code, code, 2);
      else
	throw runtime_error("Unrecognized icmp4 redirect code");
      break;
    TIME_EXCEE:
      if(code <= FRG_EXCEED)
	memset(this->specs.code, code, 2);
      else
	throw runtime_error("Unrecognized icmp4 time exceeded code");
      break;
    PARAM_PROB:
      if(code <= BAD_LEN)
	memset(this->specs.code, code, 2);
      else
	throw runtime_error("Unrecognized icmp4 parameter problem code");
      break;
    default:
      break;
  }
  if(inv)
    this->specs.invflags |= IPT_ICMP_INV;
}

void Icmp4Match::setTypeCode(Icmp4Type type, unsigned char first, unsigned char last, bool inv){
  this->specs.type = type;
  switch(type){
    DEST_UNREA:
      if(first <= PRECED_CUTO && last <= PRECED_CUTO){
	if(first <= last){
	  this->specs.code[0] = first;
	  this->specs.code[1] = last;
	}
	else{
	  this->specs.code[1] = first;
	  this->specs.code[0] = last;
	}
      }
      else
	throw runtime_error("Unrecognized icmp4 destination unreachable code");
      break;
    REDIRECT:
      if(first <= TOS_HST && last <= TOS_HST){
	if(first <= last){
	  this->specs.code[0] = first;
	  this->specs.code[1] = last;
	}
	else{
	  this->specs.code[1] = first;
	  this->specs.code[0] = last;
	}      
      }
      else
	throw runtime_error("Unrecognized icmp4 redirect code");
      break;
    TIME_EXCEE:
      if(first <= FRG_EXCEED && last <= FRG_EXCEED){
	if(first <= last){
	  this->specs.code[0] = first;
	  this->specs.code[1] = last;
	}
	else{
	  this->specs.code[1] = first;
	  this->specs.code[0] = last;
	}      
      }
      else
	throw runtime_error("Unrecognized icmp4 time exceeded code");
      break;
    PARAM_PROB:
      if(first <= BAD_LEN && last <= BAD_LEN){
	if(first <= last){
	  this->specs.code[0] = first;
	  this->specs.code[1] = last;
	}
	else{
	  this->specs.code[1] = first;
	  this->specs.code[0] = last;
	}      
      }
      else
	throw runtime_error("Unrecognized icmp4 parameter problem code");
      break;
    default:
      break;
  }
  if(inv)
    this->specs.invflags |= IPT_ICMP_INV;
}

string Icmp4Match::getName() const{
  return "icmp";
}

json Icmp4Match::asJson() const{
  json j;
  j["type"] = this->specs.type;
  j["invflags"] = this->specs.invflags;
  j["code"][0] = this->specs.code[0];
  j["code"][1] = this->specs.code[1];
  return j;
}

Icmp6Match::Icmp6Match(){
  this->specs.type = 0;
  memset(this->specs.code, 0, 2);
  this->specs.invflags = 0;
}

Icmp6Match::Icmp6Match(Icmp6Type type, bool inv){
  memset(this->specs.code, 0, 2);
  this->specs.invflags = 0;
  setType(type, inv);
}

Icmp6Match::Icmp6Match(Icmp6Type type, unsigned char code, bool inv){
  memset(this->specs.code, 0, 2);
  this->specs.invflags = 0;
  setTypeCode(type, code, inv);
}

Icmp6Match::Icmp6Match(Icmp6Type type, unsigned char first, unsigned char last, bool inv){
  memset(this->specs.code, 0, 2);
  this->specs.invflags = 0;
  setTypeCode(type, first, last, inv);
}

Icmp6Match::Icmp6Match(json j){
  this->specs.code[0] = j["code"][0].get<unsigned char>();
  this->specs.code[1] = j["code"][0].get<unsigned char>();
  this->specs.invflags = j["invflags"].get<unsigned char>();
  this->specs.type = j["type"].get<unsigned char>();
}

void Icmp6Match::setType(Icmp6Type type, bool inv){
  this->specs.type = type;
  switch(type){
    DEST_UNREACH:
      this->specs.code[0] = NO_ROUTE;
      this->specs.code[1] = PORT_UNR;
      break;
    TIME_EXCEED:
      this->specs.code[0] = HL_EXCEED;
      this->specs.code[1] = FRAG_EXCEED;
      break;
    PARAM_PROBLM:
      this->specs.code[0] = ERR_HEAD; 
      this->specs.code[1] = UNR_OPT;
      break;
    default:
      break;
  }
  if(inv)
    this->specs.invflags |= IPT_ICMP_INV;
}

void Icmp6Match::setTypeCode(Icmp6Type type, unsigned char code, bool inv){
  this->specs.type = type;
  switch(type){
    DEST_UNREACH:
      if(code <= PORT_UNR)
	memset(this->specs.code, code, 2);
      else
	throw runtime_error("Unrecognized icmp4 destination unreachable code");
      break;
    TIME_EXCEED:
      if(code <= FRAG_EXCEED)
	memset(this->specs.code, code, 2);
      else
	throw runtime_error("Unrecognized icmp4 time exceeded code");
      break;
    PARAM_PROBLM:
      if(code <= UNR_OPT)
	memset(this->specs.code, code, 2);
      else
	throw runtime_error("Unrecognized icmp4 parameter problem code");
      break;
    default:
      break;
  }
  if(inv)
    this->specs.invflags |= IPT_ICMP_INV;
}

void Icmp6Match::setTypeCode(Icmp6Type type, unsigned char first, unsigned char last, bool inv){
  this->specs.type = type;
  switch(type){
    DEST_UNREACH:
      if(first <= PORT_UNR && last <= PORT_UNR){
	if(first <= last){
	  this->specs.code[0] = first;
	  this->specs.code[1] = last;
	}
	else{
	  this->specs.code[1] = first;
	  this->specs.code[0] = last;
	}
      }
      else
	throw runtime_error("Unrecognized icmp4 destination unreachable code");
      break;
   TIME_EXCEED:
      if(first <= FRAG_EXCEED && last <= FRAG_EXCEED){
	if(first <= last){
	  this->specs.code[0] = first;
	  this->specs.code[1] = last;
	}
	else{
	  this->specs.code[1] = first;
	  this->specs.code[0] = last;
	}      
      }
      else
	throw runtime_error("Unrecognized icmp4 time exceeded code");
      break;
    PARAM_PROBLM:
      if(first <= UNR_OPT && last <= UNR_OPT){
	if(first <= last){
	  this->specs.code[0] = first;
	  this->specs.code[1] = last;
	}
	else{
	  this->specs.code[1] = first;
	  this->specs.code[0] = last;
	}      
      }
      else
	throw runtime_error("Unrecognized icmp4 parameter problem code");
      break;
    default:
      break;
  }
  if(inv)
    this->specs.invflags |= IPT_ICMP_INV;
}

string Icmp6Match::getName() const{
  return "icmp6";
}

json Icmp6Match::asJson() const{
  json j;
  j["type"] = this->specs.type;
  j["invflags"] = this->specs.invflags;
  j["code"][0] = this->specs.code[0];
  j["code"][1] = this->specs.code[1];
  return j;
}
