#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <xtables.h>
#include "firewall.hpp"
#include "strToIp.hpp"

typedef std::string string;
typedef std::runtime_error runtime_error;

Rule::Rule(){
  dstIp = "";
  srcIp = "";
  dstMsk = "";
  srcMsk = "";
  iFace = "";
  oFace = "";
  proto = 0;
  entryMatches = {};
  entryTarget = nullptr;
}

Rule::Rule(const ipt_entry* entry){
  dstIp = ipToStr(entry->ip.dst);
  srcIp = ipToStr(entry->ip.src);
  dstMsk = ipToStr(entry->ip.dmsk);
  srcMsk = ipToStr(entry->ip.smsk);
  iFace = entry->ip.iniface;
  oFace = entry->ip.outiface;
  proto = entry->ip.proto;
  if(entry->target_offset != sizeof(ipt_entry)){
    for(int size = 0; size < entry->target_offset - sizeof(ipt_entry);){
      xt_entry_match* match = (xt_entry_match*)(entry->elems+size);
      size += match->u.match_size;
      string name = match->u.user.name;
      Match* entryMatch = nullptr;
      if(name == "addrtype"){
	xt_addrtype_match* addrtype = (xt_addrtype_match*)match->data;
	entryMatch = new AddrtypeMatch(addrtype);
      }
      else if(name == "bpf"){
	xt_bpf_match* bpf = (xt_bpf_match*)match->data;
	entryMatch = new BpfMatch(bpf);
      }
      else if(name == "cgroup"){
	xt_cgroup_match* cgroup = (xt_cgroup_match*)match->data;
	entryMatch = new CgroupMatch(cgroup);
      }
      else if(name == "cluster"){
	xt_cluster_match* cluster = (xt_cluster_match*)match->data;
	entryMatch = new ClusterMatch(cluster);
      }
      else if(name == "comment"){
	xt_comment_match* comment = (xt_comment_match*)match->data;
	entryMatch = new CommentMatch(comment);
      }
      else if(name == "tcp"){
	xt_tcp_match* tcp = (xt_tcp_match*)match->data;
	entryMatch = new TcpMatch(tcp);
      }
      else if(name == "udp"){
	xt_udp_match* udp = (xt_udp_match*)match->data;
	entryMatch = new UdpMatch(udp);
      }
      else if(name == "icmp"){
	ipt_icmp_match* icmp = (ipt_icmp_match*)match->data;
	entryMatch = new Icmp4Match(icmp);
      }
      else if(name == "icmp6"){
	ip6t_icmp_match* icmp6 = (ip6t_icmp_match*)match->data;
	entryMatch = new Icmp6Match(icmp6);
      }
      entryMatches.push_back(entryMatch);
    }
  }
  xt_entry_target* target = (xt_entry_target*)((void*)entry + entry->target_offset);
  string name = target->u.user.name;
  if(name == "AUDIT"){
    xt_audit_target* audit = (xt_audit_target*)target->data;
    entryTarget = new  AuditTarget(audit);
  }
  else if(name == "CHECKSUM"){
    xt_checksum_target* checksum = (xt_checksum_target*)target->data;
    entryTarget = new  ChecksumTarget(checksum);
  }
  else if(name == "CONNMARK"){
    xt_connmark_target* connmark = (xt_connmark_target*)target->data;
    entryTarget = new  ConnmarkTarget(connmark);
  }
  else if(name == "CONNSECMARK"){
    xt_connsecmark_target* connsecmark = (xt_connsecmark_target*)target->data;
    entryTarget = new  ConnsecmarkTarget(connsecmark);
  }
  else if(name == "CT"){
    xt_ct_target* ct = (xt_ct_target*)target->data;
    entryTarget = new  CTTarget(ct);
  }
  else if(name == "DSCP"){
    xt_dscp_target* dscp = (xt_dscp_target*)target->data;
    entryTarget = new  DscpTarget(dscp);
  }
  else if(name == "TOS"){
    xt_tos_target* tos = (xt_tos_target*)target->data;
    entryTarget = new  TosTarget(tos);
  }
  else if(name == "HMARK"){
    xt_hmark_target* hmark = (xt_hmark_target*)target->data;
    entryTarget = new  HmarkTarget(hmark);
  }
  else if(name == "IDLETIMER"){
    xt_idletimer_target* idletimer = (xt_idletimer_target*)target->data;
    entryTarget = new  IdletimerTarget(idletimer);
  }
  else if(name == "LED"){
    xt_led_target* led = (xt_led_target*)target->data;
    entryTarget = new  LedTarget(led);
  }
  else if(name == "LOG"){
    xt_log_target* log = (xt_log_target*)target->data;
    entryTarget = new  LogTarget(log);
  }
  else if(name == "MARK"){
    xt_mark_target* mark = (xt_mark_target*)target->data;
    entryTarget = new  MarkTarget(mark);
  }
  else if(name == "NFLOG"){
    xt_nflog_target* nflog = (xt_nflog_target*)target->data;
    entryTarget = new  NFLogTarget(nflog);
  }
  else if(name == "NFQUEUE"){
    xt_nfqueue_target* nfqueue = (xt_nfqueue_target*)target->data;
    entryTarget = new  NFQueueTarget(nfqueue);
  }
  else if(name == "RATEEST"){
    xt_rateest_target* rateest = (xt_rateest_target*)target->data;
    entryTarget = new  RateEstTarget(rateest);
  }
  else if(name == "SECMARK"){
    xt_secmark_target* secmark = (xt_secmark_target*)target->data;
    entryTarget = new  SecMarkTarget(secmark);
  }
  else if(name == "SYNPROXY"){
    xt_synproxy_target* synproxy = (xt_synproxy_target*)target->data;
    entryTarget = new  SynproxyTarget(synproxy);
  }
  else if(name == "TCPMSS"){
    xt_tcpmss_target* tcpmss = (xt_tcpmss_target*)target->data;
    entryTarget = new  TcpmssTarget(tcpmss);
  }
  else if(name == "TCPOPTSTRIP"){
    xt_tcpoptstrip_target* tcpoptstrip = (xt_tcpoptstrip_target*)target->data;
    entryTarget = new  TcpOptStripTarget(tcpoptstrip);
  }
  else if(name == "TEE"){
    xt_tee_target* tee = (xt_tee_target*)target->data;
    entryTarget = new  TeeTarget(tee);
  }
  else if(name == "TPROXY"){
    xt_tproxy_target* tproxy = (xt_tproxy_target*)target->data;
    entryTarget = new  TproxyTarget(tproxy);
  }
  else if(name == "REJECT"){
    ipt_reject_target* reject = (ipt_reject_target*)target->data;
    entryTarget = new  RejectIPTarget(reject);
  }
  else if(name == "TTL"){
    ipt_ttl_target* ttl = (ipt_ttl_target*)target->data;
    entryTarget = new  TtlTarget(ttl);
  }
  else if(name == "DROP")
    entryTarget = new DropTarget();
  else if(name == "ACCEPT")
    entryTarget = new AcceptTarget();
  else if(name == "RETURN")
    entryTarget == new ReturnTarget();
  else if(name == ""){
    if(target->u.target_size > XT_ALIGN(sizeof(xt_entry_target))){
      int verdict = *(int*)target->data;
      if(verdict == -NF_DROP-1)
	entryTarget = new DropTarget();
      else if(verdict == -NF_ACCEPT-1)
	entryTarget = new AcceptTarget();
      else if(verdict == XT_RETURN)
	entryTarget = new ReturnTarget();
      else
	throw runtime_error("Unrecognized target");
    }
  }
  else
    throw runtime_error("Unrecognized target");
}

Rule::Rule(string dst, string src, string dmsk, string smsk, string in, string out, unsigned short proto, std::vector<Match*> matches,
    Target* target){
  dstIp = dst;
  srcIp = src;
  srcMsk = smsk;
  dstMsk = dmsk;
  iFace = in;
  oFace = out;
  this->proto = proto;
  entryMatches = matches;
  entryTarget = target;
}


Rule::Rule(json j){
  dstIp = j["dstIp"];
  srcIp = j["srcIp"];
  dstMsk = j["dstMsk"];
  srcMsk = j["srcMsk"];
  iFace = j["iFace"];
  oFace = j["oFace"];
  proto = j["proto"];
  for(auto& match : j["matches"]){
    string name = match["name"];
    if(name == "addrtype")
      entryMatches.push_back(new AddrtypeMatch(match));
    else if(name == "bpf")
      entryMatches.push_back(new BpfMatch(match));
    else if(name == "cgroup")
      entryMatches.push_back(new CgroupMatch(match));
    else if(name == "cluster")
      entryMatches.push_back(new ClusterMatch(match));
    else if(name == "comment")
      entryMatches.push_back(new CommentMatch(match));
    else if(name == "tcp")
      entryMatches.push_back(new TcpMatch(match));
    else if(name == "udp")
      entryMatches.push_back(new UdpMatch(match));
    else if(name == "icmp")
      entryMatches.push_back(new Icmp4Match(match));
    else if(name == "icmp6")
      entryMatches.push_back(new Icmp6Match(match));
  }
  string name = j["target"]["name"];
  if(name == "AUDIT")
    entryTarget = new AuditTarget(j["target"]);
  else if(name == "CHECKSUM")
    entryTarget = new ChecksumTarget(j["target"]);
  else if(name == "CONNMARK")
    entryTarget = new ConnmarkTarget(j["target"]);
  else if(name == "CONNSECMARK")
    entryTarget = new ConnsecmarkTarget(j["target"]);
  else if(name == "CT")
    entryTarget = new CTTarget(j["target"]);
  else if(name == "DSCP")
    entryTarget = new DscpTarget(j["target"]);
  else if(name == "TOS")
    entryTarget = new TosTarget(j["target"]);
  else if(name == "HMARK")
    entryTarget = new HmarkTarget(j["target"]);
  else if(name == "IDLETIMER")
    entryTarget = new IdletimerTarget(j["target"]);
  else if(name == "LED")
    entryTarget = new LedTarget(j["target"]);
  else if(name == "LOG")
    entryTarget = new LogTarget(j["target"]);
  else if(name == "MARK")
    entryTarget = new MarkTarget(j["target"]);
  else if(name == "NFLOG")
    entryTarget = new NFLogTarget(j["target"]);
  else if(name == "NFQUEUE")
    entryTarget = new NFQueueTarget(j["target"]);
  else if(name == "RATEEST")
    entryTarget = new RateEstTarget(j["target"]);
  else if(name == "SECMARK")
    entryTarget = new SecMarkTarget(j["target"]);
  else if(name == "SYNPROXY")
    entryTarget = new SynproxyTarget(j["target"]);
  else if(name == "TCPMSS")
    entryTarget = new TcpmssTarget(j["target"]);
  else if(name == "TCPOPTSTRIP")
    entryTarget = new TcpOptStripTarget(j["target"]);
  else if(name == "TEE")
    entryTarget = new TeeTarget(j["target"]);
  else if(name == "TPROXY")
    entryTarget = new TproxyTarget(j["target"]);
  else if(name == "TTL")
    entryTarget = new TtlTarget(j["target"]);
  else if(name == "HL")
    entryTarget = new HlTarget(j["target"]);
  else if(name == "REJECT")
    entryTarget = new RejectIPTarget(j["target"]);
  else if(name == "DROP")
    entryTarget = new DropTarget();
  else if(name == "ACCEPT")
    entryTarget = new AcceptTarget();
  else if(name == "RETURN")
    entryTarget = new ReturnTarget();
  else
    throw runtime_error("File corrupted. Unrecognized target");
}

    



ipt_entry* Rule::asEntry() const{
  unsigned int numOfMatches = 0;
  if(!entryMatches.empty())
    numOfMatches = entryMatches.size();
  ipt_entry* entry;
  xt_entry_match** matches = new xt_entry_match*[numOfMatches];
  memset(matches, 0, sizeof(xt_entry_match*) * numOfMatches); 
  xt_entry_target* target;
  xt_entry_match* match;
  Match* entryMatch;

  // Align everything
  unsigned int entrySize = XT_ALIGN(sizeof(ipt_entry));
  unsigned int targetSize = XT_ALIGN(sizeof(xt_entry_target) + entryTarget->getSize());
  unsigned int matchesSize = XT_ALIGN(sizeof(xt_entry_match)) * numOfMatches;
  for(int i = 0; i < numOfMatches; i++)
    matchesSize += XT_ALIGN(entryMatches.at(i)->getSize());
  unsigned int totalSize = entrySize + targetSize + matchesSize;
  entry = (ipt_entry*)calloc(1, totalSize);



  if(srcIp != "")
    entry->ip.src = strToInAddr(srcIp);
  if(dstIp != "")
    entry->ip.dst = strToInAddr(dstIp);
  //entry->ip.smsk.s_addr = inet_addr("255.255.255.255");
  //entry->ip.dmsk.s_addr = inet_addr("255.255.255.255");
  if(srcMsk != "")
    entry->ip.smsk = strToInAddr(srcMsk);
  if(dstMsk != "")
    entry->ip.dmsk = strToInAddr(dstMsk);
  if(iFace != ""){
    strncpy(entry->ip.iniface, iFace.c_str(), IFNAMSIZ);
    memset(entry->ip.iniface_mask, 1, (iFace.size() < IFNAMSIZ) ? iFace.size() + 1 : IFNAMSIZ); 
  }
  if(oFace != ""){
    strncpy(entry->ip.outiface, oFace.c_str(), IFNAMSIZ);
    memset(entry->ip.outiface_mask, 1, (oFace.size() < IFNAMSIZ) ? oFace.size() + 1 : IFNAMSIZ); 
  }
  entry->ip.proto = proto; 
  
  entry->target_offset = entrySize + matchesSize;
  entry->next_offset = totalSize;

  // Include matches
  for(int i = 0, size = 0; i < numOfMatches; i++){
    match = (xt_entry_match*) (entry->elems + size);
    entryMatch = entryMatches.at(i);
    strcpy(match->u.user.name, entryMatch->getName().c_str());
    match->u.match_size = XT_ALIGN(sizeof(xt_entry_match) + entryMatch->getSize());
    size += match->u.match_size;
    /*
    if(!strcmp(matches[i]->u.user.name,"udp")){
      xt_udp_match* match = (xt_udp_match*) matches[i]->data;
      *match = ((UdpMatch*)entryMatches->at(i))->getSpecs();
    }
    */
    memcpy(match->data, entryMatch->getSpecs(), entryMatch->getSize());
  }

  //dump_entries(rules);

  // Include target
  target = (xt_entry_target*) (entry->elems + matchesSize);
  target->u.target_size = targetSize;
  strcpy(target->u.user.name, entryTarget->getName().c_str());
  /*
  if(!strcmp(target->u.user.name, "DROP")){
    int* verdict = (int*)target->data;
    *verdict = ((DropTarget*)entryTarget)->getSpecs();
  }
  */
  memcpy(target->data, entryTarget->getSpecs(), entryTarget->getSize());

  return entry;
}

json Rule::asJson() const{
  json j;
  j["dstIp"] = dstIp;
  j["srcIp"] = srcIp;
  j["srcMsk"] = srcMsk;
  j["dstMsk"] = dstMsk;
  j["iFace"] = iFace;
  j["oFace"] = oFace;
  j["proto"] = proto;
  j["matches"] = json::array();
  for(int i = 0; i < entryMatches.size(); i++){
    j["matches"][i] = entryMatches[i]->asJson();
    j["matches"][i]["name"] = entryMatches[i]->getName();
  }
  j["target"] = entryTarget->asJson();
  j["target"]["name"] = entryTarget->getName();
  return j;
}


Firewall::Firewall(){
  ruleFile = "";
  rules = iptc_init("filter");
  if(!rules){
    string e = "Error creating firewall\n";
    throw runtime_error(e += iptc_strerror(errno));
  }
}

Firewall::Firewall(string ruleFile) : Firewall(){
  this->ruleFile = ruleFile;
}

Firewall::~Firewall(){
  iptc_free(rules);
}

void Firewall::addRule(string dstIp, string srcIp, string iFace, string oFace, 
    unsigned short proto, std::vector<Match*>* entryMatches, Target* entryTarget, string chain){ 
  unsigned int numOfMatches = 0;
  if(entryMatches)
    numOfMatches = entryMatches->size();
  ipt_entry* entry;
  xt_entry_match** matches = new xt_entry_match*[numOfMatches];
  memset(matches, 0, sizeof(xt_entry_match*) * numOfMatches); 
  xt_entry_target* target;
  xt_entry_match* match;
  Match* entryMatch;

  // Align everything
  unsigned int entrySize = XT_ALIGN(sizeof(ipt_entry));
  unsigned int targetSize = XT_ALIGN(sizeof(xt_entry_target) + entryTarget->getSize());
  unsigned int matchesSize = XT_ALIGN(sizeof(xt_entry_match)) * numOfMatches;
  for(int i = 0; i < numOfMatches; i++)
    matchesSize += XT_ALIGN(entryMatches->at(i)->getSize());
  unsigned int totalSize = entrySize + targetSize + matchesSize;
  entry = (ipt_entry*)calloc(1, totalSize);



  if(srcIp != "")
    entry->ip.src = strToInAddr(srcIp);
  if(dstIp != "")
    entry->ip.dst = strToInAddr(dstIp);
  //entry->ip.smsk.s_addr = inet_addr("255.255.255.255");
  //entry->ip.dmsk.s_addr = inet_addr("255.255.255.255");
  if(iFace != ""){
    strncpy(entry->ip.iniface, iFace.c_str(), IFNAMSIZ);
    memset(entry->ip.iniface_mask, 1, (iFace.size() < IFNAMSIZ) ? iFace.size() + 1 : IFNAMSIZ); 
  }
  if(oFace != ""){
    strncpy(entry->ip.outiface, oFace.c_str(), IFNAMSIZ);
    memset(entry->ip.outiface_mask, 1, (oFace.size() < IFNAMSIZ) ? oFace.size() + 1 : IFNAMSIZ); 
  }
  entry->ip.proto = proto; 
  
  entry->target_offset = entrySize + matchesSize;
  entry->next_offset = totalSize;

  // Include matches
  for(int i = 0, size = 0; i < numOfMatches; i++){
    match = (xt_entry_match*) (entry->elems + size);
    entryMatch = entryMatches->at(i);
    strcpy(match->u.user.name, entryMatch->getName().c_str());
    match->u.match_size = XT_ALIGN(sizeof(xt_entry_match) + entryMatch->getSize());
    size += match->u.match_size;
    /*
    if(!strcmp(matches[i]->u.user.name,"udp")){
      xt_udp_match* match = (xt_udp_match*) matches[i]->data;
      *match = ((UdpMatch*)entryMatches->at(i))->getSpecs();
    }
    */
    memcpy(match->data, entryMatch->getSpecs(), entryMatch->getSize());
  }

  //dump_entries(rules);

  // Include target
  target = (xt_entry_target*) (entry->elems + matchesSize);
  target->u.target_size = targetSize;
  strcpy(target->u.user.name, entryTarget->getName().c_str());
  /*
  if(!strcmp(target->u.user.name, "DROP")){
    int* verdict = (int*)target->data;
    *verdict = ((DropTarget*)entryTarget)->getSpecs();
  }
  */
  memcpy(target->data, entryTarget->getSpecs(), entryTarget->getSize());

  const ipt_entry* cmp = iptc_first_rule(chain.c_str(), rules);

  
  if(!iptc_append_entry(chain.c_str(), entry, rules)){
    string e = "Error adding rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }


//  if(!iptc_get_target(entry, rules))
//    throw runtime_error(iptc_strerror(errno));

/*
  if(!iptc_commit(rules)){
    string e = "Error commiting table\n";
    throw runtime_error(e += iptc_strerror(errno));
  }
*/
}

void Firewall::addRule(Rule* rule, string chain){
  //addRule(rule->dstIp, rule->srcIp, rule->iFace, rule->oFace, rule->proto, &rule->entryMatches, rule->entryTarget, chain);
  ipt_entry* entry = rule->asEntry();

  if(!iptc_append_entry(chain.c_str(), entry, rules)){
    string e = "Error adding rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }


//  if(!iptc_get_target(entry, rules))
//    throw runtime_error(iptc_strerror(errno));


}

void Firewall::addLog(Rule* rule){
  ipt_entry* entry = rule->asEntry();
  string chain = "INPUT";
  
  xtc_handle* nat = iptc_init("nat");
  if(!nat){
    string e = "Error creating nat table\n";
    throw runtime_error(e += iptc_strerror(errno));
  }

  if(!iptc_append_entry(chain.c_str(), entry, nat)){
    string e = "Error adding rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }
  
  if(!iptc_commit(nat)){
    string e = "Error commiting nat table\n";
    throw runtime_error(e += iptc_strerror(errno));
  }
  
  iptc_free(nat);
}


void Firewall::insertRule(string dstIp, string srcIp, string iFace, string oFace, 
      string proto, std::vector<Match*>* entryMatches, Target* entryTarget, string chain, int num){
  ipt_entry* entry = nullptr;
  xt_entry_match* match = nullptr;
  xt_entry_target* target = nullptr;
  Match* entryMatch = nullptr;
  int numOfMatches = 0;
  if(entryMatches != nullptr && !entryMatches->empty())
    numOfMatches = entryMatches->size();

  unsigned entrySize = XT_ALIGN(sizeof(ipt_entry));
  unsigned matchesSize = XT_ALIGN(sizeof(xt_entry_match) * numOfMatches);
  for(int i = 0; i < numOfMatches; i++)
    matchesSize += XT_ALIGN(entryMatches->at(i)->getSize());
  unsigned targetSize = XT_ALIGN(sizeof(xt_entry_target) + entryTarget->getSize());
  unsigned totalSize = entrySize + matchesSize + targetSize;

  entry = (ipt_entry*)calloc(totalSize, 0);

  if(srcIp != "")
    entry->ip.src = strToInAddr(srcIp);
  if(dstIp != "")
    entry->ip.dst = strToInAddr(dstIp);
  //entry->ip.smsk.s_addr = inet_addr("255.255.255.255");
  //entry->ip.dmsk.s_addr = inet_addr("255.255.255.255");
  if(iFace != ""){
    strncpy(entry->ip.iniface, iFace.c_str(), IFNAMSIZ);
    memset(entry->ip.iniface_mask, 1, (iFace.size() < IFNAMSIZ) ? iFace.size() + 1 : IFNAMSIZ); 
  }
  if(oFace != ""){
    strncpy(entry->ip.outiface, oFace.c_str(), IFNAMSIZ);
    memset(entry->ip.outiface_mask, 1, (oFace.size() < IFNAMSIZ) ? oFace.size() + 1 : IFNAMSIZ); 
  }
    entry->ip.proto = IPPROTO_UDP; 
  
  entry->target_offset = entrySize + matchesSize;
  entry->next_offset = totalSize;

  // Include matches
  for(int i = 0, size = 0; i < numOfMatches; i++){
    match = (xt_entry_match*) (entry->elems + size);
    entryMatch = entryMatches->at(i);
    strcpy(match->u.user.name, entryMatch->getName().c_str());
    match->u.match_size = XT_ALIGN(sizeof(xt_entry_match) + entryMatch->getSize());
    size += match->u.match_size;
    /*
    if(!strcmp(matches[i]->u.user.name,"udp")){
      xt_udp_match* match = (xt_udp_match*) matches[i]->data;
      *match = ((UdpMatch*)entryMatches->at(i))->getSpecs();
    }
    */
    memcpy(match->data, entryMatch->getSpecs(), entryMatch->getSize());
  }

  //dump_entries(rules);

  // Include target
  target = (xt_entry_target*) (entry->elems + matchesSize);
  target->u.target_size = targetSize;
  strcpy(target->u.user.name, entryTarget->getName().c_str());
  /*
  if(!strcmp(target->u.user.name, "DROP")){
    int* verdict = (int*)target->data;
    *verdict = ((DropTarget*)entryTarget)->getSpecs();
  }
  */
  memcpy(target->data, entryTarget->getSpecs(), entryTarget->getSize());

  if(!iptc_insert_entry(chain.c_str(), entry, num, rules)){
    string e = "Error adding rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }
}

void Firewall::insertRule(Rule* rule, string chain, int num){
  ipt_entry* entry = rule->asEntry();

  if(!iptc_insert_entry(chain.c_str(), entry, num, rules)){
    string e = "Error adding rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }
}
void Firewall::replaceRule(string dstIp, string srcIp, string iFace, string oFace, 
      string proto, std::vector<Match*>* entryMatches, Target* entryTarget, string chain, int num){
  ipt_entry* entry = nullptr;
  xt_entry_match* match = nullptr;
  xt_entry_target* target = nullptr;
  Match* entryMatch = nullptr;
  int numOfMatches = 0;
  if(entryMatches != nullptr && !entryMatches->empty())
    numOfMatches = entryMatches->size();

  unsigned entrySize = XT_ALIGN(sizeof(ipt_entry));
  unsigned matchesSize = XT_ALIGN(sizeof(xt_entry_match) * numOfMatches);
  for(int i = 0; i < numOfMatches; i++)
    matchesSize += XT_ALIGN(entryMatches->at(i)->getSize());
  unsigned targetSize = XT_ALIGN(sizeof(xt_entry_target) + entryTarget->getSize());
  unsigned totalSize = entrySize + matchesSize + targetSize;

  entry = (ipt_entry*)calloc(totalSize, 0);

  if(srcIp != "")
    entry->ip.src = strToInAddr(srcIp);
  if(dstIp != "")
    entry->ip.dst = strToInAddr(dstIp);
  //entry->ip.smsk.s_addr = inet_addr("255.255.255.255");
  //entry->ip.dmsk.s_addr = inet_addr("255.255.255.255");
  if(iFace != ""){
    strncpy(entry->ip.iniface, iFace.c_str(), IFNAMSIZ);
    memset(entry->ip.iniface_mask, 1, (iFace.size() < IFNAMSIZ) ? iFace.size() + 1 : IFNAMSIZ); 
  }
  if(oFace != ""){
    strncpy(entry->ip.outiface, oFace.c_str(), IFNAMSIZ);
    memset(entry->ip.outiface_mask, 1, (oFace.size() < IFNAMSIZ) ? oFace.size() + 1 : IFNAMSIZ); 
  }
    entry->ip.proto = IPPROTO_UDP; 
  
  entry->target_offset = entrySize + matchesSize;
  entry->next_offset = totalSize;

  // Include matches
  for(int i = 0, size = 0; i < numOfMatches; i++){
    match = (xt_entry_match*) (entry->elems + size);
    entryMatch = entryMatches->at(i);
    strcpy(match->u.user.name, entryMatch->getName().c_str());
    match->u.match_size = XT_ALIGN(sizeof(xt_entry_match) + entryMatch->getSize());
    size += match->u.match_size;
    /*
    if(!strcmp(matches[i]->u.user.name,"udp")){
      xt_udp_match* match = (xt_udp_match*) matches[i]->data;
      *match = ((UdpMatch*)entryMatches->at(i))->getSpecs();
    }
    */
    memcpy(match->data, entryMatch->getSpecs(), entryMatch->getSize());
  }

  //dump_entries(rules);

  // Include target
  target = (xt_entry_target*) (entry->elems + matchesSize);
  target->u.target_size = targetSize;
  strcpy(target->u.user.name, entryTarget->getName().c_str());
  /*
  if(!strcmp(target->u.user.name, "DROP")){
    int* verdict = (int*)target->data;
    *verdict = ((DropTarget*)entryTarget)->getSpecs();
  }
  */
  memcpy(target->data, entryTarget->getSpecs(), entryTarget->getSize());

  if(!iptc_replace_entry(chain.c_str(), entry, num, rules)){
    string e = "Error adding rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }

}
 
void Firewall::replaceRule(Rule* rule, string chain, int num){
  ipt_entry* entry = rule->asEntry();
  
  if(!iptc_replace_entry(chain.c_str(), entry, num, rules)){
    string e = "Error adding rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }

}

void Firewall::removeRule(unsigned num, string chain, string table){
  if(!iptc_delete_num_entry(chain.c_str(), num, rules)){
    string e = "Error removing rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }

}

void Firewall::save(){
  if(!iptc_commit(rules)){
    string e = "Error commiting table\n";
    throw runtime_error(e += iptc_strerror(errno));
  }
  json j;
  std::ofstream file(ruleFile, std::ofstream::trunc);
  for(const char* chain = iptc_first_chain(rules); chain != NULL; chain = iptc_next_chain(rules)){
    for(const ipt_entry* entry = iptc_first_rule(chain, rules); entry != NULL; 
	entry = iptc_next_rule(entry, rules)){
      Rule* rule = new Rule(entry);
      j[chain].push_back(rule->asJson());
      delete rule;
    }
  }
  file << j;
}

void Firewall::load(){
  json j;
  std::ifstream file(ruleFile);
  file >> j;
  for(auto& obj : j.items()){
    string chain = obj.key();
    for(auto& ruleJson : obj.value()){
      addRule(new Rule(ruleJson), chain);
    }
  }
}


std::vector<string>* Firewall::getRules() const{
  std::vector<string>* ret = new std::vector<string>();
  for(const char* chain = iptc_first_chain(rules); chain != NULL; chain = iptc_next_chain(rules)){
    for(const ipt_entry* entry = iptc_first_rule(chain, rules); entry != NULL; entry = iptc_next_rule(entry, rules)){
      Rule* rule = new Rule(entry);
      ret->push_back(chain);
      string ruleStr = "";
      if(rule->srcIp != "" && rule->srcIp != "0.0.0.0"){
	ruleStr += "Source IP: "; 
	ruleStr += rule->srcIp += " ";
      }
      if(rule->dstIp != "" && rule->dstIp != "0.0.0.0"){
	ruleStr += "Destination IP: ";
	ruleStr += rule->dstIp += " ";
      }
      if(rule->srcMsk != "" && rule->srcMsk != "0.0.0.0"){
	ruleStr += "Source Mask: ";
	ruleStr += rule->srcMsk += " ";
      }
      if(rule->dstMsk != "" && rule->dstMsk != "0.0.0.0"){
	ruleStr += "Destination Mask: ";
	ruleStr += rule->dstMsk += " ";
      }
      if(rule->iFace != ""){
	ruleStr += "Incoming Interface: ";
	ruleStr += rule->iFace += " ";
      }
      if(rule->oFace != ""){
	ruleStr += "Outgoing Interface: ";
	ruleStr += rule->oFace += " ";
      }
      if(rule->proto != 0){
	ruleStr += "Protocol: ";
	ruleStr += std::to_string(rule->proto) += " ";
      }
      if(!rule->entryMatches.empty()){
	ruleStr += "Matches: ";
	for(auto& match : rule->entryMatches){
	  ruleStr += match->getName() += ": ";
	  json j = match->asJson();
	  for(auto item = j.begin(); item != j.end(); item++){
	    (ruleStr += item.key()) += ": ";
	    (ruleStr += item.value().dump()) += " ";

	  }
	}
      }
      ruleStr += "Target: ";
      ruleStr += rule->entryTarget->getName() += ": ";
      json j = rule->entryTarget->asJson();
      for(auto& item : j.items()){
	(ruleStr += item.key()) += ": "; 
	(ruleStr += item.value().dump()) += " ";
      }
      ret->push_back(ruleStr);
    }
  }
  return ret;
}



string Firewall::checkLogs(int lines){
  //TODO
}

