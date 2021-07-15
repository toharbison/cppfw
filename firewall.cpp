#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <iostream>
#include <xtables.h>
#include "firewall.hpp"

#define string std::string
#define runtime_error std::runtime_error

Firewall::Firewall(){
  ruleFile = "";
  rules = iptc_init("filter");
  if(!rules){
    string e = "Error creating firewall\n";
    throw runtime_error(e += iptc_strerror(errno));
  }
}

Firewall::~Firewall(){
  iptc_free(rules);
}

void Firewall::addRule(string dstIp, string srcIp, string iFace, string oFace, 
    string proto, std::vector<Match*>* entryMatches, Target* entryTarget, string chain){ 
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

  const ipt_entry* cmp = iptc_first_rule(chain.c_str(), rules);

  
  if(!iptc_append_entry(chain.c_str(), entry, rules)){
    string e = "Error adding rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }


  if(!iptc_get_target(entry, rules))
    throw runtime_error(iptc_strerror(errno));


  if(!iptc_commit(rules)){
    string e = "Error commiting table\n";
    throw runtime_error(e += iptc_strerror(errno));
  }

}

void Firewall::removeRule(unsigned num, string chain, string table){
  if(!iptc_delete_num_entry(chain.c_str(), num, rules)){
    string e = "Error removing rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }

  if(!iptc_commit(rules)){
    string e = "Error commiting table\n";
    throw runtime_error(e += iptc_strerror(errno));
  }
}

string Firewall::checkLogs(int lines){
  //TODO
}

