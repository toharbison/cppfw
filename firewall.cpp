#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <iostream>
#include <arpa/inet.h>
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
    string proto, std::vector<string>* entryMatches, Target* entryTarget){ 
  unsigned int numOfMatches = 0;
  if(entryMatches)
    numOfMatches = entryMatches->size();
  ipt_entry* entry;
  xt_entry_match** matches = new xt_entry_match*[numOfMatches];
  memset(matches, 0, sizeof(xt_entry_match*) * numOfMatches); 
  xt_standard_target* target;

  // Align everything
  unsigned int entrySize = XT_ALIGN(sizeof(ipt_entry));
  unsigned int targetSize = XT_ALIGN(sizeof(xt_standard_target));//XT_ALIGN(sizeof(xt_entry_target));
  unsigned int matchesSize = 0;
  unsigned int totalSize = entrySize + targetSize + matchesSize;
  entry = (ipt_entry*)calloc(1, totalSize);



  if(srcIp != "")
    entry->ip.src.s_addr = inet_addr(srcIp.c_str());
  if(dstIp != "")
    entry->ip.dst.s_addr = inet_addr(dstIp.c_str());
  //entry->ip.smsk.s_addr = inet_addr("255.255.255.255");
  //entry->ip.dmsk.s_addr = inet_addr("255.255.255.255");
  if(iFace != "")
    strcpy(entry->ip.iniface, iFace.c_str());
  if(oFace != "")
    strcpy(entry->ip.outiface, oFace.c_str());
  if(proto != "")
    entry->ip.proto = 0; 
  
  entry->nfcache = 0;
  entry->target_offset = entrySize + matchesSize;
  entry->next_offset = totalSize;

  target = (xt_standard_target*) (entry->elems);
  target->target.u.target_size = targetSize;
  strcpy(target->target.u.user.name, "DROP");
  target->verdict = -1;

  const char* chain = "INPUT"; 

  std::cout << iptc_get_target(entry, rules) << "\n";  

  //dump_entries(rules);

  if(!iptc_append_entry(chain, entry, rules)){
    string e = "Error adding rule\n";
    throw runtime_error(e += iptc_strerror(errno));
  }

  //dump_entries(rules);

  if(!iptc_commit(rules)){
    string e = "Error commiting table\n";
    throw runtime_error(e += iptc_strerror(errno));
  }


}

void removeRule(int num, string chain, string table){
  
}

string Firewall::checkLogs(int lines){
  //TODO
}

