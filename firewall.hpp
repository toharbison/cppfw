#ifndef FIREWALL_H
#define FIREWALL_H

#include <string>
#include <vector>
#include <libiptc/libiptc.h>
#include <xtables.h>
#include "targets.hpp"
#include "matches.hpp"


class Firewall{
  public:

  // Constructor
  Firewall();

  // Deconstructor
  ~Firewall();

  /* Adds rule to firewall
   * "dstIp" is destination ip of packet
   * "srcIp" is source ip of packet
   * "iFace" is input interface
   * "oFace" is output interface
   * "proto" is protocol of packet
   * "matches" is a vector of rules to match against packet
   * "target" is the target of packet
   */
  void addRule(std::string dstIp, std::string srcIp, std::string iFace, std::string oFace, 
      std::string proto, std::vector<Match*>* matches, Target* target, string chain); 

  /**
   * Removes the rule of the given number from the given chain.
   * "num" number in chain, 0 being first
   * "chain" name of chain to remove rule from
   * "table" name of table to remove rule from
   */
  void removeRule(unsigned num, string chain, string table);

  /* Checks logs and returns std::string of recent log messages
   * "lines" number of messages to return
   */
  std::string checkLogs(int lines);

  private:
  
  xtc_handle* rules;
  std::string ruleFile;


};

#endif

