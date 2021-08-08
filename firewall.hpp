#ifndef FIREWALL_H
#define FIREWALL_H

#include <string>
#include <vector>
#include <libiptc/libiptc.h>
#include <xtables.h>
#include "targets.hpp"
#include "matches.hpp"

class Rule{
  public:
  /* Constructors */
  Rule();
  Rule(const ipt_entry* entry);
  Rule(json j);
  Rule(string dst, string src, string in, string out, unsigned short proto, std::vector<Match*> matches, Target* target);
  
  /* Returns rule as ipt_entry* */
  ipt_entry* asEntry() const;
  /* Returns rule as json */
  json asJson() const;

  /* Members */
  std::string dstIp, srcIp, iFace, oFace;
  unsigned short proto;
  std::vector<Match*> entryMatches;
  Target* entryTarget;
};



class Firewall{
  public:

  // Constructor
  Firewall();
  Firewall(string ruleFile);

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
      unsigned short proto, std::vector<Match*>* matches, Target* target, string chain); 
  void addRule(Rule* rule, string chain);

  /* Adds rule to firewall
   * "dstIp" is destination ip of packet
   * "srcIp" is source ip of packet
   * "iFace" is input interface
   * "oFace" is output interface
   * "proto" is protocol of packet
   * "matches" is a vector of rules to match against packet
   * "target" is the target of packet
   * "chain" chain to insert rule into
   * "num" where in the chain to insert rule
   */
  void insertRule(std::string dstIp, std::string srcIp, std::string iFace, std::string oFace, 
      std::string proto, std::vector<Match*>* matches, Target* target, string chain, int num); 
  void insertRule(Rule* rule, string chain, int num);

  /* Adds rule to firewall
   * "dstIp" is destination ip of packet
   * "srcIp" is source ip of packet
   * "iFace" is input interface
   * "oFace" is output interface
   * "proto" is protocol of packet
   * "matches" is a vector of rules to match against packet
   * "target" is the target of packet
   * "chain" chain to insert rule into
   * "num" number of rule to replace in chain
   */
  void replaceRule(std::string dstIp, std::string srcIp, std::string iFace, std::string oFace, 
      std::string proto, std::vector<Match*>* matches, Target* target, string chain, int num); 
  void replaceRule(Rule* rule, string chain, int num);
 

  /**
   * Removes the rule of the given number from the given chain.
   * "num" number in chain, 0 being first
   * "chain" name of chain to remove rule from
   * "table" name of table to remove rule from
   */
  void removeRule(unsigned num, string chain, string table);

  /* Saves to ruleFile */
  void save();

  /* Loads from ruleFile */
  void load();

  /* Returns a vector of strings about all rules */
  std::vector<string>* getRules() const;

  /* Checks logs and returns std::string of recent log messages
   * "lines" number of messages to return
   */
  std::string checkLogs(int lines);

  private:
 
  xtc_handle* rules;
  std::string ruleFile;


};

#endif

