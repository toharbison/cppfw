#ifndef FIREWALL_H
#define FIREWALL_H

#include <string>
#include <vector>
#include <libiptc/libiptc.h>
#include <xtables.h>


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
      std::string proto, std::vector<std::string>* matches, std::string target); 

  /* Checks logs and returns std::string of recent log messages
   * "lines" number of messages to return
   */
  std::string checkLogs(int lines);

  private:
  
  xtc_handle* rules;
  std::string ruleFile;


};

#endif

