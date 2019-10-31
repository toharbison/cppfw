#include <string>
#include <stdio.h>
using namespace std

//Rule for iptables
struct Rule {
  string m_chain;
  string* m_ruleSpecs;
  Rule(string chain, string* ruleSpecs);
  operator==(Rule rule);
  operator=(Rule rule);
};

struct Iptable {
  string* m_chains;
  Rule** m_rules;
};

string* parseCommands(string input);
void insert(Rule rule, int ruleNum);
void replace(Rule rule, Rule rule);
void replace(Rule rule, int ruleNum);
void delete(Rule rule);
void delete(int ruleNum);
void addChain(string chain);
void delChain(string chain);
void renameChain(string old, string new);
Iptable readFromFile(string fileName);
void writeToFile(Iptable table);
void printTable(Iptable table);
void default(string chain, string target);

int main(int argc, char[]* argv){
  
  return 0;
}
