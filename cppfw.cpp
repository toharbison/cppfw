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
} table;

void exCommands(string[] input);
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

void exCommands(string[] input){
  string[] valid = { "default", "allow", "drop", "return", "log", "delete", "replace", "help"};
  if(input[0] == valid[0]){
    //TODO
  }else if(input[0] == valid[1]){
    //TODO
  }else if(input[0] == valid[2]){
    //TODO
  }else if(input[0] == valid[3]){
    //TODO
  }else if(input[0] == valid[4]){
    //TODO
  }else if(input[0] == valid[5]){
    //TODO
  }else if(input[0] == valid[6]){
    //TODO
  }else if(input[0] == valid[7]){
    //TODO
  }else{
    //TODO
  }
}
