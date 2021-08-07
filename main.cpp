#include <iostream>
#include <stdexcept>
#include "firewall.hpp"
#include "display.hpp"


int main(int argc, char** argv){
  if(argv[1][1] == 'a'){
    try{
      Firewall* fw = new Firewall();
      Target* target = new DropTarget();
      fw->addRule("", "", "lo", "", 0, nullptr, target, "INPUT");
    }catch(std::exception &e){
      std::cerr << "FAIL APPEND: " << e.what() << "\n";
    }
  }
  else if(argv[1][1] == 'd'){
    try{
      Firewall* fw = new Firewall();
      fw->removeRule(0, "INPUT", "filter");
    }catch(std::exception &e){
      std::cerr << "FAIL REMOVE: " << e.what() << "\n";
    }
  }
  else if(argv[1][1] == 'm'){
    try{
      Firewall* fw = new Firewall();
      Match* match = new UdpMatch();
      std::vector<Match*>* matches = new std::vector<Match*>(1, match);
      Target* target = new DropTarget();
      fw->addRule("","","wlp4s0","",IPPROTO_UDP,matches,target,"INPUT");
    }catch(std::exception &e){
      std::cerr << "FAIL APPEND MATCH: " << e.what() << "\n";
    }
  }
  else if(argv[1][1] == 'r'){
    try{
      Firewall* fw = new Firewall("rules.json");
      Match* match1 = new UdpMatch();
      Match* match2 = new CommentMatch(string("Look at udp packets"));
      LogTarget* log = new LogTarget();
      log->setLevel(5);
      Target* target = log;
      fw->addRule("", "", "wlp4s0", "", IPPROTO_UDP, new std::vector<Match*>({match1, match2}), target, "INPUT");
      std::cout<<1<<'\n';
      fw->addRule(new Rule("", "", "wlp4s0", "", IPPROTO_UDP, {match1, match2}, target), "INPUT");
      fw->save();
    }catch(std::exception &e){
      std::cerr << "FAIL SAVE: " << e.what() << "\n";
    }
  }
  else if(argv[1][1] == 'l'){
    try{
      Firewall* fw = new Firewall("rules.json");
      fw->load();
      fw->save();
    }catch(std::exception &e){
      std::cerr << "FAIL LOAD: " << e.what() << "\n";
    }
  }
  else if(argv[1][1] == 's'){
    try{
      Display::start();
    }catch(std::exception &e){
      std::cerr << "FAIL DISPLAY: " << e.what() << "\n";
    }
  }

  else
    std::cout << argv[1] << " is not a valid parameter. Please try again.\n";
  return 0;
}
