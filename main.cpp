#include <iostream>
#include <stdexcept>
#include "firewall.hpp"


int main(int argc, char** argv){
  if(argv[1][1] == 'a'){
    try{
      Firewall* fw = new Firewall();
      Target* target = new DropTarget();
      fw->addRule("", "", "lo", "", "", nullptr, target, "INPUT");
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
  else
    std::cout << argv[1] << " is not a valid parameter. Please try again.\n";
  return 0;
}
