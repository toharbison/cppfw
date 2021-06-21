#include <iostream>
#include <stdexcept>
#include "firewall.h"


int main(int argc, char** argv){
  try{
    Firewall* fw = new Firewall();
    fw->addRule("", "", "lo", "", "", nullptr, "DROP");
  }catch(std::exception &e){
    std::cout << "FAIL: " << e.what() << "\n";
  }
  return 0;
}
