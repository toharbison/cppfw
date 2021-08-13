#ifndef DISPLAY_HPP
#define DISPLAY_HPP

#include<curses.h>
#include<panel.h>
#include "firewall.hpp"

class Display {
  public:
  static void start();

  private:
  static void menu();
  static void viewRules();
  static void deleteRule();
  static void appendRule();
  static void insertRule();
  static void replaceRule();
  static int selectRule();
  static string selectChain();
  static Rule* createRule();
  static Match* makeAddrtype(WINDOW* win);
  static Match* makeBpf(WINDOW* win);
  static Match* makeCgroup(WINDOW* win);
  static Match* makeCluster(WINDOW* win);
  static Match* makeComment(WINDOW* win);
  static Match* makeTcp(WINDOW* win);
  static Match* makeUdp(WINDOW* win);
  static Match* makeIcmp(WINDOW* win);
  static Target* makeLog(WINDOW* win);
};

#endif

