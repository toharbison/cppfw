#include "display.hpp"
#include "firewall.hpp"

Firewall* fw;

void Display::start(){
  initscr();
  cbreak();
  noecho();
  fw = new Firewall();
  menu();
  endwin();
  return;
}

void Display::menu(){
  WINDOW* win = newwin(0,0,0,0);
  WINDOW* menu = newwin(10, 15, 0, 0);
  PANEL* winPanel = new_panel(win);
  PANEL* menuPanel = new_panel(menu);
  int i = 0;
  int ch = 0;
  int menuItemsSize = 5;
  char* menuItems[menuItemsSize] = {"View Rules", "Add Rule", "Delete Rule", "Replace Rule", "Quit"};
  curs_set(0);
  mvwhline(win, 4, 0, ACS_HLINE, COLS);
  wattron(win, A_BOLD);
  mvwaddstr(win, 2, COLS/2 - 2, "MENU");
  wattroff(win, A_BOLD);
  for(int y = 0; y < menuItemsSize; y++){
    if(y == 0)
      wattron(menu, A_STANDOUT);
    else
      wattroff(menu, A_STANDOUT);
    mvwaddstr(menu, y*2, 0, menuItems[y]);
  }
  int x = move_panel(menuPanel, 6, 2);
  update_panels();
  doupdate();
  keypad(menu, true);
  while(ch = wgetch(menu)){
    wattroff(menu, A_STANDOUT);
    mvwaddstr(menu, i*2, 0, menuItems[i]);
    switch(ch){
      case KEY_UP:
	if(i == 0)
	  i = menuItemsSize - 1;
	else
	  i--;
	break;
      case KEY_DOWN:
	if(i == menuItemsSize - 1)
	  i = 0;
	else
	  i++;
	break;
      case '\n':
	switch(i){
	  case 0:
	    viewRules();
	    break;
	  case 1:
	  case 2:
	  case 3:
	  default:
	    curs_set(0);
	    del_panel(winPanel);
	    del_panel(menuPanel);
	    delwin(win);
	    delwin(menu);
	    return;
	}
    }
    wattron(menu, A_STANDOUT);
    mvwaddstr(menu, i*2, 0, menuItems[i]);
    update_panels();
    doupdate();
  }
  curs_set(0);
  del_panel(winPanel);
  del_panel(menuPanel);
  delwin(win);
  delwin(menu);
  return;
  
}

void Display::viewRules(){
  WINDOW* win = newwin(0,0,0,0);
  PANEL* winPanel = new_panel(win);
  auto rules = fw->getRules();
  int line = 2;
  for(int i = 0; i < rules->size(); i++){
    string str = rules->at(i);
    int len = COLS - 3;
    mvwaddnstr(win, line, 2, ((std::to_string(i) += ": ") += str).c_str(), len);
    len -= 2 + std::to_string(i).length();
    line++;
    while(len < str.length()){
      mvwaddnstr(win, line, 2, str.substr(len).c_str(), COLS - 3);
      line++;
      len += COLS - 3;
    }
    line++;
  }
  mvwaddstr(win, line, 2, "Press enter to return to the menu");
  update_panels();
  doupdate();
  while(char ch = getch()){
    if(ch == '\n')
      break;
  }
  del_panel(winPanel);
  delwin(win);
  delete rules;
}
