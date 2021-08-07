#include "display.hpp"

void Display::start(){
  initscr();
  cbreak();
  noecho();
  keypad(stdscr, true);
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
  while(ch = getch()){
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
    }
    wattron(menu, A_STANDOUT);
    mvwaddstr(menu, i*2, 0, menuItems[i]);
    update_panels();
    doupdate();
  }
  
}
 
