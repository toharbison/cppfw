#ifndef DISPLAY_CPP
#define DISPLAY_CPP

#include<ncurses.h>

class Display{
  public:
  static void start(){
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, true);
    mvhline(LINES - 5, 0, ACS_HLINE, COLS);
    //mvaddch(LINES - 3, 1, ACS_BLOCK | A_BLINK);
    mvaddch(LINES - 3, 1, '#');
    refresh();
    getch();
    endwin();
    return;
  }
};

#endif
