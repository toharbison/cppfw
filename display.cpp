#include "display.hpp"

Firewall* fw;

void Display::start(){
  initscr();
  cbreak();
  noecho();
  fw = new Firewall("rules.json");
  menu();
  endwin();
  return;
}

void Display::menu(){
  WINDOW* win = newwin(0,0,0,0);
  WINDOW* menu = newwin(12, 20, 0, 0);
  PANEL* winPanel = new_panel(win);
  PANEL* menuPanel = new_panel(menu);
  int i = 0;
  int ch = 0;
  int menuItemsSize = 6;
  char* menuItems[menuItemsSize] = {"View Rules", "Append Rule", "Insert Rule", "Delete Rule", "Replace Rule", "Quit"};
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
    bool bflag = false;
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
	  case 3:
	    deleteRule();
	    break;
	  case 1:
	    appendRule();
	    break;
	  case 2:
	    insertRule();
	    break;
	  case 4:
	    if(fw->getRules()->empty())
	      mvwaddstr(menu, menuItemsSize*2, 1, "No rules to replace");
	    else
	      replaceRule();
	    break;
	  default:
	    bflag = true;
	    break;
	}
    }
    if(bflag)
      break;
    wattron(menu, A_STANDOUT);
    mvwaddstr(menu, i*2, 0, menuItems[i]);
    update_panels();
    doupdate();
  }
  curs_set(1);
  fw->save();
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
    (str += " ") += rules->at(++i);
    int len = COLS - 3;
    mvwaddnstr(win, line, 2, ((std::to_string(i/2) += ": ") += str).c_str(), len);
    len -= 2 + std::to_string(i/2).length();
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

void Display::deleteRule(){
  WINDOW* win = newwin(0,0,0,0);
  PANEL* winPanel = new_panel(win);
  auto rules = fw->getRules();
  int* lines = new int[rules->size() / 2];
  int line = 2;
  for(int i = 0; i < rules->size(); i++){
    if(i == 0)
      wattron(win, A_STANDOUT);
    lines[i/2] = line;
    string str = rules->at(i);
    (str += " ") += rules->at(++i);
    mvwaddstr(win, line, 2, std::to_string(i/2).c_str());
    int len = COLS - 3 - std::to_string(i/2).size();
    wattroff(win, A_STANDOUT);
    waddnstr(win, (string(": ") += str).c_str(), len);
    len -= 2 + std::to_string(i/2).length();
    line++;
    while(len < str.length()){
      mvwaddnstr(win, line, 2, str.substr(len).c_str(), COLS - 3);
      line++;
      len += COLS - 3;
    }
    line++;
  }
  mvwaddstr(win, line, 2, "Select which rule to delete, or press q to return to menu");
  update_panels();
  doupdate();
  int i = 0;
  keypad(win, true);
  while(int ch = wgetch(win)){
    bool bflag = false;
    wattroff(win, A_STANDOUT);
    mvwaddstr(win, lines[i], 2, std::to_string(i).c_str()); 
    switch(ch){
      case KEY_UP:
	if(i == 0)
	  i = rules->size() / 2 - 1;
	else
	  i--;
	break;
      case KEY_DOWN:
	if(i == rules->size() / 2 - 1)
	  i = 0;
	else
	  i++;
	break;
      case 'q':
	bflag = true;
	break;
      case '\n':
	char str[COLS];
	memset(str, ' ', COLS);
	str[COLS - 1] = '\000';
	mvwaddstr(win, line, 0, str);
	mvwaddstr(win, line, 0, "Are you sure? [y]/n");
	while((ch = wgetch(win)) && rules->size() != 0){
	  bool bflag1 = false;
	  switch(ch){
	    case 'n':
	    case 'N':
	      bflag1 = true;
	      break;
	    case 'y':
	    case 'Y':
	    case '\n':
	      string chain = rules->at(2*i);
	      int j;
	      for(j = i; j > 0; j--){
		if(rules->at((j-1)*2) != chain)
		  break;
	      }
	      fw->removeRule(i - j, chain, "filter");
	      bflag = bflag1 = true;
	      break;
	  }
	  if(bflag1)
	    break;
	}
	break;
    }
    if(bflag)
      break;
    wattron(win, A_STANDOUT);
    mvwaddstr(win, lines[i], 2, std::to_string(i).c_str());
    update_panels();
    doupdate();
  }
  del_panel(winPanel);
  delwin(win);
  delete rules;
}

int Display::selectRule(){
  WINDOW* win = newwin(0,0,0,0);
  PANEL* winPanel = new_panel(win);
  int ret = -1;
  auto rules = fw->getRules();
  int* lines = new int[rules->size() / 2];
  int line = 2;
  for(int i = 0; i < rules->size(); i++){
    if(i == 0)
      wattron(win, A_STANDOUT);
    lines[i/2] = line;
    string str = rules->at(i);
    (str += " ") += rules->at(++i);
    mvwaddstr(win, line, 2, std::to_string(i/2).c_str());
    int len = COLS - 3 - std::to_string(i/2).size();
    wattroff(win, A_STANDOUT);
    waddnstr(win, (string(": ") += str).c_str(), len);
    len -= 2 + std::to_string(i/2).length();
    line++;
    while(len < str.length()){
      mvwaddnstr(win, line, 2, str.substr(len).c_str(), COLS - 3);
      line++;
      len += COLS - 3;
    }
    line++;
  }
  mvwaddstr(win, line, 2, "Select which rule to delete, or press q to return to menu");
  update_panels();
  doupdate();
  int i = 0;
  keypad(win, true);
  while(int ch = wgetch(win)){
    bool bflag = false;
    wattroff(win, A_STANDOUT);
    mvwaddstr(win, lines[i], 2, std::to_string(i).c_str()); 
    switch(ch){
      case KEY_UP:
	if(i == 0)
	  i = rules->size() / 2 - 1;
	else
	  i--;
	break;
      case KEY_DOWN:
	if(i == rules->size() / 2 - 1)
	  i = 0;
	else
	  i++;
	break;
      case 'q':
	bflag = true;
	break;
      case '\n':
	char str[COLS];
	memset(str, ' ', COLS);
	str[COLS - 1] = '\000';
	mvwaddstr(win, line, 0, str);
	mvwaddstr(win, line, 0, "Are you sure? [y]/n");
	while((ch = wgetch(win)) && rules->size() != 0){
	  bool bflag1 = false;
	  switch(ch){
	    case 'n':
	    case 'N':
	      bflag1 = true;
	      break;
	    case 'y':
	    case 'Y':
	    case '\n':
	      ret = i;
	      bflag = bflag1 = true;
	      break;
	  }
	  if(bflag1)
	    break;
	}
	break;
    }
    if(bflag)
      break;
    wattron(win, A_STANDOUT);
    mvwaddstr(win, lines[i], 2, std::to_string(i).c_str());
    update_panels();
    doupdate();
  }
  del_panel(winPanel);
  delwin(win);
  delete rules;
  return ret;
}
void Display::appendRule(){
  WINDOW* win = newwin(0,0,0,0);
  PANEL* winPanel = new_panel(win);
  string chain;
  whline(win, 3, ACS_HLINE);
  const char* chains[3] = {"INPUT", "FOWARD", "OUTPUT"};
  mvwaddstr(win, 1, COLS/2 - 7, "Select Chain Name");
  for(int i = 0; i < 3; i++){
    if(i == 0)
      wattron(win, A_STANDOUT);
    mvwaddstr(win, 5+2*i, 1, chains[i]);
    wattroff(win, A_STANDOUT);
  }
  int i = 0;
  update_panels();
  doupdate();
  keypad(win, true);
  while(int ch = wgetch(win)){
    bool bflag = false;
    wattroff(win, A_STANDOUT);
    mvwaddstr(win, 5+2*i, 1, chains[i]);
    switch(ch){
      case KEY_UP:
	if(i == 0)
	  i = 2;
	else
	  i--;
	break;
      case KEY_DOWN:
	if(i == 2)
	  i = 0;
	else
	  i++;
	break;
      case '\n':
	bflag = true;
	chain = chains[i];
	break;
    }
    if(bflag)
      break;
    wattron(win, A_STANDOUT);
    mvwaddstr(win, 5+2*i, 1, chains[i]);
    update_panels();
    doupdate();
  }
  Rule* rule = createRule();
  if(rule->entryTarget->getName() == "LOG")
    fw->addLog(rule);
  else
    fw->addRule(createRule(), chain);
  del_panel(winPanel);
  delwin(win);
}

string Display::selectChain(){
  WINDOW* win = newwin(0,0,0,0);
  PANEL* winPanel = new_panel(win);
  string chain;
  mvwhline(win, 3, 0, ACS_HLINE, COLS);
  const char* chains[3] = {"INPUT", "FOWARD", "OUTPUT"};
  mvwaddstr(win, 1, COLS/2 - 7, "Select Chain Name");
  for(int i = 0; i < 3; i++){
    if(i == 0)
      wattron(win, A_STANDOUT);
    mvwaddstr(win, 5+2*i, 1, chains[i]);
    wattroff(win, A_STANDOUT);
  }
  int i = 0;
  update_panels();
  doupdate();
  keypad(win, true);
  while(int ch = wgetch(win)){
    bool bflag = false;
    wattroff(win, A_STANDOUT);
    mvwaddstr(win, 5+2*i, 1, chains[i]);
    switch(ch){
      case KEY_UP:
	if(i == 0)
	  i = 2;
	else
	  i--;
	break;
      case KEY_DOWN:
	if(i == 2)
	  i = 0;
	else
	  i++;
	break;
      case '\n':
	bflag = true;
	chain = chains[i];
	break;
    }
    if(bflag)
      break;
    wattron(win, A_STANDOUT);
    mvwaddstr(win, 5+2*i, 1, chains[i]);
    update_panels();
    doupdate();
  }
  del_panel(winPanel);
  delwin(win);
  return chain;
}

void Display::insertRule(){
  string chain = selectChain();
  WINDOW* win = newwin(0,0,0,0);
  PANEL* winPanel = new_panel(win);
  std::vector<string> chainRules;
  auto rules = fw->getRules();
  int line = 0;
  int* lines = nullptr;
  for(int i = 0; i < rules->size(); i += 2){
    if(rules->at(i) == chain)
      chainRules.push_back(rules->at(i + 1));
  }
  lines = new int[chainRules.size() + 1];
  mvwaddstr(win, 1, COLS/2 - 16, "Select position to insert new rule");
  mvwhline(win, 3, 0, ACS_HLINE, COLS);
  for(int i = 0, line = 0; i < chainRules.size(); i++, line++){
    int len;
    lines[i] = line;
    if(i == 0)
      wattron(win, A_STANDOUT);
    mvwaddstr(win, 5+2*line, 1, std::to_string(i).c_str());
    wattroff(win, A_STANDOUT);
    waddnstr(win, (string(": ") += chainRules.at(i)).c_str(), COLS-2-std::to_string(i).size());
    len = COLS - 4 - std::to_string(i).size();
    while(len < chainRules.at(i).size()){
      line++;
      mvwaddnstr(win, 5+2*line, 1, chainRules.at(i).substr(len).c_str(), COLS - 2);
      len += COLS - 2;
    }
  }
  line++;
  lines[chainRules.size()] = line;
  mvwaddstr(win, 5+2*line, 1, (std::to_string(chainRules.size()) += ": ").c_str());
  int i = 0;
  update_panels();
  doupdate();
  while(int ch = wgetch(win)){
    bool bflag = false;
    wattroff(win, A_STANDOUT);
    mvwaddstr(win, 5+2*lines[i], 1, std::to_string(i).c_str());
    switch(ch){
      case KEY_UP:
	if(i == 0)
	  i = chainRules.size();
	else
	  i--;
	break;
      case KEY_DOWN:
	if(i == chainRules.size())
	  i = 0;
	else
	  i++;
	break;
      case '\n':
	bflag = true;
	break;
    }
    if(bflag)
      break;
    wattron(win, A_STANDOUT);
    mvwaddstr(win, 5+2*lines[i], 1, std::to_string(i).c_str());
    update_panels();
    doupdate();
  }
  Rule* rule = createRule();
  if(rule->entryTarget->getName() == "LOG")
    fw->addLog(rule);
  else
    fw->insertRule(createRule(), chain, i);
  del_panel(winPanel);
  delwin(win);
  delete[] lines;
  delete rules;
}

void Display::replaceRule(){
  int num = selectRule();
  auto rules = fw->getRules();
  string chain = rules->at(num * 2);
  int first = num;
  for(int i = 0; i < rules->size()/2; i++){
    if(chain == rules->at(2*num - 2*i) && i != 0)
      first--;
    else if(chain != rules->at(2 * num - 2 * i))
      break;
  }
  fw->replaceRule(createRule(), chain, num - first);
  delete rules;
}



Rule* Display::createRule(){
  Rule* rule = new Rule();
  WINDOW* win = newwin(0,0,0,0);
  WINDOW* menu = newwin(16, COLS - 2, 0, 0);
  PANEL* winPanel = new_panel(win);
  PANEL* menuPanel = new_panel(menu);
  const int menuItemsSize = 8;
  const int matchItemsSize = 8;
  const int targetItemsSize = 27; 
  const char* menuItems[menuItemsSize] = {"Source IP", "Destination IP", "Source Mask", "Destination Mask", "Input Interface", "Output Interface", "Protocol", "Finish"};
  const char* matchItems[matchItemsSize] = {"Addrtype", "Bpf", "Cgroup", "Cluster", "Comment", "Tcp", "Udp", "Icmp"};
  const char* targetItems[targetItemsSize] = {"Accept", "Drop", "Return","Audit", "Checksum", "Classify", "Connmark", "Connsecmark", "Ct", "Dscp", "Tos", "Hmark", "Idletimer", "Led", "Log", "Mark", "Nflog", "Nfqueue", "Rateest", "Secmark", "Synproxy", "Tcpmss", "Tcpoptstrip", "Tee", "Tproxy", "Reject", "Ttl"};
  int i = 0;
  int j = 0;
  int ch = 0;
  mvwhline(win, 3, 0, ACS_HLINE, COLS);
  mvwaddstr(win, 1, COLS / 2 - 22, "Insert specification of packet to match with"); 
  for(i = 0; i < menuItemsSize; i++){
    if(i == 0)
      wattron(menu, A_STANDOUT);
    mvwaddstr(menu, i * 2, 0, menuItems[i]);
    wattroff(menu, A_STANDOUT);
    waddstr(menu, ": ");
  }
  i = 0;
  move_panel(menuPanel, 5, 1);
  update_panels();
  doupdate();
  keypad(menu, true);
  while(ch = wgetch(menu)){
    bool bflag = false;
    wattroff(menu, A_STANDOUT);
    mvwaddstr(menu, i * 2, 0, menuItems[i]);
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
	if(i == menuItemsSize - 1){
	  bflag = true;
	  break;
	}
	waddstr(menu, ": ");
	curs_set(1);
	string str = "";
	update_panels();
	doupdate();
	while(ch = wgetch(menu)){
	  switch(ch){
	    case 127:
	    case KEY_BACKSPACE:
	      mvwdelch(menu, i * 2, getcurx(menu) - 1);
	      break;
	    case '\n':
	      bflag = true;
	      switch(i){
		case 0:
		  rule->srcIp = str;
		  str = "";
		  break;
		case 1:
		  rule->dstIp = str;
		  str = "";
		  break;
		case 2:
		  rule->srcMsk = str;
		  str = "";
		  break;
		case 3:
		  rule->dstMsk = str;
		  str = "";
		  break;
		case 4:
		  rule->iFace = str;
		  str = "";
		  break;
		case 5:
		  rule->oFace = str;
		  str = "";
		  break;
		case 6:
		  if(str == "IP" || str == "ip")
		    rule->proto = IPPROTO_IP; else if(str == "ICMP" || str == "icmp") rule->proto = IPPROTO_ICMP; else if(str == "IGMP" || str == "igmp")
		    rule->proto = IPPROTO_IGMP;
		  else if(str == "IPIP" || str == "ipip")
		    rule->proto = IPPROTO_IPIP;
		  else if(str == "TCP" || str == "tcp")
		    rule->proto = IPPROTO_TCP;
		  else if(str == "EGP" || str == "egp")
		    rule->proto = IPPROTO_EGP;
		  else if(str == "PUP" || str == "pup")
		    rule->proto = IPPROTO_PUP;
		  else if(str == "UDP" || str == "udp")
		    rule->proto = IPPROTO_UDP;
		  else if(str == "IDP" || str == "idp")
		    rule->proto = IPPROTO_IDP;
		  else if(str == "TP" || str == "tp")
		    rule->proto = IPPROTO_TP;
		  else if(str == "DCCP" || str == "dccp")
		    rule->proto = IPPROTO_DCCP;
		  else if(str == "IPV6" || str == "ipv6")
		    rule->proto = IPPROTO_IPV6;
		  else if(str == "RSVP" || str == "rsvp")
		    rule->proto = IPPROTO_RSVP;
		  else if(str == "GRE" || str == "gre")
		    rule->proto = IPPROTO_GRE;
		  else if(str == "ESP" || str == "esp")
		    rule->proto = IPPROTO_ESP;
		  else if(str == "AH" || str == "ah")
		    rule->proto = IPPROTO_AH;
		  else if(str == "MTP" || str == "mtp")
		    rule->proto = IPPROTO_MTP;
		  else if(str == "BEETPH" || str == "beetph")
		    rule->proto = IPPROTO_BEETPH;
		  else if(str == "ENCAP" || str == "encap")
		    rule->proto = IPPROTO_ENCAP;
		  else if(str == "PIM" || str == "pim")
		    rule->proto = IPPROTO_PIM;
		  else if(str == "COMP" || str == "comp")
		    rule->proto = IPPROTO_COMP;
		  else if(str == "SCTP" || str == "sctp")
		    rule->proto = IPPROTO_SCTP;
		  else if(str == "UDPLITE" || str == "udplite")
		    rule->proto = IPPROTO_UDPLITE;
		  else if(str == "MPLS" || str == "mpls")
		    rule->proto = IPPROTO_MPLS;
		  else if(str == "ETHERNET" || str == "ethernet")
		    rule->proto = IPPROTO_ETHERNET;
		  else if(str == "RAW" || str == "raw")
		    rule->proto = IPPROTO_RAW;
		  else if(str == "MPTCP" || str == "mptcp")
		    rule->proto = IPPROTO_MPTCP;
		  else{
		    move(i*2, getcurx(menu) - str.size());
		    for(int j = 0; j < str.size(); j++)
		      wdelch(menu);
		    mvwaddstr(menu, menuItemsSize*2, 0, "Invalid protocol");
		  }
		  str = "";
		  break;
	      }
	    default:
	      str.push_back((char)ch);
	      waddch(menu, ch);
	      break;
	  }
	  update_panels();
	  doupdate();
	  if(bflag){
	    bflag = false;
	    break;
	  }
	}
	break;
    }  
    if(bflag)
      break;
    wattron(menu, A_STANDOUT);
    mvwaddstr(menu, i * 2, 0, menuItems[i]);
    update_panels();
    doupdate();
  }
  move(1,0);
  wclrtoeol(win);
  mvwaddstr(win, 1, COLS/2 - 23, "Select match module to use, press q to finish");
  int maxi = getmaxx(menu)/9;
  int maxj = getmaxy(menu)/2;
  const char* matchTable[maxi][maxj]; 
  werase(menu);
  int x = 0;
  for(i = 0; i < maxi; i++){
    for(j = 0; j < maxj; j++){
      if(x < matchItemsSize){
	if(x == 0)
	  wattron(menu, A_STANDOUT);
	mvwaddstr(menu, j * 2, i * 9, matchItems[x]);
	wattroff(menu, A_STANDOUT);
	matchTable[i][j] = matchItems[x++];
      }
      else
	matchTable[i][j] = nullptr;
    }
  }
  i = j = 0;
  update_panels();
  doupdate();
  while(ch = wgetch(menu)){
    bool bflag = false;
    wattroff(menu, A_STANDOUT);
    mvwaddstr(menu, j * 2, i * 9, matchTable[i][j]);
    switch(ch){
      case KEY_UP:
	if(j == 0){
	  j = maxj - 1;
	  while(matchTable[i][j] == nullptr)
	    j--;
	}
	else
	  j--;
	break;
      case KEY_DOWN:
	if(j == maxj - 1)
	  j = 0;
	else{ 
	  j++;
	  if(matchTable[i][j] == nullptr)
	    j = 0;
	}
	break;
      case KEY_LEFT:
	if(i == 0){
	  i = maxi - 1;
	  while(matchTable[i][j] == nullptr)
	    i--;
	}
	else 
	  i--;
	break;
      case KEY_RIGHT:
	if(i == maxi - 1)
	  i = 0;
	else{ 
	  i++;
	  if(matchTable[i][j] == nullptr)
	    i = 0;
	}
	break;
      case 'q':
	bflag = true;
	break;
      case '\n':{
	werase(menu);
	if(!strcmp(matchTable[i][j], "Addrtype"))
	  rule->entryMatches.push_back(makeAddrtype(menu));
	else if(!strcmp(matchTable[i][j], "Bpf"))
	  rule->entryMatches.push_back(makeBpf(menu));
	else if(!strcmp(matchTable[i][j], "Cgroup"))
	  rule->entryMatches.push_back(makeCgroup(menu));
	else if(!strcmp(matchTable[i][j], "Cluster"))
	  rule->entryMatches.push_back(makeCluster(menu));
	else if(!strcmp(matchTable[i][j], "Comment"))
	  rule->entryMatches.push_back(makeComment(menu));
	else if(!strcmp(matchTable[i][j], "Tcp"))
	  rule->entryMatches.push_back(makeTcp(menu));
	else if(!strcmp(matchTable[i][j], "Udp"))
	  rule->entryMatches.push_back(makeUdp(menu));
	werase(menu);
	for(x = 0; x < maxi; x++){
	  for(int y = 0; y < maxj; y++){
	    mvwaddstr(menu, y*2, x*9, matchTable[x][y]);
	  }
	}
	break;
      }
    }
    if(bflag)
      break;
    wattron(menu, A_STANDOUT);
    mvwaddstr(menu, j * 2, i * 9, matchTable[i][j]);
    update_panels();
    doupdate();
  }
  werase(win);
  werase(menu);
  mvwaddstr(win, 1, COLS/2-12, "Select target of packet");
  maxi = getmaxx(menu)/12;
  const char* targetTable[maxi][maxj];
  x = 0;
  for(j = 0; j < maxj; j++){
    for(i = 0; i < maxi; i++){
      if(x == 0)
	wattron(menu, A_STANDOUT);
      if(x < targetItemsSize){
	mvwaddstr(menu, j*2, i*12, targetItems[x]);
	wattroff(menu, A_STANDOUT);
	targetTable[i][j] = targetItems[x++];
      }
      else
	targetTable[i][j] = nullptr;
    }
  }
  i = j = 0;
  update_panels();
  doupdate();
  keypad(menu, true);
  while(int ch = wgetch(menu)){
    bool bflag = false;
    wattroff(menu, A_STANDOUT);
    mvwaddstr(menu, j*2, i*12, targetTable[i][j]);
    switch(ch){
      case KEY_UP:
	if(j == 0){
	  j = maxj - 1;
	  if(targetTable[i][j] == nullptr)
	    j--;
	}
	else
	  j--;
	break;
      case KEY_DOWN:
	if(j == maxj - 1)
	  j = 0;
	else{
	  j++;
	  if(targetTable[i][j] == nullptr)
	    j = 0;
	}
	break;
      case KEY_LEFT:
	if(i == 0){
	  i = maxi - 1;
	  if(targetTable[i][j] == nullptr)
	    i--;
	}
	else
	  i--;
	break;
      case KEY_RIGHT:
	if(i == maxi - 1)
	  i = 0;
	else{
	  i++;
	  if(targetTable[i][j] == nullptr)
	    i = 0;
	}
	break;
      case '\n':{
	werase(menu);
	bflag = true;
	if(!strcmp(targetTable[i][j], "Accept"))
	  rule->entryTarget = new AcceptTarget();
	else if(!strcmp(targetTable[i][j], "Drop"))
	  rule->entryTarget = new DropTarget();
	else if(!strcmp(targetTable[i][j], "Return"))
	  rule->entryTarget = new ReturnTarget();
	else if(!strcmp(targetTable[i][j], "Log"))
	  rule->entryTarget = makeLog(menu);
	break;
	werase(menu);
      }
    }
    if(bflag)
      break;
    wattron(menu, A_STANDOUT);
    mvwaddstr(menu, j*2, i*12, targetTable[i][j]);
    update_panels();
    doupdate();
  }
  del_panel(winPanel);
  del_panel(menuPanel);
  delwin(win);
  delwin(menu);
  return rule;
}

#define MENUSTART					    \
  keypad(win, true);					    \
  int i = 0;						    \
  for(i = 0; i < optionsSize; i++){			    \
    if(i == 0)						    \
      wattron(win, A_STANDOUT);				    \
    mvwaddstr(win, i*2, 0, options[i]);			    \
    wattroff(win, A_STANDOUT);				    \
    waddstr(win, ": ");					    \
  }							    \
  i = 0;						    \
  while(int ch = wgetch(win)){				    \
    string str = "";					    \
    bool bflag = false;					    \
    wattroff(win, A_STANDOUT);				    \
    mvwaddstr(win, i*2, 0, options[i]);			    \
    switch(ch){						    \
      case KEY_UP:					    \
	if(i == 0)					    \
	  i = optionsSize-1;				    \
	else						    \
	  i--;						    \
	break;						    \
      case KEY_DOWN:					    \
	if(i == optionsSize-1)				    \
	  i = 0;					    \
	else						    \
	  i++;						    \
	break;						    \
      case 'q':						    \
	bflag = true;					    \
	break;						    \
      case '\n':					    \
	waddstr(win, ": ");				    \
	curs_set(1);					    \

#define MENUEND						    \
	curs_set(0);					    \
	break;						    \
    }							    \
    if(bflag)						    \
      break;						    \
    wattron(win, A_STANDOUT);				    \
    mvwaddstr(win, i*2, 0, options[i]);			    \
    update_panels();					    \
    doupdate();						    \
  }							    \

Match* Display::makeAddrtype(WINDOW* win){
  AddrtypeMatch* match = new AddrtypeMatch();
  const int optionsSize = 4;
  char* options[optionsSize] = {"Source Type", "Destination Type", "Limit Incoming Interface", "Limit Outgoing Interface"}; 
  MENUSTART
  while(ch = wgetch(win)){
    switch(ch){
      case 127:
      case KEY_BACKSPACE:
	if(!str.empty()){
	  mvwdelch(win, i*2, getcurx(win) - 1);
	  str.pop_back();
	}
	break;
      case '\n':
	bflag = true;
	wmove(win, optionsSize*2 - 1, 0);
	wdeleteln(win);
	switch(i){
	  case 0:
	  case 1:{
	    unsigned short type = 0;
	    if(str.find("UNSPEC") != string::npos || str.find("unspec") != string::npos)
	      type |= XT_ADDRTYPE_UNSPEC;
	    else if(str.find("UNICAST") != string::npos || str.find("unicast") != string::npos)
	      type |= XT_ADDRTYPE_UNICAST;
	    else if(str.find("LOCAL") != string::npos || str.find("local") != string::npos)
	      type |= XT_ADDRTYPE_LOCAL;
	    else if(str.find("BROADCAST") != string::npos || str.find("broadcast") != string::npos)
	      type |= XT_ADDRTYPE_BROADCAST;
	    else if(str.find("ANYCAST") != string::npos || str.find("anycast") != string::npos)
	      type |= XT_ADDRTYPE_ANYCAST;
	    else if(str.find("MULTICAST") != string::npos || str.find("multicast") != string::npos)
	      type |= XT_ADDRTYPE_MULTICAST;
	    else if(str.find("BLACKHOLE") != string::npos || str.find("blackhole") != string::npos)
	      type |= XT_ADDRTYPE_BLACKHOLE;
	    else if(str.find("UNREACHABLE") != string::npos || str.find("unreachable") != string::npos)
	      type |= XT_ADDRTYPE_UNREACHABLE;
	    else if(str.find("PROHIBIT") != string::npos || str.find("prohibit") != string::npos)
	      type |= XT_ADDRTYPE_PROHIBIT;
	    else if(str.find("THROW") != string::npos || str.find("throw") != string::npos)
	      type |= XT_ADDRTYPE_THROW;
	    else if(str.find("NAT") != string::npos || str.find("nat") != string::npos)
	      type |= XT_ADDRTYPE_NAT;
	    else if(str.find("XRESOLVE") != string::npos || str.find("xresolve") != string::npos)
	      type |= XT_ADDRTYPE_XRESOLVE;
	    else{
	      mvwaddstr(win, optionsSize*2, 0, "No recognized address types detected");
	      break;
	    }
	    if(i == 0)
	      match->setSrc(type, str.find('!') != string::npos);
	    else
	      match->setSrc(type, str.find('!') != string::npos);
	    break;
	  }
	  case 2:
	  case 3:
	    if(str.find("y") != string::npos || str.find("Y") != string::npos || str.find("yes") != string::npos ||
		str.find("YES") != string::npos || str.find("Yes") != string::npos){
	      if(i == 3)
		match->limitIFace();
	      else
		match->limitOFace();
	    }
	    break;
	}
	break;
      default:
	str.push_back((char)ch);
	waddch(win, ch);
	break;
    } 
    if(bflag){
      bflag = false;
      break;
    }
  }
  MENUEND
  return (Match*)match;
}

Match* Display::makeBpf(WINDOW* win){
  BpfMatch* match = new BpfMatch();
  const int optionsSize = 3;
  const char* options[optionsSize] = {"Object Path", "Program Path", "Byte code"};
  MENUSTART
  while(ch = wgetch(win)){
    switch(ch){
      case 127:
      case KEY_BACKSPACE:
	if(!str.empty()){
	  mvwdelch(win, i*2, getcurx(win) - 1);
	  str.pop_back();
	}
	break;
      default:
	str.push_back((char)ch);
	waddch(win, ch);
	break;
      case '\n':{
	bflag = true;
	switch(i){
	  case 0:
	    match->setPath(str);
	    break;
	  case 1:
	    match->setPinPath(str);
	    break;
	  case 2:
	    match->setProg(str);
	    break;
	  }
	break;
      }
    }
    if(bflag){
      break;
    }
    update_panels();
    doupdate();
  }
  MENUEND
  return match;
}

Match* Display::makeCgroup(WINDOW* win){
  CgroupMatch* match = new CgroupMatch();
  const int optionsSize = 2;
  const char* options[optionsSize] = {"Path", "Class Id"};
  MENUSTART
  while(ch = wgetch(win)){
    switch(ch){
      case 127:
      case KEY_BACKSPACE:
	if(!str.empty()){
	  mvwdelch(win, 2*i, getcurx(win) - 1);
	  str.pop_back();
	}
	break;
      default:
	str.push_back((char)ch);
	waddch(win, ch);
	break;
      case '\n':
	bflag = true;
	switch(i){
	  case 0:
	    if(str.at(0) == '!')
	      match->setPath(str.substr(1), true);
	    else
	      match->setPath(str);
	    break;
	  case 1:
	    if(str.at(0) == '!')
	      match->setClassId(stoul(str.substr(1)), true);
	    else
	      match->setClassId(stoul(str));
	    break;
	}
	break;
    }
    if(bflag)
      break;
    update_panels();
    doupdate();
  }
  MENUEND
  return match;
}

Match* Display::makeCluster(WINDOW* win){
  ClusterMatch* match = new ClusterMatch();
  const int optionsSize = 3;
  const char* options[optionsSize] = {"Number of Nodes", "Node Mask", "Hash Seed"};
  MENUSTART
  while(ch = wgetch(win)){
    switch(ch){
      case 127:
      case KEY_BACKSPACE:
	if(!str.empty()){
	  mvwdelch(win, i*2, getcurx(win)-1);
	  str.pop_back();
	}
	break;
      default:
	str.push_back((char)ch);
	waddch(win, ch);
	break;
      case '\n':
	bflag = true;
	switch(i){
	  case 0:
	    match->setNumNodes(stoul(str));
	    break;
	  case 1:
	    if(str.at(0) == '!'){
	      match->setNodeMask(stoul(str.substr(1)));
	      match->invertMask();
	    }
	    else
	      match->setNodeMask(stoul(str));
	    break;
	  case 2:
	    match->setSeed(stoul(str));
	    break;
	}
	break;
    }
    if(bflag){
      bflag = false;
      break;
    }
    update_panels();
    doupdate();
  }
  MENUEND
  return match;
}

Match* Display::makeComment(WINDOW* win){
  CommentMatch* match = new CommentMatch();
  const int optionsSize = 1;
  const char* options[optionsSize] = {"Comment"};
  MENUSTART
  while(ch = wgetch(win)){
    switch(ch){
      case 127:
      case KEY_BACKSPACE:
	if(!str.empty()){
	  mvwdelch(win, i*2, getcurx(win)-1);
	  str.pop_back();
	}
	break;
      default:
	str.push_back((char)ch);
	waddch(win, ch);
	break;
      case '\n':
	bflag = true;
	match->setComment(str);
	break;
    }
    if(bflag)
      break;
    update_panels();
    doupdate();
  }
  MENUEND
  return match;
}

Match* Display::makeTcp(WINDOW* win){
  TcpMatch* match = new TcpMatch();
  const int optionsSize = 4;
  const char* options[optionsSize] = {"Source Ports", "Destination Ports", "Flags to Watch", "Flags to be Set"};
  unsigned short mask = 0, cmp = 0;
  MENUSTART
  int x = getcurx(win);
  wmove(win, optionsSize*2, 0);
  wclrtoeol(win);
  wmove(win, i*2, x);
  while(ch = wgetch(win)){
    switch(ch){
      case 127:
      case KEY_BACKSPACE:
	if(!str.empty()){
	  mvwdelch(win, i*2, getcurx(win)-1);
	  str.pop_back();
	}
	break;
      default:
	str.push_back((char)ch);
	waddch(win, ch);
	break;
      case '\n':{
	bflag = true;
	switch(i){
	  case 0:
	  case 1:{
	    int pos = 0;
	    bool inv = false;
	    if(str.at(0) == '!'){
	      inv = true;
	      str = str.substr(1);
	    }
	    if((pos = str.find(' ')) != -1 || (pos = str.find(',')) != -1){
	      if(i == 0)
		match->setSrcPorts(stoul(str.substr(0,pos)), stoul(str.substr(pos+1)), inv);
	      else
		match->setDstPorts(stoul(str.substr(0,pos)), stoul(str.substr(pos+1)), inv);
	    }
	    else
	      mvwaddstr(win, optionsSize*2, 0, "Please deliminate ports with either a space or comma");
	    break;
	  }
	  case 3:
	  case 4:{
	    unsigned short flags = 0;
	    if(str.find("fin") != -1 || str.find("FIN") != -1)
	      flags |= FIN;
	    else if(str.find("SYN") != -1 || str.find("syn") != -1)
	      flags |= SYN;
	    else if(str.find("RST") != -1 || str.find("rst") != -1)
	      flags |= RST;
	    else if(str.find("PSH") != -1 || str.find("psh") != -1)
	      flags |= PSH;
	    else if(str.find("ACK") != -1 || str.find("ack") != -1)
	      flags |= ACK;
	    else if(str.find("URG") != -1 || str.find("urg") != -1)
	      flags |= URG;
	    else if(str.find("ECN") != -1 || str.find("ecn") != -1)
	      flags |= ECN;
	    else if(str.find("CWR") != -1 || str.find("cwr") != -1)
	      flags |= CWR;
	    else{
	      mvwaddstr(win, optionsSize*2, 0, "Unrecognized tcp flag(s)");
	      break;
	    }
	    if(i == 3)
	      mask = flags;
	    else
	      cmp = flags;
	    break;
	  }
	}
	break;
      }
    }
    if(bflag){
      bflag = false;
      break;
    }
  }
  MENUEND
  match->setFlags(mask, cmp);
  return match;
}

Match* Display::makeUdp(WINDOW* win){
  UdpMatch* match = new UdpMatch();
  const int optionsSize = 2;
  const char* options[optionsSize] = {"Source Ports", "Destination Ports"};
  MENUSTART
  int x = getcurx(win);
  wmove(win, optionsSize*2, 0);
  wclrtoeol(win);
  wmove(win, i*2, x);
  while(ch = wgetch(win)){
    switch(ch){
      case 127:
      case KEY_BACKSPACE:
	if(!str.empty()){
	  mvwdelch(win, i*2, getcurx(win)-1);
	  str.pop_back();
	}
	break;
      default:
	str.push_back((char)ch);
	waddch(win, ch);
	break;
      case '\n':{
	bflag = true;
	int pos = 0;
	bool inv = false;
	if(str.at(0) == '!'){
	  str = str.substr(1);
	  inv = true;
	}
	if((pos = str.find(' ')) != -1 || (pos = str.find(',')) != -1){
	  if(i == 0)
	    match->setSrcPorts(stoul(str.substr(0, pos)), stoul(str.substr(pos + 1)), inv);
	  else
	    match->setDstPorts(stoul(str.substr(0, pos)), stoul(str.substr(pos + 1)), inv);
	}
	else
	  mvwaddstr(win, optionsSize*2, 0, "Please deliminate port numbers with either a space or comma");
      }
    }
    if(bflag){
      bflag = false;
      break;
    }
    update_panels();
    doupdate();
  }
  MENUEND
  return match;
}

   

Target* Display::makeLog(WINDOW* win){
  LogTarget* target = new LogTarget();
  const int optionsSize = 2;
  const char* options[optionsSize] = {"Prefix", "Level"};
  MENUSTART
  while(ch = wgetch(win)){
    switch(ch){
      case KEY_BACKSPACE:
      case 127:
	if(!str.empty()){
	  mvwdelch(win, 2*i, getcurx(win)-1);
	  str.pop_back();
	}
	break;
      default:
	str.push_back((char)ch);
	waddch(win, ch);
	break;
      case '\n':
	bflag = true;
	if(i == 0){
	  target->setPrefix(str.substr(0, 30));
	  str = "";
	}
	else{
	  target->setLevel(stoul(str));
	  str = "";
	}
	break;
    }
    if(bflag){
      bflag = false;
      break;
    }
    update_panels();
    doupdate();
  }
  MENUEND
  return target;
}


