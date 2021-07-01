#ifndef STR_TO_IP_H
#define STR_TO_IP_H

#include <string>
#include <algorithm>
#include <linux/netfilter.h>

typedef std::string string;

in_addr strToInAddr(string str){
  union{
    unsigned int val;
    unsigned char bytes[4];
  } be;
  in_addr ret;

  for(int i = 0, j = 0; i < 4; i++){
    int pos = str.find('.', j);
    be.bytes[i] = stoi(str.substr(j, pos));
    j = ++pos;
  }
  ret.s_addr = be.val;
  return ret;
}

nf_inet_addr strToNfAddr(string str){
  nf_inet_addr ret;
  memset(ret.all, 0, 16);
  if(str.find('.') != string::npos){
    ret.in = strToInAddr(str);
  }
  else{
    union{
      unsigned int val;
      unsigned short halves[2];
      unsigned char bytes[4];
    } le, be;
    if(int pos = str.find("::")){
      if(pos + 1 == str.size() - 1)
	str.pop_back();
      for(int i = std::count(str.begin(), str.end(), ':'); i <= 8; i++)
	str.insert(pos + 1, ":0000");
      str.erase(pos, 1);
    }
    for(int i = 0, j = 0; i < 4; i++){
      int pos = str.find(':', j);
      le.halves[1] = stoi(str.substr(j, pos), nullptr, 16);
      j = ++pos;
      pos = str.find(':', j);
      le.halves[0] = stoi(str.substr(j, pos), nullptr, 16);
      std::reverse_copy(le.bytes, le.bytes + 4, be.bytes);
      ret.ip6[i] = be.val;
      j = ++pos;
    }
  }
  return ret;
}
#endif
