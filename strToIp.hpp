#ifndef STR_TO_IP_H
#define STR_TO_IP_H

#include <string>
#include <linux/netfilter.h>

typedef std::string string;

in_addr strToInAddr(string str);

nf_inet_addr strToNfAddr(string str);

string ipToStr(in_addr);
#endif
