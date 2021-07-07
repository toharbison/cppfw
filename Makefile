prog: main.o firewall.o matches.o targets.o strToIp.o
	g++ -std=c++11 -g -o prog main.o firewall.o targets.o matches.o strToIp.o -lip4tc -lxtables -ldl

main.o: main.cpp firewall.hpp
	g++ -std=c++11 -g -c main.o main.cpp

firewall.o: firewall.hpp firewall.cpp
	g++ -std=c++11 -Dtypeof=__typeof__ -g -c firewall.o firewall.cpp

matches.o: matches.hpp matches.cpp match_headers.hpp
	g++ -std=c++11 -g -c matches.o matches.cpp

targets.o: targets.hpp targets.cpp target_headers.hpp strToIp.hpp
	g++ -std=c++11 -g -c targets.o targets.cpp

strToIp.o: strToIp.hpp strToIp.cpp
	g++ -std=c++11 -g -c strToIp.o strToIp.cpp

test: prog
	sudo ./prog

clean:
	rm *.o prog
