prog: main.o firewall.o
	g++ -std=c++11 -g -o prog main.o firewall.o -lip4tc -lxtables -ldl

main.o: main.cpp firewall.hpp
	g++ -std=c++11 -g -c main.o main.cpp

firewall.o: firewall.hpp firewall.cpp
	g++ -std=c++11 -Dtypeof=__typeof__ -g -c firewall.o firewall.cpp

match.o: match.hpp match.cpp match_headers.hpp
	g++ -std=c++11 -g -c matches.o matches.cpp

targets.o: targets.hpp targets.cpp target_headers.hpp strToIp.hpp
	g++ -std=c++11 -g -c targets.o targets.cpp

test: prog
	sudo ./prog

clean:
	rm *.o prog
