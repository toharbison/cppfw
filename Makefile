prog: main.o firewall.o
	g++ -std=c++11 -g -o prog main.o firewall.o -lip4tc -lxtables -ldl

main.o: main.cpp firewall.h
	g++ -std=c++11 -g -c main.o main.cpp

firewall.o: firewall.h firewall.cpp
	g++ -std=c++11 -Dtypeof=__typeof__ -g -c firewall.o firewall.cpp

test: prog
	sudo ./prog

clean:
	rm *.o prog
