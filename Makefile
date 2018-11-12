all: a3sdn 
clean:
	rm -rf a3sdn submit.tar

tar:
	tar -czf submit.tar a3sdn.cpp Makefile A3SDN_ProjectReport.pdf 
 
a3sdn:	a3sdn.cpp
	g++ a3sdn.cpp -o a3sdn


