all: a3sdn FIFO

clean:
	rm -rf a3sdn fifo-keyboardcont fifo-keyboardsw1 fifo-keyboardsw2 fifo-keyboardsw3 fifo-keyboardsw4 fifo-keyboardsw5 fifo-keyboardsw6 fifo-keyboardsw7 submit.tar

tar:
	tar -czf submit.tar a3sdn.cpp Makefile A3SDN_ProjectReport.pdf 
 
a3sdn:	a2sdn.cpp
	g++ a3sdn.cpp -o a3sdn

FIFO:
	mkfifo fifo-keyboardcont
	mkfifo fifo-keyboardsw1
	mkfifo fifo-keyboardsw2
	mkfifo fifo-keyboardsw3
	mkfifo fifo-keyboardsw4
	mkfifo fifo-keyboardsw5
	mkfifo fifo-keyboardsw6
	mkfifo fifo-keyboardsw7

