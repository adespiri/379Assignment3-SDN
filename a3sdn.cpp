#include <stdio.h>
#include<iostream>
#include<sys/resource.h>
#include<sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include<vector>
#include<string>
#include<boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h> 
#include <fstream>
#include <poll.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

#define MAX_NSW 7;
#define MAX_IP 1000;
#define MIN_PRI 4;
#define MY_PORT 9698;

using namespace std;

typedef enum {ACK, OPEN, QUERY, ADD, RELAY, CONT_INPUT, SWITCH_INPUT} KIND; //7 different kinds of PACKETS. CONT_INPUT AND SWITCH_INPUT ARE USED FOR POLLING KEYBOARD
typedef enum {DROP, FORWARD } ACTION; //two different kinds of actions

typedef struct {
	int srcIP_lo;
	int srcIP_hi;
	int dstIP_lo;
	int dstIP_hi;
	ACTION actionType;
	int actionVal; //the port to forward to if this field is used
	int pri; //0 highest, 4 lowest
	int pktCount;
} MSG_RULE; //used for the ADD type

typedef struct {
	int packIP_lo;
	int packIP_hi;
	int port1;
	int port2;
	int switchNumber; 
	int sfd;

} MSG_PACKET; //used for OPEN. The switch sends its details to the controller, may have to rework this

typedef struct {
	int srcIP;
	int dstIP;
	int port1;
	int port2;
	int switchNumber;
} MSG_QUERY; //message struct that is used when querying for rules from the controller

typedef struct {
	int srcIP;
	int dstIP;
} MSG_RELAY;

typedef struct {
	char usercmd[20];
} MSG_KEYBOARD;

typedef union { MSG_PACKET packet; MSG_RULE rule; MSG_QUERY query; MSG_RELAY relay; MSG_KEYBOARD keyboard; } MSG; //MSG can be an entire packet or rule or entire switch
typedef struct { KIND kind; MSG msg; } FRAME;

typedef struct {
	int srcIP_lo;
	int srcIP_hi;
	int dstIP_lo;
	int dstIP_hi;
	ACTION actionType;
	int actionVal;
	int pri;
	int pktCount;
} Rule; //rules will be kept in a vector array as part of a switch

typedef struct {
	bool opened;
	int switchNumber;
	char switchIs[10];
	int port1; 
	int port2;
	int IP_lo;
	int IP_hi;
	int keyboardFifo;
	vector<Rule> rulesList;
	int sfd; //each switch now has its own file descriptor

	int admitCounter;
	int ackCounter;
	int addCounter;
	int relayInCounter;
	int openCounter;
	int queryCounter;
	int relayOutCounter;

} Switch; //switch struct

typedef struct {
	int openRcvCounter;
	int queryRcvCounter;
	int ackSentCounter;
	int addSentCounter;
	int keyboardFifo;
	vector<MSG_PACKET> connectedSwitches; //used for when controller acknowledges a new switch
	int sfd; //socket descriptor
} Controller; //controller struct to contain counters

Switch* instanceSwitch;
Controller* instanceController;
bool controllerSelected = false;
bool switchSelected = false; //global variables that will be used when USER1 signal is received

void sendFrame(int fd, KIND kind, MSG *msg) //using lab exercise on eclass as a reference
{
	FRAME frame;
	assert(fd >= 0);
	memset((char *)&frame, 0, sizeof(frame));
	frame.kind = kind;
	frame.msg = *msg;
	write(fd, (char *)&frame, sizeof(frame));

}

int openFIFO(int source, int destination)
{	/*This method opens up a fifo determined by its destination switch number (0 for controller) and destination switch number*/
	char fifoString[20];

	strcpy(fifoString, "fifo-x-y");
	fifoString[5] = source + '0'; //convert to a character and replace x with source Number
	fifoString[7] = destination + '0'; //do the same with y and replace it with destination
	return open(fifoString, O_RDWR);
}

FRAME rcvFrame(int fd)
{ /*This function is taken from the lab exercise on eclass and is used to receive frames from FIFOs
	fd is the file descriptor for the opened FIFO*/
	int    len;
	FRAME  frame;

	assert(fd >= 0);
	memset((char *)&frame, 0, sizeof(frame));
	len = read(fd, (char *)&frame, sizeof(frame));
	
	return frame;
}

void printController(Controller* cont)
{ /* This method will print the controller details*/
	printf("Switch Information: \n");
	//for every switch that is connected, print its details
	for (int i = 0; i < cont->connectedSwitches.size(); i++)
	{
		printf("[sw%d] port1= %d, port2= %d, port3= %d-%d\n", cont->connectedSwitches.at(i).switchNumber,
			cont->connectedSwitches.at(i).port1, cont->connectedSwitches.at(i).port2,
			cont->connectedSwitches.at(i).packIP_lo, cont->connectedSwitches.at(i).packIP_hi);
	}

	printf("\n");
	printf("Packet Stats: \n");
	printf("\tReceived:\tOPEN:%d, QUERY:%d\n", cont->openRcvCounter, cont->queryRcvCounter);
	printf("\tTransmitted:\tACK:%d, ADD:%d\n\n", cont->ackSentCounter, cont->addSentCounter);
}

void sendAckPacket(int switchNumber, int sfd)
{/*	This method is used by the controller to send the acknowledgment packet to the designated switch*/
	FRAME frame;
	frame.kind = ACK;
	write(sfd, (char *)&frame, sizeof(frame));
}

void sendAddPacket(int switchNumber, int SCfifo, MSG* msg)
{	/*this method is used by the controler to send the add packet to the designated switch*/
	FRAME frame;
	frame.kind = ADD;
	frame.msg = *msg;
	write(SCfifo, (char *)&frame, sizeof(frame));

}
//HAVE TO CHANGE THIS
MSG createRule(int port1, int port2, int dstIP, int srcIP,Controller cont)
{	/*Method that creates a rule when a switch queries*/
	MSG msg;
	int dstSwitchNumber;
	int actionVal;

	 //iterate through all of the known connected switches and determine if there are any ip ranges that will accommodate the dstIP
	for (int i = 0; i < cont.connectedSwitches.size(); i++)
	{	
		if (cont.connectedSwitches.at(i).packIP_lo <= dstIP && cont.connectedSwitches.at(i).packIP_hi >= dstIP)
		{	//if the dstIP can fit within the switch under observation, then get switch number
			dstSwitchNumber = cont.connectedSwitches.at(i).switchNumber;

			//ASSUMING switches are in numerical order and there is a linear path from one switch to the next
			//we can compare port1 and port2 to the dstSwitch and we should know which direction to sent the packet
			if (port1 >= dstSwitchNumber) { actionVal = 1; } //send to port1 (left)
			else if (port2 <= dstSwitchNumber) { actionVal = 2; } //send to port2 (right)

			//create rule now that we have which port to send packet to
			msg.rule.srcIP_lo = srcIP;
			msg.rule.srcIP_hi = srcIP;
			msg.rule.dstIP_lo = dstIP;
			msg.rule.dstIP_hi = dstIP + 10; //arbitrarily have the range as 10
			msg.rule.actionType = FORWARD;
			msg.rule.actionVal = actionVal;
			msg.rule.pri = 0; //arbitrary
			msg.rule.pktCount = 0;
			return msg;
		}
	}
	//if there is no switch that can accommodate dstIP, then we need to create a DROP rule 
	msg.rule.srcIP_lo = srcIP;
	msg.rule.srcIP_hi = srcIP;
	msg.rule.dstIP_lo = dstIP;
	msg.rule.dstIP_hi = dstIP + 10; //arbitrarily have the range as 10
	msg.rule.actionType = DROP;
	msg.rule.pri = 0; //arbitrary
	msg.rule.pktCount = 0;
	msg.rule.actionVal = 0;

	return msg;
}

MSG composeKeyboardMessage(char* usercmd)
{			/*create the message that will be sent to the keyboard fifo*/
	MSG msg;
	strcpy(msg.keyboard.usercmd, usercmd);
	return msg;

}

void pollKeyboard(int keyBoardFifo, KIND kind)
{	//the user enters a line into the terminal. the command is sent to keyboardfifo where it will be polled
	while (1) //do indefinitely
	{	
		char usercmd[30];
		cin >> usercmd;


		MSG msg;
		msg = composeKeyboardMessage(usercmd);

		//send it to the appropriate fifo
		sendFrame(keyBoardFifo, kind, &msg);
	}
}

void executeController(int numberofSwitches, const char* portNum)
{	/* This is the main method that will be used for the instance that the controller is chosen*/
	Controller cont;
	instanceController = &cont; //global controller quals cont, FOR USER1SIGNAL handling
	cont.openRcvCounter = 0; //initialize counters
	cont.queryRcvCounter = 0;
	cont.ackSentCounter = 0;
	cont.addSentCounter = 0;
	cont.keyboardFifo = open("fifo-keyboardcont", O_RDWR); //open up keyboard Fifo
	pid_t newpid = fork(); //forking a process which is needed for polling keyboard

	if (newpid == 0) //the child process will go to the keyboard polling state
	{
		pollKeyboard(cont.keyboardFifo, CONT_INPUT);
	}

	
	int newsocket;
	struct sockaddr_storage peer_addr;
	socklen_t addr_size;

	//bind the socket to the localhost
	struct addrinfo hints, *res; //reference from lecture notes and http://beej.us/guide/bgnet/html/multi/syscalls.html#accept
	memset((char*)&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE; //service is port num and fill in ip for me 

	getaddrinfo(NULL, portNum, &hints, &res);
	cont.sfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol); //create the socket and bind it

	if (bind(cont.sfd, res->ai_addr, res->ai_addrlen) < 0)
	{
		perror("Could not bind");
		exit(EXIT_FAILURE); //exit if there is an error
	}

	//after binding we need to set the socket as a listening socket
	if (listen(cont.sfd, numberofSwitches) < 0)
	{
		perror("Could not set socket to listening socket");
		exit(EXIT_FAILURE); //exit if there is an error
	}

	char usercmd[30];
	cout << "Controller Created - supported commands: 'list' and 'exit'" << endl;

	while (1) //main loop
	{	

		//poll the keyboard for user command
		struct pollfd keyboardPoll[1]; //initiate and set values
		keyboardPoll[0].fd = cont.keyboardFifo;
		keyboardPoll[0].events = POLLIN;

		poll(keyboardPoll, 1, 0); //non blocking poll
		if ((keyboardPoll[0].revents&POLLIN) == POLLIN)
		{
			FRAME frame;
			frame = rcvFrame(keyboardPoll[0].fd);
			strcpy(usercmd, frame.msg.keyboard.usercmd);
		}

		if (strcmp(usercmd, "list") == 0)
		{
			printController(&cont);
		}

		else if (strcmp(usercmd, "exit") == 0)
		{
			printController(&cont);
			kill(newpid, SIGKILL);
			return;
		}

		//reset usercmd
		strcpy(usercmd, " ");

		//poll the socket to see if there are any incoming connections
		struct pollfd pollSocket[1], pollSwitch[1];
		pollSocket[0].fd = cont.sfd;
		pollSocket[0].events = POLLIN;

		poll(pollSocket, 1, 0); //non blocking poll to check if there is a new connection attempt
		if ((pollSocket[0].revents&POLLIN) == POLLIN)
		{
			cout << "Attempting to Connect to New Socket..." << endl;
			//now we may accept the next connection 
			newsocket = accept(cont.sfd, (struct sockaddr *) &peer_addr, &addr_size);
			//after accepting the connection we have to wait for the switch details from the
			//incoming switch
			pollSwitch[0].fd = newsocket; //fd for incoming socket
			pollSwitch[0].events = POLLIN;

			poll(pollSwitch, 1, 4); //will timeout after 4 seconds
			if ((pollSwitch[0].revents&POLLIN) == POLLIN)
			{	
				FRAME frame;
				frame = rcvFrame(newsocket);
				cout << "Waiting for Switch Information..." << endl;
				if (frame.kind == OPEN)
				{	
					cont.openRcvCounter += 1;
					//send the switch ACK and increase ACK counter
					cout << "Switch Information Received" << endl;

					//update controller list and counter
					cont.connectedSwitches.push_back(frame.msg.packet);
					sendAckPacket(frame.msg.packet.switchNumber, newsocket); //write ACK frame to socket
					cont.ackSentCounter += 1;
				}

				else
				{
					//if a packet that was sent was not the OPEN type then there is an error
					cout << "Error: Unexpected Packet Type While Waiting for OPEN" << endl;
				}
			}
		}

		//after accepting connection (if any), we poll for any query packets from all the connected switches
		if (cont.connectedSwitches.size() == 0) { continue; }
		struct pollfd pollQuery[cont.connectedSwitches.size()];
		for (int i = 0; i < cont.connectedSwitches.size(); i++)
		{
			pollQuery[i].fd = cont.connectedSwitches.at(i).sfd;
			pollQuery[i].events = POLLIN | POLLHUP;
		}

		poll(pollQuery, cont.connectedSwitches.size(), 0); //non blocking poll
		
		for (int i = 0; i < cont.connectedSwitches.size(); i++)
		{
			//check for each socket whether there is a packet to be read or if the client disconnected
			if ((pollQuery[i].revents&POLLIN) == POLLIN)
			{
				//read the packet, it should be a query packet
				FRAME frame;
				frame = rcvFrame(pollQuery[i].fd);

				if (frame.kind == QUERY)
				{
					MSG msg;
					//create new rule based off dstIP and port numbers
					msg = createRule(frame.msg.query.port1, frame.msg.query.port2, frame.msg.query.dstIP, frame.msg.query.srcIP, cont);

					//send rule to switch and increase counters
					cout << "Sending new rule to switch..." << endl;
					sendAddPacket(frame.msg.query.switchNumber, pollQuery[i].fd, &msg);
					cont.addSentCounter += 1;
					cont.queryRcvCounter += 1;
				}
				else {
					cout << "Error: Unexpected Packet Type While Waiting for QUERY" << endl;
				}
				
			}

			else if ((pollQuery[i].revents&POLLHUP) == POLLHUP)
			{
				//client disconnected, notify the user TODO
				printf("Lost Connection to sw%d\n", cont.connectedSwitches.at(i).switchNumber);
				cont.connectedSwitches.erase(cont.connectedSwitches.begin() + i); //erase the element from the list of connected switches
			}
		}
	}

}

Rule initializeRules(int lowIP, int highIP)
{	//this function will initialize the flow table of the switch with the first default rule
	Rule rule;
	rule.srcIP_lo = 0;
	rule.srcIP_hi = MAX_IP;
	rule.dstIP_lo = lowIP;
	rule.dstIP_hi = highIP;
	rule.actionType = FORWARD;
	rule.actionVal = 3;
	rule.pri = MIN_PRI;
	rule.pktCount = 0;
	return rule;
}

void printFlowTable(Switch* sw)
{
	int i = 0; //keeps track of specific rule number
	//this function will print out the switch info to the terminal screen
	printf("Flow Table: \n");
	char actionString[20];
	
	//print out every table in the rulesList
	for (vector<Rule>::iterator itr = sw->rulesList.begin(); itr != sw->rulesList.end(); itr++)
	{
		if (itr->actionType == FORWARD) { strcpy(actionString,"FORWARD"); }
		else if (itr->actionType == DROP) {strcpy(actionString, "DROP");}
		printf("[%d] (srcIP= %d-%d, destIP= %d-%d, action= %s:%d, pri= %d, pktCount=%d) \n",
			i,itr->srcIP_lo, itr->srcIP_hi, itr->dstIP_lo, itr->dstIP_hi, actionString, itr->actionVal, itr->pri, itr->pktCount);
		i++;
	}
	printf("\n");
	printf("Packet Stats: \n");
	printf("\t Received:\tADMIT:%d, ACK:%d, ADDRULE:%d, RELAYIN:%d \n", sw->admitCounter, sw->ackCounter, sw->addCounter, sw->relayInCounter);
	printf("\t Transmitted:\tOPEN:%d, QUERY:%d, RELAYOUT:%d \n\n", sw->openCounter, sw->queryCounter, sw->relayOutCounter);
}

MSG composeOpenMessage(Switch* sw)
{
	MSG msg;

	msg.packet.port1 = sw->port1;
	msg.packet.port2 = sw->port2;
	msg.packet.packIP_lo = sw->IP_lo;
	msg.packet.packIP_hi = sw->IP_hi;
	msg.packet.switchNumber = sw->switchNumber;
	msg.packet.sfd = sw->sfd;

	return msg;
}

MSG composeQueryMessage(Switch* sw, int dstIP, int srcIP, int switchNumber)
{ /*Creates the message that contains the necessary information for querying*/
	MSG msg;

	msg.query.srcIP = srcIP;
	msg.query.dstIP = dstIP;
	msg.query.port1 = sw->port1;
	msg.query.port2 = sw->port2;
	msg.query.switchNumber = switchNumber;

	return msg;
}

MSG composeRelayMessage(int dstIP, int srcIP)
{	/*Creates message that relays ip addresses*/
	MSG msg;
	msg.relay.srcIP = srcIP;
	msg.relay.dstIP = dstIP;
	return msg;
}

bool sendOpenPacket(int CSfifo, int SCfifo, Switch* sw)
{ /*this method is called when a switch is initialized, it sends the open packet
  to the controller and waits to receive the ACK packet. Returns true if successful*/
	struct pollfd poll_list[1]; //help on using poll from http://www.unixguide.net/unix/programming/2.1.2.shtml
	MSG msg;
	FRAME frame;

	poll_list[0].fd = SCfifo;
	poll_list[0].events = POLLIN;

	msg = composeOpenMessage(sw);
	//send the frame, indicating it is a packet of type OPEN
	sendFrame(CSfifo, OPEN, &msg);
	//use polling and wait for server to send ACK packet
	printf("Waiting for server to acknowledge...\n");
	poll(poll_list, 1, 2000); //wait for two seconds
	if ((poll_list[0].revents&POLLIN) == POLLIN)
	{
		//server wrote to SCfifo
		frame = rcvFrame(SCfifo);
		if (frame.kind == ACK)
		{	//switch is now opened and connected to controller, increment counters
			sw->openCounter += 1;
			sw->ackCounter += 1;
			sw->opened = true;
			printf("Acknowledgement Received... \n");
			return true;
		}

		
	}
	else 
	{	printf("Error communicating with controller \n");
	printf("Either controller is not open or controller capacity is full \n");
		return false; 
	}

}

void sendQueryPacket(int CSfifo, int SCfifo, Switch* sw, int dstIP, int srcIP, int switchNumber)
{ /*this method is called when a switch cannot find a rule for a line in trafficFile, it sends the open packet
  to the controller and waits to receive the ADD packet*/
	struct pollfd poll_list[1];
	MSG msg;
	FRAME frame;

	poll_list[0].fd = SCfifo;
	poll_list[0].events = POLLIN;

	msg = composeQueryMessage(sw, dstIP, srcIP, switchNumber);
	//send the frame, indicating it is a packet of type QUERY
	sendFrame(CSfifo, QUERY, &msg);
	printf("Waiting for server to provide rule...\n");
	poll(poll_list, 1, 2000); //wait for two seconds 
	if ((poll_list[0].revents&POLLIN) == POLLIN)
	{
		//server wrote to SCfifo
		frame = rcvFrame(SCfifo);
		if (frame.kind == ADD)
		{	//switch received the new rule, now must apply it
			Rule rule;
			rule.srcIP_hi = frame.msg.rule.srcIP_hi;
			rule.srcIP_lo = frame.msg.rule.srcIP_lo;
			rule.dstIP_hi = frame.msg.rule.dstIP_hi;
			rule.dstIP_lo = frame.msg.rule.dstIP_lo;
			rule.actionType = frame.msg.rule.actionType;
			rule.actionVal = frame.msg.rule.actionVal;
			rule.pri = frame.msg.rule.pri;
			rule.pktCount = frame.msg.rule.pktCount;
			sw->rulesList.push_back(rule); 
			sw->queryCounter += 1;
			sw->addCounter += 1;
			printf("Rule Received... \n");
			return;
		}


	}
	else { printf("error communicating with controller \n"); return; }
}

void sendRelayPacket(int srcIP, int dstIP, Switch* sw, int selectedFifo)
{	/*We need to relay the packet to eiter port1 or port2. The appropriate FIFO is an input*/
	struct pollfd poll_list[1];
	MSG msg;
	FRAME frame;

	msg = composeRelayMessage(srcIP, dstIP);

	poll_list[0].fd = selectedFifo;
	poll_list[0].events = POLLIN;

	msg = composeRelayMessage(dstIP, srcIP); //compose message

	//send the frame, indicating it is a packet of type RELAY
	sendFrame(selectedFifo, RELAY, &msg);

}

void processPacket(int srcIP, int dstIP, Switch* sw, int p1writeFifo, int p2writeFifo)
{	/*after reading each line the switch will process the packet
	this function is called assuming there already is a rule in the switch rulesList
	for this packet*/
	ACTION actionType;
	int index;
	for (int i = 0; i < sw->rulesList.size(); i++)
	{
		//find the rule that applies to this switch, get its index
		if (sw->rulesList.at(i).dstIP_lo <= dstIP && sw->rulesList.at(i).dstIP_hi >= dstIP) {index = i; }
	}
	
	//now we need to see what the action type is. If it drops the packet do nothing, else we need to relay it
	actionType = sw->rulesList.at(index).actionType;
	if (actionType == DROP) {
		sw->rulesList.at(index).pktCount += 1; //increment counter
		return; }
	else if (actionType == FORWARD)
	{	
		//check if packet is already in correct destination
		if (sw->IP_lo <= dstIP && sw->IP_hi >= dstIP)
		{	//increment admit counter by 1 and return
			sw->admitCounter += 1;
			sw->rulesList.at(index).pktCount += 1;
			return;
		}

		//get the port that msg is being sent to and the necessary fifos
		int sendToPort;
		int selectedFifo;


		sendToPort = sw->rulesList.at(index).actionVal;
		if (sendToPort == 1) { selectedFifo = p1writeFifo; }
		else if (sendToPort == 2) { selectedFifo = p2writeFifo; }

		sendRelayPacket(srcIP, dstIP, sw, selectedFifo);
		sw->relayOutCounter += 1; //increment counter
		sw->rulesList.at(index).pktCount += 1;
	}

}

int checkRuleExists(Switch* sw, int dstIP)
{	/*Checks to see if there exists a rule in the switch with the given IPs, returns index of rule in list if it does exist*/
	for (int i = 0; i < sw->rulesList.size(); i++)
	{
		Rule rule;
		rule = sw->rulesList.at(i);
		if (dstIP <= rule.dstIP_hi && dstIP >= rule.dstIP_lo) return i;
	}
	return -1; //-1 indicates rules does not exist
}

void pollSwitches(Switch* sw, int p1readFifo, int p1writeFifo, int p2readFifo, int p2writeFifo, int SCfifo, int CSfifo)
{	/*This function is called at the end of each switch loop. It polls the ports attached to switches
	and processes any incoming packets*/
	//poll port1 and port2
	struct pollfd pollPorts[2];
	int receivedSrcIP;
	int receivedDstIP; //variables received from fifo

	if (sw->port1 != -1) 
	{
		pollPorts[0].fd = p1readFifo; //setup pollfd struct
		pollPorts[0].events = POLLIN;
	}

	if (sw->port2 != 1)
	{
		pollPorts[1].fd = p2readFifo;
		pollPorts[1].events = POLLIN;
	}

	poll(pollPorts, 2, 0); //do not block

	//if ports were read from we need to process and query packets again
	if ((pollPorts[0].revents&POLLIN) == POLLIN && sw->port1 != -1)
	{	//port1 is read from
		FRAME frame;
		frame = rcvFrame(pollPorts[0].fd);
		printf("Receiving relay from port1\n");
		if (frame.kind == RELAY)
		{
			receivedSrcIP = frame.msg.relay.srcIP;
			receivedDstIP = frame.msg.relay.dstIP;
			sw->relayInCounter += 1; //increment counter
			//check if srcIP and dstIP rule are in current switch
			if (checkRuleExists(sw, receivedDstIP) == -1) //rule does not exists
			{
				cout << "No rule exists in flow table" << endl;
				//send query packet to server
				sendQueryPacket(CSfifo, SCfifo, sw, receivedDstIP, receivedSrcIP, sw->switchNumber);
			}

			//process the packets
			processPacket(receivedSrcIP, receivedDstIP, sw, p1writeFifo, p2writeFifo);
		}
	}

	if ((pollPorts[1].revents&POLLIN) == POLLIN &&  sw->port2 != -1)
	{	//port2 is read from
		FRAME frame;
		frame = rcvFrame(pollPorts[1].fd);
		printf("Receiving relay from port2\n");
		if (frame.kind == RELAY)
		{
			receivedSrcIP = frame.msg.relay.srcIP;
			receivedDstIP = frame.msg.relay.dstIP;
			sw->relayInCounter += 1; //increment counter
			//check if srcIP and dstIP rule are in current switch
			if (checkRuleExists(sw, receivedDstIP) == -1) //rule does not exists
			{
				cout << "No rule exists in flow table" << endl;
				//send query packet to server
				sendQueryPacket(CSfifo, SCfifo, sw, receivedDstIP, receivedSrcIP, sw->switchNumber);
			}

			//process the packets
			processPacket(receivedSrcIP, receivedDstIP, sw, p1writeFifo, p2writeFifo);
		}
	}

}

void getUserCmdSwitch(Switch* sw, int pid)
{	/*This function is used to get user input while in the switch perspective*/
	char usercmd[20] = " ";

	//poll the keyboard for user command
	struct pollfd keyboardPoll[1]; //initiate and set values
	keyboardPoll[0].fd = sw->keyboardFifo;
	keyboardPoll[0].events = POLLIN;
	poll(keyboardPoll, 1, 0); //non blocking poll

	if ((keyboardPoll[0].revents&POLLIN) == POLLIN)
	{
		FRAME frame;
		frame = rcvFrame(keyboardPoll[0].fd);
		strcpy(usercmd, frame.msg.keyboard.usercmd);
	}

	if (strcmp(usercmd, "list") == 0)
	{	//print out list
		printFlowTable(sw); 
		return;
	}

	else if (strcmp(usercmd, "exit") == 0)
	{	//print out list and exit
		printFlowTable(sw);
		kill(pid, SIGKILL); //kill child process when we are done
		exit(1);
		return;
	}

	

}

void delaySwitch(int interval, Switch* sw)
{	/*This function is used when a delay command is read from the trafficFile
	It will delay the switch by the interval amount and still allow polling of neighbouring switches
	and the keyboard*/
	printf("DelaySwitch Reached");
	return;
}

void executeSwitch(char* filename, int port1, int port2 , int lowIP, int highIP, char* thisSwitch, int switchNum)
{	/* This method will be used for the instance that the switch is chosen*/
	//First initialize the switch object
	string line; //initiate trafficfile
	ifstream file(filename);

	if (file.fail()) {
		printf("TRAFFICFILE DOES NOT EXIST\n"); exit(1);
	} //check if file exists


	printf("Switch number %d opened. Type in list or exit command to see switch info\n", switchNum);
	Switch sw;
	instanceSwitch = &sw; //global switch equals sw, FOR USER1SIGNAL handling
	int CSfifo;
	int SCfifo;
	int p1writeFifo;
	int p1readFifo;
	int p2writeFifo;
	int p2readFifo;
	int dstIP;
	int srcIP;

	sw.opened = false;
	sw.port1 = port1;
	sw.port2 = port2;
	strcpy(sw.switchIs, thisSwitch);
	sw.switchNumber = switchNum;
	sw.IP_lo = lowIP;
	sw.IP_hi = highIP;
	sw.admitCounter = 0;
	sw.ackCounter = 0;
	sw.addCounter = 0;
	sw.relayInCounter = 0;
	sw.openCounter = 0;
	sw.queryCounter = 0;
	sw.relayOutCounter = 0;

	 //have to get proper keyboard fifo to read from
	char keyboardFifoString[20];
	strcpy(keyboardFifoString, "fifo-keyboardswY"); //replace the Y with the switch number
	keyboardFifoString[15] = sw.switchNumber + '0';
	sw.keyboardFifo = open(keyboardFifoString, O_RDWR); //open up the keyboard fifo for the switch

	pid_t newpid = fork(); //fork, child will go to polling state
	if (newpid == 0) { pollKeyboard(sw.keyboardFifo, SWITCH_INPUT); }
	
	
	//initialize the first rule 
	sw.rulesList.push_back(initializeRules(lowIP, highIP));

	//open up the FIFOs for this switch/controller pair as well as switch/switch pairs
	CSfifo = openFIFO(sw.switchNumber, 0);
	SCfifo = openFIFO(0, sw.switchNumber);
	
	if (sw.port1 != -1) //-1 indicates null and no connected switch to port 1
	{
		p1writeFifo = openFIFO(sw.switchNumber, sw.port1);
		p1readFifo = openFIFO(sw.port1, sw.switchNumber);
	}

	if (sw.port2 != -1)
	{
		p2writeFifo = openFIFO(sw.switchNumber, sw.port2);
		p2readFifo = openFIFO(sw.port2, sw.switchNumber);
	}

	//send open packet to controller, if not successful, kill child process,return
	if (!sendOpenPacket(CSfifo, SCfifo, &sw)) { kill(newpid, SIGKILL); return; }

	while (1) 
	{
		if (file.good())
		{
			while (getline(file, line))
			{	
				//ignore any comments or white lines or lines where the switch is not the current switch
				if (line[0] == '#' || line[0] == '\r' || line[0] == '\n') {
					continue;
				}
				else if (strcmp(line.substr(0, line.find(" ")).c_str(), sw.switchIs
				)) continue;
		
				/*tokenize read string and determine if any of the rules for the switch apply TOKENIZING was created in reference to lab material 
			*/
				char cline[100];
				char* temp;

				
	
			
				int ruleExist;

				strcpy(cline, line.c_str());
		
				temp = strtok(cline, " "); //temp is now switch name
				temp = strtok(NULL, " "); //temp is now srcIP or 'Delay', if it is delay, we need to delay the switch
				if (temp == "delay") {
					delaySwitch(atoi(strtok(NULL, "\t")), &sw); //grab interval and switch
					continue;
				}
				srcIP = atoi(temp);
				temp = strtok(NULL, " "); //temp is now dstIP or time interval in milliseconds to delay
				dstIP = atoi(temp);

				//first determine if we are going to delay a switch
			

				ruleExist = checkRuleExists(&sw, dstIP); //checkRuleExists returns index of rule if it exists, otherwise it returns -1
				//check if there is a rule that exists with these IP ranges
				if (ruleExist == -1) 
				{
					cout << "No rule exists in flow table" << endl;
					//send query packet to server
					sendQueryPacket(CSfifo, SCfifo, &sw, dstIP, srcIP, sw.switchNumber);
				}

				//relay packet
				processPacket(srcIP, dstIP, &sw, p1writeFifo, p2writeFifo);

				//poll user for command, if any
				getUserCmdSwitch(&sw, newpid);
				
				
				//poll ports 1 and ports 2
				pollSwitches(&sw, p1readFifo, p1writeFifo, p2readFifo, p2writeFifo, SCfifo, CSfifo);
			}
			file.close();
		}

		//once file is done being read we still wait for keystrokes and poll 
		getUserCmdSwitch(&sw, newpid);
		//poll port1 and port2
		pollSwitches(&sw, p1readFifo, p1writeFifo, p2readFifo, p2writeFifo, SCfifo, CSfifo);
	}
	
}

void user1Handler(int signum)
{
	printf("\n");
	printf("\nUSER1 Signal Received... \n\n");
	if (controllerSelected == true) 
	{ 
		printController(instanceController); 
		printf("Please type 'list' or 'exit: "); 
		fflush(stdout); //use of fflush in signalhandler https://stackoverflow.com/questions/1716296/why-does-printf-not-flush-after-the-call-unless-a-newline-is-in-the-format-strin
		return; 
	}
	else if (switchSelected == true) 
	{ 
		printFlowTable(instanceSwitch); 
		printf("Please type 'list' or 'exit': "); 
		fflush(stdout);
		return;
	}
	
}

int main(int argc, char* argv[])
{
	/*There are going to be two categories:
	either the user initiates the program from the view of a controller or they do it from
	the view of a switch
	*/
	signal(SIGUSR1, user1Handler);

	char chosenSwitch[100]; //will be used to determine if command line argument was for a switch and not controller
	strcpy(chosenSwitch, argv[1]);
	
	if (strcmp(argv[1], "cont") == 0 && argc == 4) //compare if argument entered was cont 
	{
		if (atoi(argv[2]) < 1 || atoi(argv[2]) > 7) { printf("Invalid number of switches\n"); return 0; }
		controllerSelected = true;
		executeController(atoi(argv[2]), argv[3]);

	}

	else if (chosenSwitch[0] == 's' && chosenSwitch[1] == 'w' && argc == 6 ) //compare if argument was switch
	{
		if (strlen(chosenSwitch) != 3) 
		{
			printf("Invalid Switch Entered\n"); return 0;
		} //if argument for switch is not the right length i.e sw was entered but not a number

		else if (atoi(&chosenSwitch[2]) > 7 || atoi(&chosenSwitch[2]) < 1) { printf("Not a valid switch\n"); return 0; }
		char* temp;
		int lowIP;
		int highIP;
		char port1[10];
		char port2[10];
		char filename[100];
		int port1num;
		int port2num;

		switchSelected = true;
		strcpy(port1, argv[3]);	//copying main line arguments into actual variables for easier readibility
		strcpy(port2, argv[4]);
		strcpy(filename, argv[2]);
		//parse command to get ip range
		temp = strtok(argv[5], "-");
		lowIP = atoi(temp);
		temp = strtok(NULL, "-");
		highIP = atoi(temp);

		if ((strcmp(port1, "null") != 0) && (atoi(&port1[2]) < 1 || atoi(&port1[2]) > 7)) { printf("Invalid Switches Entered\n"); return 0; }//check if entered switch is valid
		if ((strcmp(port2, "null") != 0) && (atoi(&port2[2]) < 1 || atoi(&port2[2]) > 7)) { printf("Invalid Switches Entered\n"); return 0; }//check if entered switch is valid

		//check if either of the ports is NULL
		if (strcmp(argv[3], "null") == 0)
		{
			port1num = -1;
		}
		else
		{	
			port1num = atoi(&port1[2]);
		}

		if (strcmp(argv[4], "null") == 0)
		{
			port2num = -1;
		}
		else
		{
			port2num = atoi(&port2[2]);
		}

		executeSwitch(filename, port1num, port2num, lowIP, highIP, chosenSwitch, atoi(&chosenSwitch[2]));

	}

	else { printf("Invalid Arguments/Command \n"); }

	return 0;
}
