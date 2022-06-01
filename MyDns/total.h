//include and link libs
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <Windows.h>
#include <process.h>
#include <time.h>
#include <fstream>
#include <stdbool.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

//constant defination
#define ID_TRANS_SIZE 32 /* The max size of ID_TRANS_TABLE*/
#define DNS_PORT 53 //server's port
#define DNameMaxLen 129 //name's max length

//macro defination
#define BUFSIZE 1024 //dns message's max byte size

//struct defination
typedef struct HEADER {
	unsigned id : 16;      /* query identification number */
	unsigned qr : 1;       /* response flag */
	unsigned opcode : 4;   /* purpose of message */
	unsigned aa : 1;       /* authoritive answer */
	unsigned tc : 1;       /* truncated message */
	unsigned rd : 1;       /* recursion desired */
	unsigned rcode : 4;    /* response code */
	unsigned z : 3;        /* unused bits, must be ZERO */
	unsigned ra : 1;       /* recursion available */
	unsigned qdcount : 16; /* number of question entries */
	unsigned ancount : 16; /* number of answer entries */
	unsigned nscount : 16; /* number of authority entries */
	unsigned arcount : 16; /* number of resource entries */
} HEADER;//dns message's header


typedef struct QUESTION{
	char qname[DNameMaxLen]; //name
	unsigned qtype : 16;  //type
	unsigned qclass : 16; //class
} QUESTION;//dns message's question

typedef struct RR{
	char name[DNameMaxLen]; //name
	unsigned RRtype : 16;  //type
	unsigned RRclass : 16; //class 
	unsigned TTL : 32;     //time to live
	unsigned dataLen : 16; //data length
	char *Rdata;
} RR;//record resource

typedef struct DNS_PACKET {
	HEADER header;       //DNS header
	QUESTION *questions; //questions
	RR *AN;              //answer RR
	RR *NS;              //authority RR
	RR *AR;              //additional RR
} DNS_PACKET;//dns packet


typedef struct DNIPList { 
	char ip[16]; //IP address xxx.xxx.xxx.xxx
	char dn[DNameMaxLen]; //name
	int expire_time;   //exact expire_time
	DNIPList *nextPtr; //pointer to next node
	int length; //NodeList's length, only head node saves this value
} DNIPList;//the list having head node, list stores temporary name-ip table


typedef struct ID_TRANS_CELL {
	unsigned short last_ID; /* The old id*/
	BOOL done;          /*Mark whether the request was analysed completely*/
	SOCKADDR_IN client; /*Requestor socket address*/
	char url[DNameMaxLen]; /*URL*/
	int expire_time;    /*The time to die*/
} ID_TRANS_CELL;//ID translate table, this table stores some initial information in dns message

//function declarations

/// <summary>
/// Get the ip address of domain name
/// </summary>
/// <param name="Local_DNIPList">local table of name and ip</param>
/// <param name="Temp_DNIPList">temporary table of name and ip</param>
/// <param name="url">serch name</param>
/// <returns>
/// successfully return ip address; 
/// failed return string"failed"
/// </returns>
char *Ip_str(DNIPList **Local_DNIPList, DNIPList **Temp_DNIPList, char *url);

/// <summary>
/// Show dns packet
/// </summary>
/// <param name="packet">dns packet</param>
/// <param name="buf">dns message</param>
void Show_DNSPacket(DNS_PACKET packet, char *buf);

/// <summary>
/// read local file , generate the local table's node list and a null temporary table's node list
/// </summary>
/// <param name="local_dniplist"> store local table </param>
/// <param name="extern_dniplist"> store temporary table </param>
void Read_scheurl(DNIPList **local_dniplist, DNIPList **extern_dniplist);

/// <summary>
/// Get the name in dns message
/// </summary>
/// <param name="buf">dns message's pointer </param>
/// <param name="dest">store name </param>
/// <param name="offset">search positon's offset </param>
void Get_TLD(char *buf, char *dest,unsigned long long offset);


/// <summary>
/// Get dns packet form dns message
/// </summary>
/// <param name="buf">dns message </param>
/// <returns>dns packet</returns>
DNS_PACKET receiveDNS(char *buf);

/// <summary>
/// Get name's length
/// </summary>
/// <param name="p">name's start pointer</param>
/// <returns>length of name</returns>
int Get_TLDLength(char *p);

/// <summary>
/// Store dns message information in table and return the index in table
/// </summary>
/// <param name="id">initial id</param>
/// <param name="cli">initial client, where the dns message from </param>
/// <param name="ttl">time to live in this table</param>
/// <param name="url">name</param>
/// <returns>index in the table</returns>
unsigned short generate_new_id(unsigned short id, sockaddr_in cli, int ttl,
			       char *url);

/// <summary>
/// Print our team message
/// </summary>
void print_team_msg();

/// <summary>
/// Get the debug level
/// </summary>
/// <param name="argc">command word number</param>
/// <param name="argv">command word list</param>
void getLevel(int argc, char *argv[]);

/// <summary>
/// Add node to Tempoary List
/// </summary>
/// <param name="extern_dniplist">Tempoary List's head pointer</param>
/// <param name="newNode">the node to add</param>
void addToExternDniplist(DNIPList **extern_dniplist, DNIPList *newNode);

/// <summary>
/// Show dns message
/// </summary>
/// <param name="buf">dns message</param>
/// <param name="length">dns message length</param>
void showBuffer(char *buf, int length);

/// <summary>
/// Receive dns message from local host
/// </summary>
void receiveFromLocal();

/// <summary>
/// Receive dns message from extern DNS
/// </summary>
void receiveFromExtern();

/// <summary>
/// PrintTime
/// </summary>
void PrintTime();

/// <summary>
/// 输出DNS报文回答区段信息
/// </summary>
/// <param name="packet">要打印的DNS报文</param>
/// <param name="level">调试等级</param>
void PrintAnswer(DNS_PACKET packet, char *buf);

