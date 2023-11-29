// ------------------------------------------------
// ICMP-IP Header File.
//
// Author: Jesus Camara (jesus.camara@infor.uva.es)
// ------------------------------------------------

// Network Libraries
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SIZE 64 // Payload Size

/* IPv4 Header Definition
  | ==================================================================================== |
  |  4 bits  |  4 bits  |       8 bits        |  3 bits  |           13 bits             |
  | ======== | ======== | =================== | ======================================== |
  |  Version |    HL	 |   Type of Service   |               Total Length                 |
  | ------------------------------------------------------------------------------------ |
  |                Identifier                 |   Flags  |        Fragment Offset        |
  | ------------------------------------------------------------------------------------ |
  |     Time-to-Live    |       Protocol      |              Header Checksum             |
  | ------------------------------------------------------------------------------------ |
  |                                     Source Address                                   |
  | ------------------------------------------------------------------------------------ |
  |                                  Destination Address                                 |
  | ------------------------------------------------------------------------------------ |
*/
typedef struct sIPHeader
{
  unsigned char VHL;           // IP_Version + Header_Length
  unsigned char ToS;           // Type of Service
  short int TotLeng;           // Total Datagram Length.
  short int ID;                // Datagram ID.
  short int FlagOff;           // Flag + Fragment_Offset
  unsigned char TTL;           // Time-to-Live
  unsigned char Protocol;      // Higher-Level Protocol.
  unsigned short int Checksum; // Header Checksum Value.
  struct in_addr iaSrc;        // Source IP Address
  struct in_addr iaDst;        // Destination IP Address
} IPHeader;

/* ICMP Header Definition
  | ========================================= |
  |  1 byte  |  1 byte  |       2 bytes       |
  | ======== | ======== | =================== |
  |   Type	  |   Code	 |       Checksum      |
  | ----------------------------------------- |
*/
typedef struct tsICMPHeader
{
  unsigned char type;          // Type of ICMP Message
  unsigned char code;          // Code Related to Type
  unsigned short int checksum; // Integer to Check Datagram Integrity
} ICMPHeader;

/* ICMP Echo Request Datagram
  | ========================================= |
  |  1 byte  |  1 byte  |       2 bytes       |
  | ======== | ======== | =================== |
  |   Type	  |   Code	 |       Checksum      |
  | ----------------------------------------- |
  |      Identifier     |     Seq. Number     |
  | ----------------------------------------- |
  |         Payload (variable length)         |
  | ----------------------------------------- |
*/
typedef struct typeICMPRequest
{
  ICMPHeader icmpHdr;          // ICMP Header
  unsigned short int pid;      // Process ID.
  unsigned short int sequence; // Sequence Number
  char payload[SIZE];          // Arbitrary String
} EchoRequest;

/* ICMP Echo Reply Datagram
  | ========================================= |
  |     20 bytes     |        Variable        |
  | ================ | ====================== |
  |     IP Header	  |      ICMP Message      |
  | ----------------------------------------- |
*/
typedef struct tsICMPReply
{
  IPHeader ipHdr;      // IP Header
  EchoRequest icmpMsg; // ICMP Message
} EchoReply;

