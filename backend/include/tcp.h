#ifndef __TCP_H__
#define __TCP_H__

#include "grouter.h"
#include "message.h"
#include <stdint.h>

// flags
#define FIN 0x1
#define SYN 0x2
#define RST 0x4
#define PSH 0x8
#define ACK 0x10
#define URG 0x20
#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

// header

typedef struct tcphdr {
	uint16_t src;	// ports
	uint16_t dst; 
	uint32_t seq;   // acks and sequences
	uint32_t ack;
	
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int reserved:4;     
	unsigned int data_off:4;    // data offset
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned int data_off:4;
	unsigned int reserved:4;
#endif

	uint8_t flags;
	uint16_t win;
	uint16_t checksum;
	uint16_t urg;
} tcphdr_t;

// states
enum
{
  ESTABLISHED = 1,
  SYN_SENT,
  SYN_RECV,
  FIN_WAIT1,
  FIN_WAIT2,
  TIME_WAIT,
  CLOSED,
  CLOSE_WAIT,
  LAST_ACK,
  LISTEN,
  CLOSING  
};

// pseudo header size in bytes
#define TCP_PHEADER_SIZE 12

// a port on which to listen on, creates port for you
int tcp_listen(ushort port);

// creates local port for you
int tcp_connect(ushort local, uchar *dest_ip, ushort dest_port);

// only one connection at a time for now, must call connect first
int tcp_send(uchar *buf, int len);

void tcp_recv(gpacket_t *gpkt);

// close current connection
int tcp_close(void);

// receive is done on port, see ports.h

#endif  /*__TCP_H__*/
