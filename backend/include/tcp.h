#ifndef __TCP_H__
#define __TCP_H__

#include <stdint.h>

// flags
#define FIN 0x1
#define SYN 0x2
#define RST 0x4
#define PSH 0x8
#define ACK 0x10
#define URG 0x20

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

// a port on which to listen on, creates port for you
int listen(ushort port);

// creates local port for you
int connect(ushort local, uchar *dest_ip, ushort dest_port);

// only one connection at a time for now, must call connect first
int send(char *buf, int len);

// close current connection
int close(void);

// receive is done on port, see ports.h

#endif  /*__TCP_H__*/
