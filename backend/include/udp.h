#ifndef __UDP_H__
#define __UDP_H__

#include <stdint.h>
#include "message.h"
// header size in octets
#define UDP_HEADER_SIZE 8
#define PHEADER_SIZE 12

// udp header per rfc 768

typedef struct udphdr {
	uint16_t source;  // ports
	uint16_t dest;
	uint16_t len;	  // length of data + header in octets
	uint16_t check;   // checksum value
} udphdr_t;

// returns -1 on error
int send_udp(uchar dest_ip[4], uint16_t dest_port, uint16_t src_port, char *data, uint16_t len);
void udp_recv(gpacket_t *packet);

#endif /* __UDP_H__ */
