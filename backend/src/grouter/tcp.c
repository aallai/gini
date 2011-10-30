#include "ports.h"
#include "tcp.h"
#include "protocols.h"
#include "message.h"
#include <stdlib.h>

/** state variables, only one active connection so there not in a struct
 * our version of the TCB from the rfc
 * might need to put this in a struct later, since all this needs to be reset
 * for every new connection **/

int state = CLOSED;                // the actual connection state 

// ports, addresses
uint16_t local_port;
uchar remote_ip[4];
uint16_t remote_port;

// for send
unsigned long snd_nxt;    // next
unsigned long snd_una;    // unacknowledged
unsigned long snd_win;    // window
unsigned long iss;        // inital sequence umber

// for receive
unsigned long recv_nxt;   // next
unsigned long recv_win;   // window
unsigned long irs;        // initial sequence number

#define BUFSIZE 65535

uchar snd_data[BUFSIZE] = {0};
uchar rcv_data[BUFSIZE] = {0};
 
// returns 0 on error

int listen(ushort port)
{
	if (!open_port(port, TCP_PROTOCOL)) {
		return 0;
	}	

	local_port = port;

	state = LISTEN;

	return 1;
}

// do we have this block until connection is established? maybe
int connect(ushort local, uchar *dest_ip, ushort dest_port)
{
	if (!open_port(port, TCP_PROTOCOL)) {
                return 0;
        }

	local_port = port;
	memcpy(remote_ip, dest_ip, 4);
	remote_port = dest_port;

	// send a SYN packet 
	// calloc gives zeroed out mem
	gpacket_t *gpkt = calloc(1, sizeof(gpacket_t));

	if (gpkt == NULL) {
		return 0;
	}

	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	ip->ip_hdr_len = 5;

	tcphdr_t *hdr = (uchar *) ip + ip->ip_hdr_len * 4;
		
}

tcp_recv(gpacket_t *)

int close()
{
	// must keep receiving until remote end also closes
}
