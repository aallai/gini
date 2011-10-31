
#include "ports.h"
#include "tcp.h"
#include "ip.h"
#include "protocols.h"
#include "message.h"
#include "grouter.h"
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

/** state variables, only one active connection so there not in a struct
 * our version of the TCB from the rfc
 * might need to put this in a struct later, since all this needs to be reset
 * for every new connection **/

// will have to threadsafe this
int state = CLOSED;                // the actual connection state 
pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;

// ports, addresses
uint16_t local_port;
uchar remote_ip[4];
uint16_t remote_port;

// for send
unsigned long snd_nxt;    // next
unsigned long snd_una;    // unacknowledged
unsigned long snd_win;    // window
unsigned long iss;        // inital sequence number

// for receive
unsigned long recv_nxt;   // next
unsigned long recv_win = BUFSIZE;   // window
unsigned long irs;        // initial sequence number

#define BUFSIZE 65535

int recv_off = 0;
int snd_off = 0;
uchar snd_data[BUFSIZE] = {0};
uchar rcv_data[BUFSIZE] = {0};

int read_state() 
{
	int ret;
	pthread_mutex_lock(&state_lock);
	ret = state;
	pthread_mutex_unlock(&state_lock);
	return ret;
}

void set_state(int val) 
{
	pthread_mutex_lock(&state_lock);
	state = val;
	pthread_mutex_unlock(&state_lock);
}

void reset_state()
{

}

// assumes the data is right after the tcp header
uint16_t tcp_checksum(uchar *src, uchar *dst, tcphdr_t *hdr, int data_len)
{
	uchar buf[TCP_PHEADER_SIZE + DEFAULT_MTU] = {0};

	memcpy(buf, src, 4);
	memcpy(buf + 4, dst, 4);
	buf[9] = TCP_PROTOCOL;
	((ushort *) buf)[5] = hdr->data_off * 4 + data_len

		memcpy(buf + TCP_PHEADER_SIZE, hdr, hdr->data_off * 4);
	memcpy(buf + TCP_PHEADER_SIZE + hdr->data_off * 4, (uchar *) hdr + hdr->data_off * 4, data_len);

	if (data_len % 2 != 0) {
		data_len++;
	}	

	return checksum(buf, (TCP_PHEADER_SIZE + hdr->data_off * 4 + data_len) / 2);
} 

uint32_t sequence_gen()
{
	return (uint32_t) clock();
}



// returns 0 on error
int listen(ushort port)
{
	if (!open_port(port, TCP_PROTOCOL)) {
		return 0;
	}	

	local_port = port;

	set_state(LISTEN);

	return 1;
}

// do we have this block until connection is established? maybe
int connect(ushort local, uchar *dest_ip, ushort dest_port)
{
	if (read_state() != CLOSED) {
		return 0;
	}

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

	iss = sequence_gen();
	snd_una = iss;
	snd_nxt = iss + 1;

	getsrcaddr(gpkt, dest_ip);
	uchar tmpbuf[4] = {0};
	COPYIP(ip->ip_dst, gHtonl(tmp, dest_ip));

	hdr->src = htons(local_port);
	hdr->dst = htons(remote_port);
	hdr->seq = htonl(iss);
	hdr->data_off = 5;
	hdr->flags = SYN;
	hdr->checksum = 0;

	// I THINK WINDOW CAN BE ZERO FOR FIRST SYN

	hdr->checksum = htons(tcp_checksum(ip->ip_src, ip->ip_dst, hdr, 0));
	if (hdr->checksum == 0) {
		hdr->checksum = ~hdr->checksum;
	}				

	IPOutgoingPacket(gpkt, remote_ip, hdr->data_off * 4, 1, TCP_PROTOCOL);

	set_state(SYN_SENT);

	return 1;		
}

// send a RST in response to segment gpkt
void send_rst(gpackt_t *gpkt)
{
	uchar tmp[4];
	uint16_t tmp_port;

	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	tcphdr_t *hdr = (tcphdr_t *) (uchar *) ip + ip->ip_hdr_len * 4;

	if (hdr->flags & ACK) {
		hdr->seq = hdr->ack;
		hdr->flags = RST;
	} else {
		hdr->ack = htonl(ntohl(hdr->seq) + ntohs(ip->ip_pkt_len) - ip->ip_hdr_len * 4 - hdr->data_off * 4);
		hdr->seq = 0;
		hdr->flags = RST | ACK;
	}	 	

	tmp_port = hdr->src;
	hdr->src = hdr->dst;
	hdr->dst = tmp_port;
	hdr->data_off = 5;
	hdr->win = 0;
	hdr->urg = 0
		hdr->checksum = 0;

	// src and dst are flipped
	hdr->checksum = htons(tcp_checksum(ip->ip_dst, ip->ip_src, hdr, 0));

	if (hdr->checksum == 0) {
		hdr->checksum = ~hdr->checksum;
	}

	IPOutgoingPacket(gpkt, gNtohl(tmp, ip->ip_src), hdr->data_off * 4, 0, TCP_PROTOCOL);
}

// send syn-ack in response to syn segment gpkt
void send_synack(gpacket_t *gpkt)
{
	uchar tmp[4];
	uint16_t tmp_port;

	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	tcphdr_t *hdr = (tcphdr_t *) (uchar *) ip + ip->ip_hdr_len * 4; 

	hdr->flags = SYN | ACK;
	tmp_port = hdr->src;
	hdr->src = hdr-src;
	hdr->src = tmp_port;

	hdr->ack = htonl(recv_nxt);
	hdr->seq = htonl(iss);
	hdr->data_off = 5;
	hdr->win = htonl(recv_win);
	hdr->urg = 0;
	hdr->checksum = 0;

	// src and dst are flipped
	hdr->checksum = htons(tcp_checksum(ip->ip_dst, ip->ip_src, hdr, 0));

	if (hdr->checksum == 0) {
		hdr->checksum = ~hdr->checksum;
	}

	IPOutgoingPacket(gpkt, gNtohl(tmp, ip->ip_src), hdr->data_off * 4, 0, TCP_PROTOCOL);
}

// process incoming segment in closed state
void incoming_closed(gpaket_t *gpkt)
{
	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	tcphdr_t *hdr = (tcphdr_t *) (uchar *) ip + ip->ip_hdr_len * 4;

	if (hdr->flags & RST) {
		free(gpkt);
	} else {
		send_rst(gpkt);
	}
	return;
}


// process incoming segment in listen state
void incoming_listen(gpacket_t *gpkt)
{
	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	tcphdr_t *hdr = (tcphdr_t *) (uchar *) ip + ip->ip_hdr_len * 4;

	if (hdr->flags & RST) {
		return;
	}

	if (hdr->flags & ACK) {
		send_rst(gpkt);
		return;
	}

	// accept connection
	if (hdr->flags & SYN) {

		if (ntohs(hdr->dst) != local_port) {
			send_rst(gpkt);
			return;
		}

		recv_nxt = ntohl(hdr->seq) + 1;
		irs = ntohl(hdr->seq);

		iss = sequence_gen();
		snd_nxt = iss + 1;
		snd_una = iss;

		uchar tmp[4];
		COPYIP(remote_ip, gNtohl(tmp, ip->ip_src))
			remote_port = ntohs(hdr->dst);

		send_synack(gpkt);

		set_state(SYN_RECEIVED);
		return;
	}

}

void incoming_syn_sent(gpacket_t *gpkt)
{
	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
        tcphdr_t *hdr = (tcphdr_t *) (uchar *) ip + ip->ip_hdr_len * 4;
	int valid_ack = 0;

	// check if valid syn-ack
	if (hdr->flags & ACK) {
		if (ntohl(hdr->ack) != snd_nxt) {

			if (hdr->flags & RST) {
				free(gpkt);
			} else {
				send_rst(gpkt);
			}
			return;
		}
		valid_ack = 1;
	}

	if (hdr->flags & RST) {

	}
}

void tcp_recv(gpacket_t *gpkt)
{
	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
        tcphdr_t *hdr = (tcphdr_t *) (uchar *) ip + ip->ip_hdr_len * 4;

	// je suis le rfc, derniere section qui explique etape par etape

	if (read_state() == CLOSED) {
		incoming_closed(gpkt);
	}	

	else if (ntohs(hdr->dest) != local_port) {
		if (hdr->flags & RST) {
			free(gpkt);
		} else {
			sent_rst(gpkt);
		}
	}

	else if (read_state() == LISTEN) {
		incoming_listen(gpkt);
	}	

	else if (read_state() == SYN_SENT) {
		incoming_syn_sent(gpkt);
	}

}

int close()
{
	// must keep receiving until remote end also closes

}
