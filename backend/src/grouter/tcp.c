#include "ports.h"
#include "tcp.h"
#include "ip.h"
#include "protocols.h"
#include "message.h"
#include "grouter.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

void set_state(int);

/** state variables, only one active connection so there not in a struct
 * our version of the TCB from the rfc
 * might need to put this in a struct later, since all this needs to be reset
 * for every new connection **/

struct tcb_t {

	int state;                // the actual connection state 
	pthread_mutex_t state_lock;

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
	unsigned long recv_win;   // window
	unsigned long irs;        // initial sequence number

	#define BUFSIZE 65535

	int snd_head;
	uchar snd_buf[BUFSIZE];

} tcb;

void reset_tcb_state()
{
	memset(&tcb, 0, sizeof(struct tcb_t));
	set_state(CLOSED);
	pthread_mutex_init(&tcb.state_lock, NULL);
}

void init_tcp()
{
	reset_tcb_state();
}

// converts seq from sequence space to buffer space using intial as initial sequence number
int seq_to_off(uint32_t seq, uint32_t initial)
{
	// one sequence number used up by SYN, not in buffer
	return (seq - initial - 1) % BUFSIZE;
}

// remember to update snd_una and snd_next

// write len bytes starting from data in to circular buffer, returns -1 on error
int write_snd_buf(uchar *data, int len)
{
	if ( (tcb.snd_head + len - 1) % BUFSIZE >= seq_to_off(tcb.snd_una, tcb.iss) ) {
		// not enough space	
		return -1;
	}

	int i;
	for (i = 0; i < len; i++) {
		tcb.snd_buf[(tcb.snd_head + i) % BUFSIZE] = data[i];
	}

	tcb.snd_head = (tcb.snd_head + len) % BUFSIZE;
}

/** copies up to len bytes of unacknowledged data into buf, will probably be useful
 * for example if snd_win is smaller than total amount of unacked data, returns amount
 * of bytes copied (may be smaller than len if there is not that much unacked data!)
**/
int copy_una(uchar *buf, int len)
{
	long available = tcb.snd_nxt - tcb.snd_una;

	if (available < len) {
		memcpy(buf, tcb.snd_buf + seq_to_off(tcb.snd_una, tcb.iss), available);
		return available;
	} else {
		memcpy(buf, tcb.snd_buf + seq_to_off(tcb.snd_una, tcb.iss), len);
		return len;
	}
}

/** Same as above buf copies unsent data into buf, returns count of bytes copied. **/
int copy_unsent(uchar *buf, int len)
{
	long available = tcb.snd_head - tcb.snd_nxt;

	if (available < len) {
                memcpy(buf, tcb.snd_buf + seq_to_off(tcb.snd_nxt, tcb.iss), available);
                return available;
        } else {
                memcpy(buf, tcb.snd_buf + seq_to_off(tcb.snd_nxt, tcb.iss), len);
                return len;
        } 	
}

int read_state() 
{
	int ret;
	pthread_mutex_lock(&tcb.state_lock);
	ret = tcb.state;
	pthread_mutex_unlock(&tcb.state_lock);
	return ret;
}

void set_state(int val) 
{
	pthread_mutex_lock(&tcb.state_lock);
	tcb.state = val;
	pthread_mutex_unlock(&tcb.state_lock);
}

// assumes the data is right after the tcp header
uint16_t tcp_checksum(uchar *src, uchar *dst, tcphdr_t *hdr, int data_len)
{
	uchar buf[TCP_PHEADER_SIZE + DEFAULT_MTU] = {0};

	memcpy(buf, src, 4);
	memcpy(buf + 4, dst, 4);
	buf[9] = TCP_PROTOCOL;
	((ushort *) buf)[5] = htons(hdr->data_off * 4 + data_len);

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

int tcp_send(uchar *buf, int len)
{
	if (write_snd_buf(buf, len) == -1) {
		return -1;
	}

	
}

// returns 0 on error
int tcp_listen(ushort port)
{
	if (!open_port(port, TCP_PROTOCOL)) {
		return 0;
	}	

	tcb.local_port = port;

	printf("state -> LISTEN\n");
	set_state(LISTEN);

	return 1;
}

// do we have this block until connection is established? maybe
int tcp_connect(ushort local, uchar *dest_ip, ushort dest_port)
{
	if (read_state() != CLOSED) {
		return 0;
	}

	if (!open_port(local, TCP_PROTOCOL)) {
		return 0;
	}

	tcb.local_port = local;
	memcpy(tcb.remote_ip, dest_ip, 4);
	tcb.remote_port = dest_port;

	// send a SYN packet 
	// calloc gives zeroed out mem
	gpacket_t *gpkt = calloc(1, sizeof(gpacket_t));

	if (gpkt == NULL) {
		return 0;
	}

	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	ip->ip_hdr_len = 5;

	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);

	tcb.iss = sequence_gen();
	tcb.snd_una = tcb.iss;
	tcb.snd_nxt = tcb.iss + 1;

	getsrcaddr(gpkt, dest_ip);
	uchar tmpbuf[4] = {0};
	COPY_IP(ip->ip_dst, gHtonl(tmpbuf, dest_ip));

	hdr->src = htons(tcb.local_port);
	hdr->dst = htons(tcb.remote_port);
	hdr->seq = htonl(tcb.iss);
	hdr->data_off = 5;
	hdr->flags = SYN;
	hdr->checksum = 0;

	tcb.recv_win = BUFSIZE;
	hdr->win = tcb.recv_win;

	hdr->checksum = htons(tcp_checksum(ip->ip_src, ip->ip_dst, hdr, 0));
	if (hdr->checksum == 0) {
		hdr->checksum = ~hdr->checksum;
	}				

	IPOutgoingPacket(gpkt, tcb.remote_ip, hdr->data_off * 4, 1, TCP_PROTOCOL);

	printf("state -> SYN_SENT\n");
	set_state(SYN_SENT);

	return 1;		
}

// send a RST in response to segment gpkt
void send_rst(gpacket_t *gpkt)
{
	uchar tmp[4];
	uint16_t tmp_port;

	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);

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
	hdr->urg = 0;
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
	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4); 

	hdr->flags = SYN | ACK;
	tmp_port = hdr->src;
	hdr->src = hdr->src;
	hdr->src = tmp_port;

	hdr->ack = htonl(tcb.recv_nxt);
	hdr->seq = htonl(tcb.iss);
	hdr->data_off = 5;
	hdr->win = htonl(tcb.recv_win);
	hdr->urg = 0;
	hdr->checksum = 0;

	// src and dst are flipped
	hdr->checksum = htons(tcp_checksum(ip->ip_dst, ip->ip_src, hdr, 0));

	if (hdr->checksum == 0) {
		hdr->checksum = ~hdr->checksum;
	}

	IPOutgoingPacket(gpkt, gNtohl(tmp, ip->ip_src), hdr->data_off * 4, 0, TCP_PROTOCOL);
}

// ack segment
// assumes all the state variables have been set approprately
// will probably change this to have it send some data too
void send_ack(gpacket_t *gpkt)
{
	uchar tmp[4];
        uint16_t tmp_port;

        ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
        tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);	



	hdr->flags = ACK;
        tmp_port = hdr->src;
        hdr->src = hdr->src;
        hdr->src = tmp_port;
	
	hdr->ack = htonl(tcb.recv_nxt);
        hdr->seq = htonl(tcb.snd_nxt);
        hdr->data_off = 5;
        hdr->win = htonl(tcb.recv_win);
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
void incoming_closed(gpacket_t *gpkt)
{
	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);

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
	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);

	if (hdr->flags & RST) {
		return;
	}

	if (hdr->flags & ACK) {
		send_rst(gpkt);
		return;
	}

	// accept connection
	if (hdr->flags & SYN) {

		if (ntohs(hdr->dst) != tcb.local_port) {
			send_rst(gpkt);
			return;
		}

		tcb.recv_nxt = ntohl(hdr->seq) + 1;
		tcb.irs = ntohl(hdr->seq);
		tcb.recv_win = BUFSIZE;

		tcb.iss = sequence_gen();
		tcb.snd_nxt = tcb.iss + 1;
		tcb.snd_una = tcb.iss;

		uchar tmp[4];
		COPY_IP(tcb.remote_ip, gNtohl(tmp, ip->ip_src));
		tcb.remote_port = ntohs(hdr->dst);

		send_synack(gpkt);
		
		printf("state -> SYN_RECV\n");
		set_state(SYN_RECV);
		return;
	}

}

void incoming_syn_sent(gpacket_t *gpkt)
{
	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
        tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);
	int valid_ack = 0;

	// check if valid syn-ack
	if (hdr->flags & ACK) {
		if (ntohl(hdr->ack) != tcb.snd_nxt) {

			if (hdr->flags & RST) {
				free(gpkt);
			} else {
				send_rst(gpkt);
			}
			return;
		}
		valid_ack = 1;
	}

	// reset
	if (hdr->flags & RST) {
		if (valid_ack) {
			printf("state -> CLOSED\n");
			set_state(CLOSED);
		} 
		free(gpkt);
		return;
	}

	else if (hdr->flags & SYN) {
		tcb.recv_nxt = ntohl(hdr->seq) + 1;
		tcb.recv_win--;
		tcb.irs = ntohl(hdr->seq);

		if (valid_ack) {
			tcb.snd_una = ntohl(hdr->ack);

			send_ack(gpkt);
			printf("state -> ESTABLISHED\n");	
			set_state(ESTABLISHED);
			return;

		} else {
			send_synack(gpkt);
			printf("state -> SYN_RECV\n");
			set_state(SYN_RECV);		
		}
	} 

	else {
		free(gpkt);
	}
}



//checks if a tcp packet is acceptable
int check_if_tcp_acceptable(tcphdr_t *hdr, uint16_t tcp_data_len)
{	
	int accept  = 0; 

	if ( tcp_data_len == 0 && tcb.recv_win == 0 )
	{
		if ( hdr->seq == tcb.recv_nxt ) 
		{
			accept =  1; 
		}
	}
	else if ( tcp_data_len == 0 && tcb.recv_win > 0 )
	{
		if ( (tcb.recv_nxt <= hdr->seq) && (hdr->seq < tcb.recv_nxt+tcb.recv_win )) 
		{
			if ( (tcb.recv_nxt <= hdr->seq) && (hdr->seq < tcb.recv_nxt+tcb.recv_win ) ) 
			{
				accept =  1; 
			}
		}
	}
	else if ( tcp_data_len > 0 && tcb.recv_win > 0 )
	{
		if ( ((tcb.recv_nxt <= hdr->seq) && (hdr->seq < tcb.recv_nxt + tcb.recv_win)) || ((tcb.recv_nxt <= hdr->seq + tcp_data_len-1) && (hdr->seq  < tcb.recv_nxt + tcb.recv_win)) ) 
		{
			accept = 1; 
		}
	}
	return accept; 
}

void update_window(tcphdr_t *tcpHeader)
{
	/*if ( ) 
	{
	
	}*/
}


void tcp_recv(gpacket_t *gpkt)
{
	int packet_acceptable = 0;

	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	uint16_t ipPacketLength = ntohs(ip->ip_pkt_len); 

        tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);
	uint16_t tcp_data_len = ipPacketLength - ip->ip_hdr_len * 4 - hdr->data_off * 4; 
	uint8_t tcpFlags = hdr->flags;

	// je suis le rfc, derniere section qui explique etape par etape

	if (read_state() == CLOSED) 
	{
		incoming_closed(gpkt);
	}

	else if (tcp_checksum(ip->ip_src, ip->ip_dst, hdr, tcp_data_len) != 0) {
		free(gpkt);
		printf("Bad checksum\n");
	}
	
	else if (ntohs(hdr->dst) != tcb.local_port) 
	{
		if (hdr->flags & RST) 
		{
			free(gpkt);
		} 
		else 
		{
			send_rst(gpkt);
		}
	}
	else if (read_state() == LISTEN) 
	{
		incoming_listen(gpkt);
	}	
	else if (read_state() == SYN_SENT) 
	{
		incoming_syn_sent(gpkt);
	}
	else
	{
		packet_acceptable = check_if_tcp_acceptable(hdr,tcp_data_len); //part of 1st check 
		
		if (packet_acceptable == 1)
		{
			if ( CHECK_BIT(tcpFlags, 3) != 0 ) //2nd check
			{
				if ( read_state() == SYN_RECV )
				{
					// TODO if was syn-set state then 
					// notify user "connection refused
				}
				else if ( (read_state() == ESTABLISHED) || (read_state() == FIN_WAIT1) || (read_state() == FIN_WAIT2) ||(read_state() == CLOSE_WAIT) )
				{
					// TODO notify user : connection reset
					send_rst(gpkt);
				}
				// TODO delete tcb 
				printf("state -> CLOSED\n");
				set_state(CLOSED);
				return;
			}
			else if ( CHECK_BIT(tcpFlags, 2) != 0) // 4th check TODO 3rd check missing : what is security and precedence?
			{
				send_rst(gpkt);
				// TODO send user connection reset
				printf("state -> CLOSED\n");
				set_state(CLOSED);
				// TODO delete tcb
			}
			else if (CHECK_BIT(tcpFlags, 5) != 0 ) // part of 5th check
			{
				if ( read_state() == SYN_RECV )
				{
					printf("state -> ESTABLISHED\n");
					set_state(ESTABLISHED);
				}
				else if ( read_state() == ESTABLISHED ) 
				{
					tcb.snd_una = hdr->ack;
					//TODO remove segments in the retransmission queue that have been ack
					//TODO sent positive ack to user for buffers that have been sent and acked (send buffer should be retured with OK" response)
					//TODO update window
					//update_window(hdr);
				}	
			} 
		}
		else 
		{
			if ( CHECK_BIT(tcpFlags, 3) == 0 ) //part of 1st check
			{
				//TODO send <SEQ=SND.NXT><ACK=RVC.NXT><CTL=ACK>
			}
			else if (CHECK_BIT(tcpFlags, 5) != 0 ) // part of 5h check 
			{
				if ( read_state() == SYN_RECV )
				{
					//TODO dontforget to ask alex is send reset => <SEQ=SEQ.ACK><CST=RST>
					send_rst(gpkt);
				}
				else if ( read_state() == ESTABLISHED ) 
				{
					if (hdr->ack > tcb.snd_nxt )
					{	
						//TODO send an ack drop the segment.....why?????
					} 
				}
			} 
			return;
		}
	}
}






int tcp_close()
{
	// must keep receiving until remote end also closes
	return 0;
}
