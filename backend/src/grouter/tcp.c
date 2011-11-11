	
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
#include <signal.h>
#include <unistd.h>

void set_state(int);
void timer_handler();
void timer_handler_send_resend();

/** state variables, only one active connection so there not in a struct
 * our version of the TCB from the rfc
 * might need to put this in a struct later, since all this needs to be reset
 * for every new connection **/

struct tcb_t {

	int state;                // the actual connection state

#define PASSIVE 0
#define ACTIVE 1

	int type;                 // passive or active
	pthread_mutex_t state_lock;

	// ports, addresses
	uchar local_ip[4];
	uint16_t local_port;
	uchar remote_ip[4];
	uint16_t remote_port;
	

	// for send
	unsigned long snd_nxt;    // next
	unsigned long snd_una;    // unacknowledged
	ushort snd_win;    // window (offset in sequence numbers)
	unsigned long snd_wl1;	  // last seq # used to update window
	unsigned long snd_wl2;    // last ack used to update window
	unsigned long iss;        // inital sequence number	

	// for receive
	unsigned long recv_nxt;   // next
	ushort recv_win;   // window
	unsigned long irs;        // initial sequence number

	// for timeout
	int retran;		// the number of the retransmission
	timer_t timer;		//self explanatory
 	struct itimerspec itime;	// gives the interval and the time to wait
	struct sigevent event;		// to create a new thread
	unsigned long timer_una;	// una that the timer is waiting for
	struct timespec rtt;	//round trip time
	struct timespec stt;	//smooth round trip time
	struct timespec sndtm;	// time at which the packet is send	
	struct timespec rcvtm;	//time at which the ack was received

	//Timer for fin_wait and else
	timer_t timer_wait;
	struct itimerspec itime_wait;	// gives the interval and the time to wait
	struct sigevent event_wait;	

	int snd_head;
	uchar snd_buf[BUFSIZE];

} tcb;

void reset_tcb_state()
{
	memset(&tcb, 0, sizeof(struct tcb_t));
	set_state(CLOSED);
	close_port(tcb.local_port, TCP_PROTOCOL);
	pthread_mutex_init(&tcb.state_lock, NULL);
	tcb.recv_win = DEFAULT_WINSIZE;

	tcb.retran = 0;
	tcb.rtt.tv_sec = 0;
        tcb.rtt.tv_nsec = 0;
	tcb.stt.tv_sec = 0;
        tcb.stt.tv_nsec = 0;

	// timer pour send resend
	tcb.event.sigev_notify = SIGEV_THREAD;
   	tcb.event.sigev_notify_function = timer_handler_send_resend;
    	tcb.event.sigev_notify_attributes = NULL;
		
	int status = timer_create(CLOCK_REALTIME, &tcb.event, &tcb.timer);
        if (status < 0) {
               return;
        }

	// timer pour wait and close
	tcb.event_wait.sigev_notify = SIGEV_THREAD;
   	tcb.event_wait.sigev_notify_function = timer_handler;
    	tcb.event_wait.sigev_notify_attributes = NULL;
		
	status = timer_create(CLOCK_REALTIME, &tcb.event_wait, &tcb.timer_wait);
        if (status < 0) {
               return;
        }
}

void init_tcp()
{
	reset_tcb_state();

}

void calc_stt(){
	if ((	tcb.rcvtm.tv_nsec - tcb.sndtm.tv_nsec) < 0) {
		tcb.rtt.tv_sec = tcb.rcvtm.tv_sec - tcb.sndtm.tv_sec-1;
		tcb.rtt.tv_nsec = NSECS_PER_SEC + tcb.rcvtm.tv_nsec - tcb.sndtm.tv_nsec;
	} else {
		tcb.rtt.tv_sec = tcb.rcvtm.tv_sec - tcb.sndtm.tv_sec;
		tcb.rtt.tv_nsec = tcb.rcvtm.tv_nsec - tcb.sndtm.tv_nsec;
	}

	tcb.stt.tv_sec = ALPHA*tcb.stt.tv_sec + (1-ALPHA)*tcb.rtt.tv_sec;
        tcb.stt.tv_nsec = ALPHA*tcb.stt.tv_nsec + (1-ALPHA)*tcb.rtt.tv_nsec;
        if (tcb.stt.tv_nsec < 0) {
                tcb.stt.tv_sec--;
                tcb.stt.tv_nsec += NSECS_PER_SEC;
        }
        if (tcb.stt.tv_nsec >= NSECS_PER_SEC) {
                tcb.stt.tv_sec++;
                tcb.stt.tv_nsec -= NSECS_PER_SEC;
        }	
}

// converts seq from sequence space to buffer space using intial as initial sequence number
int seq_to_off(uint32_t seq, uint32_t initial)
{
	// one sequence number used up by SYN, not in buffer, we account for this elsewhere
	return (seq - initial) % BUFSIZE;
}

// gets the length of the unacknowledgement space
long get_una_size(){
	long last_sent = seq_to_off(tcb.snd_nxt, tcb.iss);
	long una = seq_to_off(tcb.snd_una, tcb.iss);
	long length= (last_sent - una);
	if(una > last_sent){
		length = ((last_sent + BUFSIZE - una)% BUFSIZE);
	} 
	return length;
}

// gets the length of the unsent space
long get_unsent_size(){
	long last_sent = seq_to_off(tcb.snd_nxt, tcb.iss);
	long available = tcb.snd_head - last_sent;
	if(last_sent > tcb.snd_head){
		available = ((tcb.snd_head + BUFSIZE - last_sent)% BUFSIZE);
	} 
	return available;
}

// remember to update snd_una and snd_next

// write len bytes starting from data in to circular buffer, returns -1 on error
int write_snd_buf(uchar *data, int len)
{
	int una = seq_to_off(tcb.snd_una, tcb.iss);
	int remaining= 0;
	if(una > tcb.snd_head){
		remaining = BUFSIZE - ((tcb.snd_head + BUFSIZE - una)% BUFSIZE);
	} else {
		remaining = BUFSIZE - (tcb.snd_head - una);
	}
	
	if ( (tcb.snd_head + len - 1) % BUFSIZE >= remaining ) {
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
	long available = get_una_size();
	if(available > (DEFAULT_MTU - sizeof(ip_packet_t) - TCP_HEADER_SIZE)){
		available = DEFAULT_MTU - sizeof(ip_packet_t) - TCP_HEADER_SIZE;
	}

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
	long last_sent = seq_to_off(tcb.snd_nxt, tcb.iss);
	long available = get_unsent_size();
	if(available > (DEFAULT_MTU - sizeof(ip_packet_t) - TCP_HEADER_SIZE)){
		available = DEFAULT_MTU - sizeof(ip_packet_t) - TCP_HEADER_SIZE;
	}

	if (available < len) {
		memcpy(buf, tcb.snd_buf + last_sent, available);
		return available;
	} else {
		memcpy(buf, tcb.snd_buf + last_sent, len); 
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


void print_state(int state) 
{
	if ( state == ESTABLISHED ) 
	{
		printf("state->ESTABLISHED\n");
	}
	else if ( state == SYN_SENT ) 
	{
		printf("state->SYN_SENT\n");
	}
	else if ( state == SYN_RECV ) 
	{
		printf("state->SYN_RECV\n");
	}
	else if ( state == FIN_WAIT1) 
	{
		printf("state->FIN_WAIT1\n");
	}
	else if ( state == FIN_WAIT2 ) 
	{
		printf("state->FIN_WAIT2\n");
	}
 	else if ( state == TIME_WAIT ) 
	{
		printf("state->TIME_WAIT\n");
	}
 	else if ( state == CLOSED ) 
	{
		printf("state->CLOSED\n");
	}
 	else if ( state == CLOSE_WAIT) 
	{
		printf("state->CLOSE_WAIT\n");
	}
	else if ( state == LAST_ACK ) 
	{
		printf("state->LAST_ACK\n");
	}
 	else if ( state == LISTEN ) 
	{
		printf("state->LISTEN\n");
	}
 	else if ( state == CLOSING ) 
	{
		printf("state->CLOSING\n");
	}
}

void set_state(int val) 
{
	pthread_mutex_lock(&tcb.state_lock);
	tcb.state = val;
	print_state(tcb.state);
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

// returns 0 on error
int tcp_listen(ushort port)
{
	if (!open_port(port, TCP_PROTOCOL)) {
		return 0;
	}	

	tcb.local_port = port;
	tcb.type = PASSIVE;
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
	tcb.type = ACTIVE;

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
	tcb.snd_head = seq_to_off(tcb.snd_nxt, tcb.iss);

	uchar tmpbuf[4];
	getsrcaddr(gpkt, dest_ip);
	memcpy(tcb.local_ip, gNtohl(tmpbuf, ip->ip_src), 4);
	COPY_IP(ip->ip_dst, gHtonl(tmpbuf, dest_ip));

	hdr->src = htons(tcb.local_port);
	hdr->dst = htons(tcb.remote_port);
	hdr->seq = htonl(tcb.iss);
	hdr->data_off = 5;
	hdr->flags = SYN;
	hdr->checksum = 0;
	hdr->win = htons(tcb.recv_win);

	hdr->checksum = htons(tcp_checksum(ip->ip_src, ip->ip_dst, hdr, 0));
	if (hdr->checksum == 0) {
		hdr->checksum = ~hdr->checksum;
	}				

	clock_gettime(CLOCK_REALTIME, &tcb.sndtm);

	IPOutgoingPacket(gpkt, tcb.remote_ip, hdr->data_off * 4, 1, TCP_PROTOCOL);

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

	IPOutgoingPacket(gpkt, gNtohl(tmp, ip->ip_src), hdr->data_off * 4, 1, TCP_PROTOCOL);
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
	hdr->src = hdr->dst;
	hdr->dst = tmp_port;
	hdr->ack = htonl(tcb.recv_nxt);
	hdr->seq = htonl(tcb.iss);
	hdr->data_off = 5;
	hdr->win = htons(tcb.recv_win);	
	hdr->urg = 0;
	hdr->checksum = 0;
	hdr->reserved = 0;	

	// src and dst are flipped
	hdr->checksum = htons(tcp_checksum(ip->ip_dst, ip->ip_src, hdr, 0));

	if (hdr->checksum == 0) {
		hdr->checksum = ~hdr->checksum;
	}

	IPOutgoingPacket(gpkt, gNtohl(tmp, ip->ip_src), hdr->data_off * 4, 1, TCP_PROTOCOL);
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
	hdr->src = hdr->dst;
	hdr->dst = tmp_port;
	hdr->ack = htonl(tcb.recv_nxt);
	hdr->seq = htonl(tcb.snd_nxt);	
	hdr->data_off = 5;
	hdr->win = htons(tcb.recv_win);
	hdr->urg = 0;
	hdr->checksum = 0;
	hdr->reserved = 0;

	// src and dst are flipped
	hdr->checksum = htons(tcp_checksum(ip->ip_dst, ip->ip_src, hdr, 0));

	if (hdr->checksum == 0) {
		hdr->checksum = ~hdr->checksum;
	}   

	IPOutgoingPacket(gpkt, gNtohl(tmp, ip->ip_src), hdr->data_off * 4, 1, TCP_PROTOCOL);
}


void send_fin(gpacket_t *gpkt) 
{
	uchar tmp[4];
	uint16_t tmp_port;

	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);	

	hdr->flags = FIN;
	tmp_port = hdr->src;
	hdr->src = hdr->dst;
	hdr->dst = tmp_port;
	hdr->ack = 0;
	hdr->ack = htonl(tcb.recv_nxt);
	hdr->seq = htonl(tcb.snd_nxt);	
	hdr->data_off = 5;
	hdr->win = htons(tcb.recv_win);
	hdr->urg = 0;
	hdr->checksum = 0;
	hdr->reserved = 0;

	// src and dst are flipped
	hdr->checksum = htons(tcp_checksum(ip->ip_dst, ip->ip_src, hdr, 0));

	if (hdr->checksum == 0) {
		hdr->checksum = ~hdr->checksum;
	}   

	IPOutgoingPacket(gpkt, gNtohl(tmp, ip->ip_src), hdr->data_off * 4, 1, TCP_PROTOCOL);
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
		free(gpkt);
		return;
	}

	if (hdr->flags & ACK) {
		send_rst(gpkt);
		return;
	}

	// accept connection
	if (hdr->flags & SYN) {

		tcb.recv_nxt = ntohl(hdr->seq) + 1;
		tcb.irs = ntohl(hdr->seq);		

		tcb.iss = sequence_gen();
		tcb.snd_nxt = tcb.iss + 1;
		tcb.snd_una = tcb.iss;
		tcb.snd_win = ntohs(hdr->win);
		tcb.snd_head = seq_to_off(tcb.snd_nxt, tcb.iss);

		uchar tmp[4];
		COPY_IP(tcb.remote_ip, gNtohl(tmp, ip->ip_src)); // get remote ip

		getsrcaddr(gpkt, gNtohl(tmp, ip->ip_src));
		COPY_IP(tcb.local_ip, gNtohl(tmp, ip->ip_src));

		// jumping through hoops because the sen_synack function expexts src and dst to be flipped
		COPY_IP(ip->ip_src, gHtonl(tmp, tcb.remote_ip));
		COPY_IP(ip->ip_dst, gHtonl(tmp, tcb.local_ip));
		
		tcb.remote_port = ntohs(hdr->src);

		send_synack(gpkt);

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
		clock_gettime(CLOCK_REALTIME, &tcb.rcvtm);
		calc_stt();
		valid_ack = 1;
	}

	// reset
	if (hdr->flags & RST) {
		if (valid_ack) {
			set_state(CLOSED);
		} 
		free(gpkt);
		return;
	}

	else if (hdr->flags & SYN) {
		tcb.recv_nxt = ntohl(hdr->seq) + 1;
		tcb.irs = ntohl(hdr->seq);
		tcb.snd_win = ntohs(hdr->win);

		if (valid_ack) {
			tcb.snd_una = ntohl(hdr->ack);

			send_ack(gpkt);
			set_state(ESTABLISHED);
			return;

		} else {
			send_synack(gpkt);
			set_state(SYN_RECV);		
		}
	} 

	else {
		free(gpkt);
	}
}

//return 1 if succeed , 0 if failed
int tcp_send(uchar *buf, int len)
{
	//printf("send\n");
	if(read_state() == CLOSED){
		printf("error: connection must be opened\n");
		return 0;
	}

	else if(read_state() == LISTEN){
		printf("error: connection must be established\n");
		return 0;
	}

	else if(read_state() == SYN_SENT  || read_state() == SYN_RECV){
		if(len != 0) {
			if (write_snd_buf(buf, len) == -1) {			
				printf("error: insufficient resources\n");
				return 0;
			}	
		}	
	}

	else if(read_state() == ESTABLISHED || read_state() == CLOSE_WAIT){
		// check if data is too big
		if(len != 0){
			if (write_snd_buf(buf, len) == -1) {			
				printf("error: insufficient resources\n");
				return 0;
			}
		}
		// don't send anything if the previous ack isn't received
		if(tcb.snd_una != tcb.snd_nxt){
			return 0;
		}

		gpacket_t *gpkt = (gpacket_t *) calloc(1, sizeof(gpacket_t));

		if (gpkt == NULL) {			
			return 0;
		}

		ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
		ip->ip_hdr_len = 5;

		tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);

		uchar tmpbuf[4] = {0};
		COPY_IP(ip->ip_dst, gHtonl(tmpbuf, tcb.remote_ip));
		COPY_IP(ip->ip_src, gHtonl(tmpbuf, tcb.local_ip));

		hdr->ack = htonl(tcb.recv_nxt);
		hdr->seq = htonl(tcb.snd_nxt);
		hdr->src = htons(tcb.local_port);
		hdr->dst = htons(tcb.remote_port);
		hdr->data_off = 5;
		hdr->flags = ACK;
		hdr->checksum = 0;
		hdr->reserved = 0;
		hdr->urg = 0;
		hdr->win = htons(tcb.recv_win);
		
		//data
		int size = get_unsent_size();
		if(tcb.snd_win < size) {
			size = tcb.snd_win;
		}
		size = copy_unsent((uchar *) hdr + hdr->data_off * 4, size);
		if(size == 0){ //don't send an empty packet
			return 1;
		}

		hdr->checksum = htons(tcp_checksum(ip->ip_src, ip->ip_dst, hdr, size));
		if (hdr->checksum == 0) {
			hdr->checksum = ~hdr->checksum;
		}
		
		clock_gettime(CLOCK_REALTIME, &tcb.sndtm);

		IPOutgoingPacket(gpkt, gNtohl(tmpbuf, ip->ip_dst), hdr->data_off * 4 + size, 1, TCP_PROTOCOL);	

		tcb.snd_nxt += size;
		
		tcb.timer_una = tcb.snd_una;
		start_timer_STT();
	}

	else {
		printf("error: connection closing\n");
		return 0;
	}

	
	return 1;
}

// it is a simple resend
int tcp_resend(){
	gpacket_t *gpkt = (gpacket_t *) calloc(1, sizeof(gpacket_t));

	if (gpkt == NULL) {			
		return 0;
	}

	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	ip->ip_hdr_len = 5;

	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);

	uchar tmpbuf[4] = {0};
	COPY_IP(ip->ip_dst, gHtonl(tmpbuf, tcb.remote_ip));
	COPY_IP(ip->ip_src, gHtonl(tmpbuf, tcb.local_ip));

	hdr->ack = htonl(tcb.recv_nxt);
	hdr->seq = htonl(tcb.snd_una);
	hdr->src = htons(tcb.local_port);
	hdr->dst = htons(tcb.remote_port);
	hdr->data_off = 5;
	hdr->flags = ACK;
	hdr->checksum = 0;
	hdr->reserved = 0;
	hdr->urg = 0;
	hdr->win = htons(tcb.recv_win);
	
	//data
	int size = get_una_size();
	if(tcb.snd_win < size) {
		size = tcb.snd_win;
	}
	size = copy_una((uchar *) hdr + hdr->data_off * 4, size);
	if(size == 0){ //don't send an empty packet
		printf("No data to resend\n");
		return 1;
	}

	hdr->checksum = htons(tcp_checksum(ip->ip_src, ip->ip_dst, hdr, size));
	if (hdr->checksum == 0) {
		hdr->checksum = ~hdr->checksum;
	}
	clock_gettime(CLOCK_REALTIME, &tcb.sndtm);

	IPOutgoingPacket(gpkt, gNtohl(tmpbuf, ip->ip_dst), hdr->data_off * 4 + size, 1, TCP_PROTOCOL);	
	tcb.retran++;
	start_timer_STT();
}

// only accept idealized segments starting at recv.next and smaller/equal to window size
// according to rfc wording this is ok
int check_if_tcp_acceptable(tcphdr_t *hdr, uint16_t tcp_data_len)
{	
	unsigned long seq = ntohl(hdr->seq);

	int accept  = 0; 

	if ( tcp_data_len == 0 && tcb.recv_win == 0 )
	{
		if ( seq == tcb.recv_nxt ) 
		{
			accept =  1; 
		}
	}
	else if ( tcp_data_len == 0 && tcb.recv_win > 0 )
	{
		if (tcb.recv_nxt == seq)
		{
			accept =  1; 
		}
	}
	else if ( tcp_data_len > 0 && tcb.recv_win > 0 )
	{
		if ( (tcb.recv_nxt == seq) && (seq + tcp_data_len - 1  < tcb.recv_nxt + tcb.recv_win) ) 
		{
			accept = 1; 
		}
	}
	return accept; 
}

void incoming_reset()
{
	if ( read_state() == SYN_RECV && tcb.type == PASSIVE) {   // return to listen
		ushort port = tcb.local_port;
		reset_tcb_state();
		tcb.local_port = port;
		set_state(LISTEN);
	} else {
		reset_tcb_state();
		set_state(CLOSED);
	}
}


void incoming_misplaced_syn(gpacket_t *gpkt)
{
	send_rst(gpkt);
	verbose(2, "[tcp_recv]:: Connection Reset\n");
	reset_tcb_state();
	set_state(CLOSED);
}

void timer_handler_send_resend(){
	if(read_state() == ESTABLISHED || read_state() == CLOSE_WAIT 
		|| read_state() == FIN_WAIT1 || read_state() == FIN_WAIT2 || read_state() == TIME_WAIT  ){
		//check if the timer is still alive
		if(tcb.snd_una > tcb.timer_una){
			tcb.timer_una = tcb.snd_una;
			tcb.retran = 0;
		} else {
			if(tcb.retran == MAXDATARETRANSMISSIONS){
				tcb.retran = 0;
				verbose(1, "[tcp_retransmission]:: Connection INACCESSIBLE");
				set_state(CLOSED); 
				reset_tcb_state();
			return;
			} else {
				tcp_resend();
			}
		}
	}
}

void timer_handler(){
	if ( read_state() == TIME_WAIT ) {	
		set_state(CLOSED); 
		reset_tcb_state();
	} 
}

// time in seconds, use STT for sed and resend
int start_timer_STT()
{	
	tcb.itime.it_value.tv_sec = BETA*tcb.stt.tv_sec;
   	tcb.itime.it_value.tv_nsec = BETA*tcb.stt.tv_nsec; 
   	tcb.itime.it_interval.tv_sec = 0;
   	tcb.itime.it_interval.tv_nsec = 0; 

   	timer_settime(tcb.timer, 0, &tcb.itime, NULL);

	return 0;
}

// time in seconds
//time == 0 it stops timer
int start_timewait_timer(int time)
{	
	tcb.itime_wait.it_value.tv_sec = time;
   	tcb.itime_wait.it_value.tv_nsec = 0; 
   	tcb.itime_wait.it_interval.tv_sec = 0;
   	tcb.itime_wait.it_interval.tv_nsec = 0; 

   	timer_settime(tcb.timer_wait, 0, &tcb.itime_wait, NULL);

	return 0;
}

void check4TimeWaitTimeOut()
{
	int timeout = 1;
	if (timeout)
	{
		set_state(CLOSED); 
		reset_tcb_state();
		verbose(2, "[tcp_recv]:: WAIT TIMEOUT\n");
	}
}


int process_ack(gpacket_t *gpkt)
{
	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);
	unsigned long ack = ntohl(hdr->ack);
        unsigned long seq = ntohl(hdr->seq);
        ushort win = ntohs(hdr->win);

	if (tcb.snd_una < ack && ack <= tcb.snd_nxt) {
		tcb.snd_una = ack;            // update acked data
		// update window
		if ((tcb.snd_wl1 < seq) || (tcb.snd_wl1 == seq && tcb.snd_wl2 <= ack)) {
			tcb.snd_win = win;
			tcb.snd_wl1 = seq;
			tcb.snd_wl2 = ack;
		}  
		//send remaining packets
		if((read_state() == ESTABLISHED || read_state() == CLOSE_WAIT) && get_unsent_size > 0){
			tcp_send(NULL,0);
		}  

		return 1; 

	} else if (ack > tcb.snd_nxt) {
		send_ack(gpkt);
		return 0;
	} else {
		return 1;    // ignore ack but still process data
	}
}

int incoming_ack(gpacket_t *gpkt)
{
	int proceed = 1;
	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	uint16_t ipPacketLength = ntohs(ip->ip_pkt_len); 

	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);

	if (read_state() == FIN_WAIT1) {
		printf("current -> FIN_WAIT1");
	}

	if ( read_state() == SYN_RECV )
	{
		if (tcb.snd_una <= ntohl(hdr->ack) && ntohl(hdr->ack) <= tcb.snd_nxt)  {
			
			set_state(ESTABLISHED);
		} else {
			send_rst(gpkt);
			return 0;
		}
	}

	if ( (read_state() == ESTABLISHED) || (read_state() == CLOSE_WAIT || (read_state() == FIN_WAIT2)) ) 
	{
		
			proceed = process_ack(gpkt);
	
	}

	else if ( read_state() ==  FIN_WAIT1 )
	{
		proceed = process_ack(gpkt);                   
		if (proceed) {
			set_state(FIN_WAIT2);
		} 
	}
	else if ( read_state() == CLOSING)
	{
		proceed = process_ack(gpkt);

		if (proceed) {
			set_state(TIME_WAIT);
		} 
	}
	else if ( read_state() == LAST_ACK ) 
	{
		proceed = process_ack(gpkt);

		if (proceed) {
			reset_tcb_state();
			set_state(CLOSED);
			proceed = 0;
		}
	}
	else if ( read_state() == TIME_WAIT ) 
	{
		send_ack(gpkt);
		start_timewait_timer(2*MSL);
	}

	return proceed;					
}


void incoming_fin() 
{
	if ( (read_state() == SYN_RECV) || (read_state() == ESTABLISHED) )
	{
		set_state(CLOSE_WAIT);
	}
	else if ( read_state() == FIN_WAIT1 ) 
	{
		// ENTER CLOSING STATE IF NOT ACKED...WONT HAPPEN
		start_timewait_timer(MSL);
		set_state(TIME_WAIT);
	}
	else if ( read_state() == FIN_WAIT2 ) 
	{
		start_timewait_timer(MSL);
		set_state(TIME_WAIT);
	}
	else if ( read_state() == TIME_WAIT ) 
	{	
		start_timewait_timer(2*MSL);
	}
}


void tcp_recv(gpacket_t *gpkt)
{
	int packet_acceptable = 0;

	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	uint16_t ipPacketLength = ntohs(ip->ip_pkt_len); 

	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);
	uint16_t tcp_data_len = ipPacketLength - ip->ip_hdr_len * 4 - hdr->data_off * 4; 

	uint8_t *data = (uint8_t *) hdr + hdr->data_off * 4;
	
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
			printf("tcp_recv() : wrong port, reset.\n");
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
			if ( hdr->flags & RST ) //2nd check (rst_bit) 
			{
				incoming_reset();
				free(gpkt);
			}

			else if (hdr->flags & SYN) // 4th check (SYN bit) 
			{
				incoming_misplaced_syn(gpkt);
				return;
			}
			
			if( hdr->ack !=0)
			{
				if (hdr->flags & ACK == 0) 
				{ // part of 5th check (ACK bit) 
					free(gpkt);
					return;		
				}
				if( incoming_ack(gpkt) == 0)
				{ 
					return;
				}
			}

			if ( (read_state() == ESTABLISHED) || (read_state() == FIN_WAIT1) || (read_state() == FIN_WAIT2) )
			{

				// if our pipe is full, put window to zero
				// good thing other TCPs obey the robustness principle! 
				if (tcp_data_len > 0) {
					if (write_data(tcb.local_port, TCP_PROTOCOL, data, tcp_data_len) < tcp_data_len) {
						tcb.recv_win = 0;
					} else {
						tcb.recv_win = DEFAULT_WINSIZE;
						tcb.recv_nxt += tcp_data_len;
						send_ack(gpkt);
					}

				}
				//Calculate the round trip time
				clock_gettime(CLOCK_REALTIME, &tcb.rcvtm);
				calc_stt();	
			}

			if ( hdr->flags & FIN )
			{
				incoming_fin();
			}

			else if ( read_state() == CLOSE_WAIT )
                        {
                                send_fin(gpkt);
                                set_state(LAST_ACK);
                                printf("[tcp_recv]:: CLOSE WAIT PLEASE CLOSE CONNECTION\n");
                                verbose(2, "[tcp_recv]:: CLOSE WAIT PLEASE CLOSE CONNECTION\n");
                                return;
                        }


		} else {
			if (hdr->flags & RST) //part of 1st check (rst bit) 
			{
				free(gpkt);
                                return;
			}
			else {
				send_ack(gpkt);
			}
		}
	}
}


int tcp_close()
{
	gpacket_t *gpkt = (gpacket_t *) calloc(1, sizeof(gpacket_t));

	if (gpkt == NULL)
 	{			
		printf("error: gpkt not allocated\n");
		return 0;
	}

	ip_packet_t *ip = (ip_packet_t *) gpkt->data.data;
	ip->ip_hdr_len = 5;

	tcphdr_t *hdr = (tcphdr_t *) ((uchar *) ip + ip->ip_hdr_len * 4);

	uchar tmpbuf[4] = {0};
	COPY_IP(ip->ip_dst, gHtonl(tmpbuf, tcb.remote_ip));
	COPY_IP(ip->ip_src, gHtonl(tmpbuf, tcb.local_ip));

	hdr->ack = htonl(tcb.recv_nxt);
	hdr->seq = htonl(tcb.snd_nxt);
	hdr->src = htons(tcb.local_port);
	hdr->dst = htons(tcb.remote_port);
	hdr->data_off = 5;
	hdr->flags = FIN;
	hdr->checksum = 0;
	hdr->reserved = 0;
	hdr->urg = 0;
	hdr->win = htons(tcb.recv_win);

	hdr->checksum = htons(tcp_checksum(ip->ip_src, ip->ip_dst, hdr, 0));

	if (hdr->checksum == 0) 
	{
		hdr->checksum = ~hdr->checksum;
	}

	IPOutgoingPacket(gpkt, gNtohl(tmpbuf, ip->ip_dst), hdr->data_off * 4 + 0, 1, TCP_PROTOCOL);	

	set_state(FIN_WAIT1);
	
	return 0;
}
