#include "udp.h"
#include "ports.h"
#include "grouter.h"
#include "ip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

uint16_t mychecksum(uint8_t *, int);

// changes ip array to int so we can call ntohl on it
uint32_t ip_atol(uchar ip[4])
{
	uint32_t ret = 0;
	int i;
	for (i = 0; i < 4; i++) {
		ret |= (ip[i] & 0xff) << 8 * i; 
	}
	return ret;
}


// everything in network byte order
uint16_t udp_cksum(ip_packet_t *iphdr, udphdr_t *hdr, uint8_t *data)
{
	uint8_t buf[PHEADER_SIZE + DEFAULT_MTU + 1] = {0};  // extra byte for padding

	// pseudo hdr
	memcpy(buf, iphdr->ip_src, 4);
	memcpy(buf + 4, iphdr->ip_dst, 4);
	buf[8] = 0x0;
	buf[9] = UDP_PROTOCOL;
	buf[10] = htons(ntohs(iphdr->ip_pkt_len) - iphdr->ip_hdr_len * 4); 
	
	int data_len = ntohs(hdr->len) - UDP_HEADER_SIZE;

	memcpy(buf + PHEADER_SIZE, hdr, UDP_HEADER_SIZE);
	memcpy(buf + PHEADER_SIZE + UDP_HEADER_SIZE, data, data_len);

	if (data_len % 2 != 0) {
		data_len++;		                                                                                  
	}
	
	//return checksum((uchar *)buf, (PHEADER_SIZE + UDP_HEADER_SIZE + data_len) / 2);
	return mychecksum(buf, PHEADER_SIZE + UDP_HEADER_SIZE + data_len);
}

uint16_t mychecksum(uint8_t *buf, int len)
{
	uint32_t sum = 0;

	while (len > 1) {
		sum += * (uint16_t *) buf++;
		len -= 2;
	}

	if (len > 0) {
		sum += * (uint8_t *) buf;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return (uint16_t) ~sum;
}

// RAPPEL caller les fonctions pour convertir en network byte order ou l'inverse

int send_udp(uint8_t dest_ip[4], uint16_t dest_port, uint16_t src_port, char *data, uint16_t len)
{
	// check if data is too big
	if (len > DEFAULT_MTU - sizeof(ip_packet_t) - UDP_HEADER_SIZE) {
		return -1; 
	}
	
	// Allocate the gpacket (ip, udphdr)
	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));

	if (out_pkt == NULL) {
		return -1;
	}

	ip_packet_t *ipkt = (ip_packet_t *) out_pkt->data.data;
	ipkt->ip_hdr_len = 5;
	ipkt->ip_pkt_len = htons(ipkt->ip_hdr_len * 4 + UDP_HEADER_SIZE + len);
	
	// fill in header and copy data
	udphdr_t *hdr = (udphdr_t *) ((uchar *) ipkt + ipkt->ip_hdr_len*4);
	hdr->source = htons(src_port);
	hdr->dest = htons(dest_port);
	hdr->check = 0;
	hdr->len = htons(len + UDP_HEADER_SIZE);

	memcpy((uchar *) hdr+UDP_HEADER_SIZE, data, len);
	
	// copies src and dest addresses into IP header in newtork byte order
	getsrcaddr(out_pkt,dest_ip);
	
	uchar tmp[4] = {0};
	COPY_IP(ipkt->ip_dst, gHtonl(tmp, dest_ip));

	/*
	// calculate checkum with everything in network byte order	
	hdr->check = htons(udp_cksum(ipkt, hdr, (uint8_t *) data));

	if(hdr->check == 0){
		hdr->check = ~hdr->check;
	}
	*/

	// send
	IPOutgoingPacket(out_pkt, dest_ip, ntohs(hdr->len), 1, UDP_PROTOCOL);

	return 0;
}

void udp_recv(gpacket_t *packet)
{
	// calcul et verfie checksum
    uint16_t udpChecksum;
    uint16_t tempChecksum;
    
    ip_packet_t *ipPacket = (ip_packet_t *) packet->data.data;
    uint16_t ipPacketLength = ntohs(ipPacket->ip_pkt_len);  
   
    // convert header to right byte order 
    udphdr_t *udpHeader = (udphdr_t *)((uint8_t *)ipPacket + ipPacket->ip_hdr_len*4);

    uint8_t *data = (uint8_t *) udpHeader + UDP_HEADER_SIZE;
    int dataLength = ntohs(udpHeader->len) - UDP_HEADER_SIZE;
 
    /*    
    if (udpHeader->check !=0) 
    {
	// dump packet
       if (udp_cksum(ipPacket, udpHeader, data) != 0) {
		return;
	} 
    }
    */

    // verifie que le port est rouvert
    if (port_open(ntohs(udpHeader->dest), UDP_PROTOCOL) == 0) 
    {
        ICMPProcessPortUnreachable(packet);
        return;
    }
   
     // donne le data au port layer (write_data(port, proto, buf len)) 
     write_data(ntohs(udpHeader->dest),UDP_PROTOCOL,data,dataLength);
}
