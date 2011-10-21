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


// udp header in host byte order please
uint16_t cksum(ip_packet_t *iphdr, udphdr_t *hdr, uint8_t *data)
{
	uint16_t word;
	uint8_t buf[PHEADER_SIZE + DEFAULT_MTU + 1] = {0};  // extra byte for padding


	memcpy(buf, &iphdr->ip_src, 4);
	memcpy(buf + 4, &iphdr->ip_dst, 4);
	buf[8] = 0x0;
	buf[9] = UDP_PROTOCOL;
	buf[10] = htons(ntohs(iphdr->ip_pkt_len) - iphdr->ip_hdr_len * 4); 

	int data_len = ntohs(hdr->len) - UDP_HEADER_SIZE;

	memcpy(buf + PHEADER_SIZE, hdr, sizeof(hdr));
	memcpy(buf + PHEADER_SIZE + UDP_HEADER_SIZE, data, data_len);

	if (data_len % 2 != 0) {
		data_len++;		                                                                                  
	}
	
	if (checksum((uchar *) buf, PHEADER_SIZE + UDP_HEADER_SIZE + data_len) != mychecksum(buf, PHEADER_SIZE + UDP_HEADER_SIZE + data_len)) {
		printf("puzzle.\n");
	}
	
	return (uint16_t) checksum((uchar *)buf, PHEADER_SIZE + UDP_HEADER_SIZE + data_len);
	//return mychecksum(buf, PHEADER_SIZE + UDP_HEADER_SIZE + data_len);
}

uint16_t mychecksum(uint8_t *data, int len)
{
	uint32_t sum;

	while (len > 1) {
		printf("%x ", * (uint16_t *) data);
		sum += * (uint16_t *) data++;
		len -=2;
	}

	if (len > 0) {
		sum += * (uint8_t *) data;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return (uint16_t) ~sum;
}

// RAPPEL caller les fonctions pour convertir en network byte order ou l'inverse

int send_udp(uint8_t dest_ip[4], uint16_t dest_port, uint16_t src_port, char *data, int len)
{
	// check if data is too big
	if (len > DEFAULT_MTU - sizeof(ip_packet_t) - UDP_HEADER_SIZE) {
		return -1; 
	}
	
	char tmpbuf[MAX_TMPBUF_LEN];
	// Allocate the gpacket (ip, udphdr)
	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ip_packet_t *ipkt = (ip_packet_t *)(out_pkt->data.data);
	ipkt->ip_hdr_len = 5;                                  // no IP header options!!
	
	udphdr_t *hdr = (udphdr_t *)((uchar *)ipkt + ipkt->ip_hdr_len*4);
	hdr->source = htons(src_port);
	hdr->dest = htons(dest_port);
	hdr->check = 0;
	uint16_t ttlen = len + UDP_HEADER_SIZE;
	hdr->len = htons(ttlen);

	/*XXX*/
	memcpy(hdr+UDP_HEADER_SIZE, data, len);
	char buf[DEFAULT_MTU] = {0};
	memcpy(buf, hdr+UDP_HEADER_SIZE, len);
	printf("DATA at UDP -> %s", buf);
	/*XXX*/
	
	//uint32_t tmp = getsrcaddr(out_pkt,dest_ip);

	/*
	uint16_t checksum = cksum(ipkt,hdr,(uint8_t *)data);
	if(checksum == 0){
		checksum = ~checksum;
	}
 	hdr->check = htons(checksum);
	*/

	hdr->check = 0;
	// send
	IPOutgoingPacket(out_pkt, dest_ip, ttlen, 1, UDP_PROTOCOL);

	return 0;
}

void udp_recv(gpacket_t *packet)
{
	// calcul et verifie checksum
    uint16_t udpChecksum;
    uint16_t tempChecksum;
    
    ip_packet_t *ipPacket = (ip_packet_t *) packet->data.data;
    uint16_t ipPacketLength = ntohs(ipPacket->ip_pkt_len);  
   
    // convert header to right byte order 
    udphdr_t *udpHeader = (udphdr_t *)((uint8_t *)ipPacket + ipPacket->ip_hdr_len*4);

    /*
    udpHeader->source = ntohs(udpHeader->source);
    udpHeader->dest = ntohs(udpHeader->dest);
    udpHeader->len = ntohs(udpHeader->len);
    udpHeader->check = ntohs(udpHeader->check);    
    */

    uint8_t *data;
    data = (uint8_t *) udpHeader + UDP_HEADER_SIZE;
    int dataLength = ntohs(udpHeader->len) - UDP_HEADER_SIZE;
 
/*    
    if (udpHeader->check !=0) 
    {
        udpChecksum = udpHeader->check;
	
	printf("packet sum - > %u\n", udpChecksum);

        udpHeader->check = 0;
        tempChecksum = cksum(ipPacket, udpHeader, data);

	printf("computed sum -> %u\n", tempChecksum);

        if (udpChecksum != tempChecksum) 
        {
	    verbose(1, "[udp_recv]:: jai domper un packet");
            return;
        }
    }
*/
	// verifie que le port est rouvert
    if (port_open(ntohs(udpHeader->dest), UDP_PROTOCOL) == 0) 
    {
	printf("got packet for unopened port %d\n", ntohs(udpHeader->dest));
        ICMPProcessPortUnreachable(packet);
        return;
    }
   
	// donne le data au port layer (write_data(port, proto, buf len)) 
	write_data(ntohs(udpHeader->dest),UDP_PROTOCOL,data,dataLength);
}
