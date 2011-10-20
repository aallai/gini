#include "udp.h"
#include "ports.h"
#include "grouter.h"
#include "ip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// everything in machine byte order please
uint16_t cksum(uint32_t src, uint32_t dest, udphdr_t *hdr, uint8_t *data, int data_len){

	uint16_t word16;
	uint8_t buf[PHEADER_SIZE + DEFAULT_MTU + 1];  // extra byte for padding

	buf[0] = src;
	buf[4] = dest;
	buf[8] = 0;
	buf[9] = UDP_PROTOCOL;
	buf[10] = hdr->len;             // this should be ip_packet_hdr->len - sizeof(ip_packet_hdr)
	
	int i;
	for (i = 0; i < UDP_HEADER_SIZE; i++) {
		buf[PHEADER_SIZE + i] = *(((uint8_t *) hdr) + i);
	}

	for (i = 0; i < data_len; i++) {
		buf[PHEADER_SIZE + UDP_HEADER_SIZE + i] = *(data + i);
	}	

	if (data_len % 2 != 0) {
		buf[PHEADER_SIZE + UDP_HEADER_SIZE + data_len] = 0;
		data_len++;		                                                                                  
	}
		
	return (uint16_t) checksum((uchar *)buf, PHEADER_SIZE + UDP_HEADER_SIZE + data_len);
}

// RAPPEL caller les fonctions pour convertir en network byte order ou l'inverse

int send_udp(uint32_t dest_ip, uint16_t dest_port, uint16_t src_port, char *data, int len)
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
	int ttlen = len + UDP_HEADER_SIZE;
	hdr->len = htons(ttlen);

	memcpy((uint8_t *)(hdr+UDP_HEADER_SIZE), data, len);
	
	uint32_t tmp = getsrcaddr(out_pkt,(uchar *)&dest_ip);
	// calcul checksum - alex
	uint16_t checksum = (tmp,dest_ip,hdr,(uint8_t *)data,len);
	if(checksum == 0){
		checksum = ~checksum;
	}
 	hdr->check = htons(checksum);
	// send
	IPOutgoingPacket(out_pkt, (uchar *)&dest_ip, ttlen, 1, UDP_PROTOCOL);

	return 0;
}

void udp_recv(gpacket_t *packet)
{
	// calcul et verifie checksum
    uint16_t udpChecksum;
    uint16_t tempChecksum;
    
    ip_packet_t *ipPacket = (ip_packet_t *) packet->data.data;
    uint16_t ipPacketLength = ntohs(ipPacket->ip_pkt_len);  
    
    uint32_t ipSource;
    uint32_t iPDestination;
   
    // convert header to right byte order 
    udphdr_t *udpHeader = (udphdr_t *)((uint8_t *)ipPacket + ipPacket->ip_hdr_len*4);
    udpHeader->source = ntohs(udpHeader->source);
    udpHeader->dest = ntohs(udpHeader->source);
    udpHeader->len = ntohs(udpHeader->len);
    udpHeader->check = ntohs(udpHeader->check);    

    uint8_t *data;
    data = (uint8_t *) udpHeader + UDP_HEADER_SIZE;
    int dataLength = udpHeader->len - UDP_HEADER_SIZE; 
    
 
    
    ipSource = ntohl(*((uint32_t *) &ipPacket->ip_src));
    iPDestination = ntohl(*((uint32_t *) &ipPacket->ip_dst));    
    
    if (udpHeader->check !=0) 
    {
        udpChecksum = udpHeader->check;
        udpHeader->check = 0;
        tempChecksum = cksum(ipSource, iPDestination, udpHeader, data, dataLength);

        if (udpChecksum != tempChecksum) 
        {
	    verbose(1, "[udp_recv]:: jai domper un packet");
            return;
        }
    }

/*	// verifie que le port est rouvert
    if (port_open(udpHeader->dest, UDP_PROTOCOL) == 0) 
    {
        ICMPProcessPortUnreachable(packet);
        return;
    }
*/
	
	char str[21];
	memcpy(str, (void *) data, 20);
	str[20] = 0;
	verbose(1, "[udp_recv]:: received packet.");
	verbose(1, str);	
   
	// donne le data au port layer (write_data(port, proto, buf len)) 
	write_data(udpHeader->dest,UDP_PROTOCOL,data,dataLength);
}
