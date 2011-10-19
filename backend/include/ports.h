/**
 * Ports to multiplex packets to applications.
 * As simple as possible to work with udp,
**/

#ifndef __PORTS_H__
#define __PORTS_H__

#include <stdlib.h>
#include <unistd.h>
#include "protocols.h"
#include "message.h"

#define PORT_MIN 0
#define PORT_MAX 65535



/**
 * According to wikipedia port numbers are not unique, they are per protocol, i.e.
 * you can open port number 45000 twice at the same time using UDP and TCP
**/


// these return 0 on failure or 1 on success unless otherwise specified

// open up a port using a given protocol
int open_port(int port, int proto);

// On a real machine you should not have the ability to read from any port!!!
// returns number of bytes copied into buf or -1 upon error
int recv(int port, int proto, void *buf, size_t buf_len);

// or close any port!
int close_port(int port, int proto);

/**
 * For internal grouter use only.
**/

// checks if a port has been opened by an application for a specific protocol
int port_open(int port, int proto);

/** hand off data to application layer 
 * non blocking, returns number of bytes written or -1 on error
**/
int write_data(int port, int proto, void *buf, size_t buf_len);

// allocate memory bla bla, should be called in grouter main
void init_ports(void);

#endif		/*__PORTS_H__*/
