/**
 * Implementation for ports.h
 **/

#include "ports.h"
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <slack/map.h>

typedef struct _port {
	int port;
	int proto;
	int pipe[2];
} port_t;

Map *udp_ports = NULL;
Map *tcp_ports = NULL;

pthread_mutex_t tcp_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t udp_lock = PTHREAD_MUTEX_INITIALIZER;

void port_free(void *port)
{
	port_t *p = (port_t *) port;
	close(p->pipe[0]);
	close(p->pipe[1]);

	free(port);
}

port_t *get(int port, int proto)
{
	pthread_mutex_t *lock;
	Map *map;

	if (!get_map(proto, &map, &lock)) {
		return NULL;
	}   

	pthread_mutex_lock(lock);

	port_t *p = (port_t *) map_get(map, &port); 

	pthread_mutex_unlock(lock);

	return p;
}

int add(int port, int proto, port_t *p) 
{
	pthread_mutex_t *lock;
	Map *map;

	if (!get_map(proto, &map, &lock)) {
		return 0;
	}   

	int ret = 1;

	pthread_mutex_lock(lock);

	if (map_add(map, &port, p) == -1) {
		ret = 0;
	}   

	pthread_mutex_unlock(lock);

	return ret;
}

int get_map(int proto, Map **map, pthread_mutex_t **lock)
{
	if (proto == UDP_PROTOCOL) {
		*map = udp_ports;
		*lock = &udp_lock;
	} else if (proto == TCP_PROTOCOL) {
		*map = tcp_ports;
		*lock = &tcp_lock;
	} else {
		return 0;
	}

	return 1;
}


void init_ports()
{
	udp_ports = map_create(port_free);
	tcp_ports = map_create(port_free);

	if (!udp_ports || !tcp_ports) {
		fatal("[init_ports]:: could not allocate memory for port data structures.");
		return;
	}
} 

int open_port(int port, int proto)
{


	// port already exists or isnt in valid range? fail
	if (port_open(port, proto) || !(port >= PORT_MIN && port <= PORT_MAX) ) {
		printf("Port is open\n");
		return 0;
	}	

	port_t *p = (port_t *) malloc(sizeof(port_t));

	if (!p) {
		fatal("[open_port]:: Could not allocated memory for new port");
		return 0;
	}

	p->port = port;
	p->proto = proto;

	if (pipe(p->pipe) == -1) {
		free(p);
		return 0;
	}

	// set write end to non-blocking so packetcore thread doesn't block 
	// waiting for app to empty pipe
	int flags = fcntl(p->pipe[1], F_GETFL);
	fcntl(p->pipe[1], F_SETFL, flags | O_NONBLOCK);

	flags = fcntl(p->pipe[0], F_GETFL);
	fcntl(p->pipe[0], F_SETFL, flags | O_NONBLOCK);

	if (!add(port, proto, p)) {

		printf("add failed\n");

		port_free(p);
		return 0;
	}

	return 1;
}

int close_port(int port, int proto)
{
	pthread_mutex_t *lock;
	Map *map;

	if (!get_map(proto, &map, &lock)) {
		return 0;
	}

	int ret = 1;

	pthread_mutex_lock(lock);

	if (map_remove(map, &port) == -1) {
		ret = 0;
	}	

	pthread_mutex_unlock(lock);

	return ret;
}

int grecv(int port, int proto, void *buf, size_t buf_len)
{
	port_t *p;

	if (!(p = get(port, proto))) {
		return -1;
	}

	return read(p->pipe[0], buf, buf_len);
}

/* Non blocking write */

int write_data(int port, int proto, void *buf, size_t buf_len)
{
	port_t * p;

	if (!(p = get(port, proto))) {
		return -1;
	}

	return write(p->pipe[1], buf, buf_len);
}

int port_open(int port, int proto)
{
	if (!get(port, proto)) {
		return 0;
	}

	return 1;
}

