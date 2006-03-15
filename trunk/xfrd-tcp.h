/*
 * xfrd-tcp.h - XFR (transfer) Daemon TCP system header file. Manages tcp conn.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef XFRD_TCP_H
#define XFRD_TCP_H

#include <config.h>

struct buffer;
struct xfrd_zone;
struct xfrd_soa;
struct xfrd_state;
struct region;
struct dname;
struct acl_options;

#define XFRD_MAX_TCP 10 /* max number of tcp connections */
#define XFRD_TCP_TIMEOUT TCP_TIMEOUT /* seconds */

typedef struct xfrd_tcp xfrd_tcp_t;
typedef struct xfrd_tcp_set xfrd_tcp_set_t;
/*
 * A set of xfrd tcp connections.
 */
struct xfrd_tcp_set {
	/* tcp connections, each has packet and read/wr state */
	struct xfrd_tcp *tcp_state[XFRD_MAX_TCP];
	/* number of TCP connections in use. */
	int tcp_count;
	/* linked list of zones waiting for a TCP connection */
	struct xfrd_zone *tcp_waiting_first, *tcp_waiting_last;
};

/*
 * Structure to keep track of an open tcp connection
 * The xfrd tcp connection is used to first make a request
 * Then to receive the answer packet(s).
 */
struct xfrd_tcp {
	/* tcp connection state */
	/* state: reading or writing */
	uint8_t is_reading;

	/* how many bytes have been read/written - total,
	   incl. tcp length bytes */
	uint32_t total_bytes;

	/* msg len bytes */
	uint16_t msglen;

	/* fd of connection. -1 means unconnected */
	int fd;

	/* packet buffer of connection */
	struct buffer* packet;
};

/* create set of tcp connections */
xfrd_tcp_set_t* xfrd_tcp_set_create(struct region* region);

/* init tcp state */
xfrd_tcp_t* xfrd_tcp_create(struct region* region);
/* obtain tcp connection for a zone (or wait) */
void xfrd_tcp_obtain(xfrd_tcp_set_t* set, struct xfrd_zone* zone);
/* release tcp connection for a zone (starts waiting) */
void xfrd_tcp_release(xfrd_tcp_set_t* set, struct xfrd_zone* zone);
/* use tcp connection to start xfr */
void xfrd_tcp_xfr(xfrd_tcp_set_t* set, struct xfrd_zone* zone);
/* initialize tcp_state for a zone. Opens the connection. true on success.*/
int xfrd_tcp_open(xfrd_tcp_set_t* set, struct xfrd_zone* zone);
/* read data from tcp, maybe partial read */
void xfrd_tcp_read(xfrd_tcp_set_t* set, struct xfrd_zone* zone);
/* write data to tcp, maybe a partial write */
void xfrd_tcp_write(xfrd_tcp_set_t* set, struct xfrd_zone* zone);

/* see if the tcp connection is in the reading stage (else writin) */
static inline int xfrd_tcp_is_reading(xfrd_tcp_set_t* set, int conn)
{return set->tcp_state[conn]->is_reading;}

/* setup DNS packet for a query of this type */
void xfrd_setup_packet(struct buffer* packet,
        uint16_t type, uint16_t klass, const struct dname* dname);
/* write soa in network format to the packet buffer */
void xfrd_write_soa_buffer(struct buffer* packet,
        struct xfrd_zone* zone, struct xfrd_soa* soa);
/* use acl address to setup sockaddr struct */
void xfrd_acl_sockaddr(struct acl_options* acl, struct sockaddr_storage *to);

#endif /* XFRD_TCP_H */
