/*
 * $Id: server.c,v 1.12 2002/02/06 13:20:32 alexis Exp $
 *
 * server.c -- nsd(8) network input/output
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, NLnet Labs. All rights reserved.
 *
 * This software is an open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "nsd.h"

int
server(db)
	struct namedb *db;
{
	struct namedb *newdb;
	struct query *q;
	struct sockaddr_in addr;
	int s_udp, s_tcp, s_tcpio;
	u_int16_t tcplen;
	int received, sent;
	fd_set peer;

	/* A message to reject tcp connections... */
	tcp_open_connections = 0;

	/* UDP */
	bzero(&addr, sizeof(struct sockaddr_in));
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(cf_udp_port);
	addr.sin_family = AF_INET;

	/* Make a socket... */
	if((s_udp = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %m");
		return -1;
	}

	/* Bind it... */
	if(bind(s_udp, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
		syslog(LOG_ERR, "cant bind the socket: %m");
		return -1;
	}

	/* TCP */
	if((s_tcp = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %m");
		return -1;
	}

	/* Bind it... */
	if(bind(s_tcp, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
		syslog(LOG_ERR, "cant bind the socket: %m");
		return -1;
	}

	/* Listen to it... */
	if(listen(s_tcp, cf_tcp_max_connections) == -1) {
		syslog(LOG_ERR, "cant listen: %m");
		return -1;
	}

	/* Setup... */
	if((q = query_new()) == NULL) {
		syslog(LOG_ERR, "failed to allocate a query: %m");
		return -1;
	}


	/* The main loop... */	
	while(1) {
		/* Do we need to reload the database? */
		switch(server_mode) {
		case NSD_RELOAD:
			server_mode = NSD_RUN;
			if((newdb = namedb_open(db->filename)) == NULL) {
				syslog(LOG_ERR, "unable to reload the database: %m");
			}  else {
				namedb_close(db);
				db = newdb;
				syslog(LOG_WARNING, "database reloaded...");
			}
			break;
		case NSD_SHUTDOWN:
			namedb_close(db);
			exit(1);
			break;
		case NSD_RUN:
			break;
		default:
			break;
		}

		/* Set it up */
		FD_ZERO(&peer);
		FD_SET(s_udp, &peer);
		FD_SET(s_tcp, &peer);

		if(select((tcp_open_connections < cf_tcp_max_connections) ? s_tcp + 1 : s_udp + 1,
									&peer, NULL, NULL, NULL) == -1) {
			if(errno == EINTR) {
				/* We'll fall out of the loop if we need to shut down */
				continue;
			} else {
				syslog(LOG_ERR, "select failed: %m");
				break;
			}
		}
		if(FD_ISSET(s_udp, &peer)) {
#if DEBUG > 2
			printf("udp packet!\n");
#endif
			query_init(q);
			if((received = recvfrom(s_udp, q->iobuf, q->iobufsz, 0,
					(struct sockaddr *)&q->addr, &q->addrlen)) == -1) {
				syslog(LOG_ERR, "recvfrom failed: %m");
				/* XXX: We should think of better action here in instead of break; */
				continue;
			}
			q->iobufptr = q->iobuf + received;

			if(query_process(q, db) != -1) {
				if((sent = sendto(s_udp, q->iobuf, q->iobufptr - q->iobuf, 0,
					(struct sockaddr *)&q->addr, q->addrlen)) == -1) {
					syslog(LOG_ERR, "sendto failed: %m");
					/* XXX: We should think of better action here in instead of break; */
				} else if(sent != q->iobufptr - q->iobuf) {
					syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q->iobufptr - q->iobuf);
				}
			}
		} else if(FD_ISSET(s_tcp, &peer)) {
			query_init(q);
			q->maxlen = (q->iobufsz > cf_tcp_max_message_size) ? cf_tcp_max_message_size : q->iobufsz;
#if DEBUG > 2
			syslog(LOG_NOTICE, "tcp connection!");
#endif

			if((s_tcpio = accept(s_tcp, (struct sockaddr *)&q->addr, &q->addrlen)) == -1) {
				syslog(LOG_ERR, "accept failed: %m");
				continue;
			}

			switch(fork()) {
			case -1:
				syslog(LOG_ERR, "fork failed: %m");
				break;
			case 0:
				alarm(120);

				/* Until we've got end of file */
				while((received = read(s_tcpio, &tcplen, 2)) == 2) {
					if(ntohs(tcplen < 17)) {
						syslog(LOG_WARNING, "dropping bogus tcp connection");
						exit(0);
					}

					if(ntohs(tcplen) > q->iobufsz) {
						syslog(LOG_ERR, "insufficient tcp buffer, truncating incoming message");
						tcplen = htons(q->iobufsz);
					}

					/* We should use select or settimer() */
					alarm(120);

					if((received = read(s_tcpio, q->iobuf, ntohs(tcplen))) == -1) {
						if(errno == EINTR) {
							syslog(LOG_WARNING, "timed out reading tcp connection");
							exit(0);
						} else {
							syslog(LOG_ERR, "failed reading tcp connection: %m");
							exit(0);
						}
					}

					if(received == 0) {
						syslog(LOG_WARNING, "remote closed connection");
						exit(0);
					}

					if(received != ntohs(tcplen)) {
						syslog(LOG_WARNING, "couldnt read entire tcp message");
					}

					alarm(0);

					q->iobufptr = q->iobuf + received;

					if(query_process(q, db) != -1) {
						alarm(120);
						tcplen = htons(q->iobufptr - q->iobuf);
						if(((sent = write(s_tcpio, &tcplen, 2)) == -1) ||
							((sent = write(s_tcpio, q->iobuf, q->iobufptr - q->iobuf)) == -1)) {
								syslog(LOG_ERR, "write failed: %m");
								exit(0);
						}
						if(sent != q->iobufptr - q->iobuf) {
							syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q->iobufptr - q->iobuf);
						}
					}
					alarm(120);
				}
				if(received == -1) {
					if(errno == EINTR) {
						syslog(LOG_WARNING, "timed out reading tcp connection");
						exit(0);
					} else {
						syslog(LOG_ERR, "failed reading tcp connection: %m");
						exit(0);
					}
				}
				close(s_tcpio);
				exit(0);
			default:
				tcp_open_connections++;
				/* PARENT */
			}
		} else {
			/* Time out... */
			syslog(LOG_ERR, "select timed out");
		}
		/* Mostly NOTREACHED */
	}

	/* Clean up */
	query_destroy(q);
	close(s_tcp);
	close(s_udp);
	return -1;
}
