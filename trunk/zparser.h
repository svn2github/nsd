/*
 * $Id: zparser.h,v 1.4 2003/02/14 21:15:56 alexis Exp $
 *
 * zparser.h -- master zone file parser
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

#ifndef _ZPARSER_H_
#define	_ZPARSER_H_

#define	ZBUFSIZE	16384		/* Maximum master file entry size */
#define	MAXRDATALEN	64		/* This is more than enough, think multiple TXT */
#define	MAXTOKENSLEN	512		/* Maximum number of tokens per entry */
#define	B64BUFSIZE	16384		/* Buffer size for b64 conversion */
#define	ROOT		(u_char *)"\001"

#define	IP6ADDRLEN	128/8

/* Type of rdata elements we might encounter */
#define RDATA_A		1
#define RDATA_A6	2
#define RDATA_B64	3
#define RDATA_BYTE	4
#define RDATA_DNAME	5
#define RDATA_LONG	6
#define RDATA_SHORT	7
#define RDATA_TEXT	8
#define RDATA_PERIOD	9
#define RDATA_TYPE	10
#define RDATA_TBITMAP	11
#define RDATA_TIME	12

/* A single resource record */
struct RR {
	u_char *dname;
	int32_t ttl;
	u_int16_t class;
	u_int16_t type;
	char *rdatafmt;
	u_int16_t **rdata;
};

/* An open parser */
struct zparser {
	FILE	*file;			/* The file handler */
	char	*filename;		/* Current filename */
	int	errors;			/* Errors encountered */
	u_long	_lineno;		/* Current line no */
	u_long	lines;			/* Total number of lines parser */
	int32_t	ttl;			/* Default ttl */
	u_int16_t class;		/* Class of this zone file */
	u_char	*origin;		/* Default origin */
	struct zparser *include;	/* If we're including a file */
	struct RR _rr;			/* Current resource record */
	int	_tc;			/* Current token to be parsed */
	int	_rc;			/* Current rdata to be parsed */
	char	*_t[MAXTOKENSLEN];	/* Tokens in the current line */
	char	_buf[ZBUFSIZE];	/* Current input buffer */
};

/* A generic purpose lookup table */
struct ztab {
	u_int16_t sym;
	char *name;
};

#define	Z_CLASSES {		\
	{CLASS_IN, "IN"},	\
	{0, NULL}		\
}

#define	Z_TYPES {		\
	{TYPE_A, "A"},		\
	{TYPE_NS, "NS"},	\
	{TYPE_MD, "MD"},	\
	{TYPE_MF, "MF"},	\
	{TYPE_CNAME, "CNAME"},	\
	{TYPE_SOA, "SOA"},	\
	{TYPE_MB, "MB"},	\
	{TYPE_MG, "MG"},	\
	{TYPE_MR, "MR"},	\
	{TYPE_NULL, "NULL"},	\
	{TYPE_WKS, "WKS"},	\
	{TYPE_PTR, "PTR"},	\
	{TYPE_HINFO, "HINFO"},	\
	{TYPE_MINFO, "MINFO"},	\
	{TYPE_MX, "MX"},	\
	{TYPE_TXT, "TXT"},	\
        {TYPE_AAAA, "AAAA"},	\
	{TYPE_SRV, "SRV"},	\
	{TYPE_NAPTR, "NAPTR"},	\
	{TYPE_LOC, "LOC"},	\
	{TYPE_AFSDB, "AFSDB"},	\
	{TYPE_RP, "RP"},	\
	{TYPE_SIG, "SIG"},	\
	{TYPE_KEY, "KEY"},	\
	{TYPE_NXT, "NXT"},	\
	{TYPE_DS, "DS"},	\
	{TYPE_ANY, "ANY"},	\
	{0, NULL}		\
}

extern void *xalloc(size_t size);
extern void *xrealloc(void *p, size_t size);

/* zparser.c */
u_int16_t intbyname(char *a, struct ztab *tab);
int zrdatacmp(u_int16_t **a, u_int16_t **b);
long strtottl(char *nptr, char **endptr);
void zerror(struct zparser *z, char *msg);
void zsyntax(struct zparser *z);
void zunexpected(struct zparser *z);
struct zparser *zopen(char *filename, u_int32_t ttl, u_int16_t class, char *origin);
struct zparser *_zopen(char *filename, u_int32_t ttl, u_int16_t class, u_char *origin);
struct RR *zread(struct zparser *z);
void zclose(struct zparser *z);
void zrdatafree(u_int16_t **rdata);
void zaddrdata(struct zparser *z, u_int16_t *r);
int zrdata(struct zparser *z);
int zrdatascan(struct zparser *z, int what);
int zrdata_loc(struct zparser *z);
void zaddtoken(struct zparser *z, char *t);
int zparseline(struct zparser *z);

#endif /* _ZPARSER_H_ */
