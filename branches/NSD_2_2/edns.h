/*
 * edns.h -- EDNS definitions (RFC 2671).
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _EDNS_H_
#define _EDNS_H_

#include "buffer.h"

#define	OPT_LEN	11U	                /* Length of the NSD EDNS response record. */
#define DNSSEC_OK_MASK  0x8000U         /* do bit mask */
#define NSID_DATA       "DEADBEAF"      /* bogus nsid, to showcase */
#define NSID_CODE       1               /* nsid option code */
#define NSID_LEN        8               /* lenght of the nsid data */
#define DNSSEC_OK_MASK 0x8000U  /* bitmask to get to the dnssec_ok bit */

struct edns_data
{
	char ok[OPT_LEN];
	char error[OPT_LEN];
        char nsid[4 + NSID_LEN]; 
};
typedef struct edns_data edns_data_type;

enum edns_status
{
	EDNS_NOT_PRESENT,
	EDNS_OK,
	EDNS_ERROR
};
typedef enum edns_status edns_status_type;

struct edns_record
{
	edns_status_type status;
	size_t           position;
	size_t           maxlen;
	int              dnssec_ok;
};
typedef struct edns_record edns_record_type;

void edns_init_data(edns_data_type *data, uint16_t max_length);
void edns_init_record(edns_record_type *data);
int edns_parse_record(edns_record_type *data, buffer_type *packet);

/*
 * The amount of space to reserve in the response for the EDNS data
 * (if required).
 */
size_t edns_reserved_space(edns_record_type *data);

#endif /* _EDNS_H_ */
