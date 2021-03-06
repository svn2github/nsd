/*
 * query.c -- nsd(8) the resolver.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#include "answer.h"
#include "axfr.h"
#include "dns.h"
#include "dname.h"
#include "nsd.h"
#include "namedb.h"
#include "plugins.h"
#include "query.h"
#include "util.h"

static int add_rrset(struct query  *query,
		     answer_type    *answer,
		     rr_section_type section,
		     domain_type    *owner,
		     rrset_type     *rrset);

static void answer_authoritative(struct query     *q,
				 answer_type      *answer,
				 uint32_t          domain_number,
				 int               exact,
				 domain_type      *closest_match,
				 domain_type      *closest_encloser);

void
query_put_dname_offset(struct query *q, domain_type *domain, uint16_t offset)
{
	assert(q);
	assert(domain);
	assert(domain->number > 0);

	if (offset > MAX_COMPRESSION_OFFSET)
		return;
	if (q->compressed_dname_count >= MAX_COMPRESSED_DNAMES)
		return;
	
	q->compressed_dname_offsets[domain->number] = offset;
	q->compressed_dnames[q->compressed_dname_count] = domain;
	++q->compressed_dname_count;
}

void
query_clear_dname_offsets(struct query *q, size_t max_offset)
{
	while (q->compressed_dname_count > 0
	       && (q->compressed_dname_offsets[q->compressed_dnames[q->compressed_dname_count - 1]->number]
		   >= max_offset))
	{
		q->compressed_dname_offsets[q->compressed_dnames[q->compressed_dname_count - 1]->number] = 0;
		--q->compressed_dname_count;
	}
}

void
query_clear_compression_tables(struct query *q)
{
	uint16_t i;
	
	for (i = 0; i < q->compressed_dname_count; ++i) {
		assert(q->compressed_dnames);
		q->compressed_dname_offsets[q->compressed_dnames[i]->number] = 0;
	}
	q->compressed_dname_count = 0;
}

void
query_add_compression_domain(struct query *q, domain_type *domain, uint16_t offset)
{
	while (domain->parent) {
		DEBUG(DEBUG_NAME_COMPRESSION, 1,
		      (stderr, "query dname: %s, number: %lu, offset: %u\n",
		       dname_to_string(domain_dname(domain), NULL),
		       (unsigned long) domain->number,
		       offset));
		query_put_dname_offset(q, domain, offset);
		offset += label_length(dname_name(domain_dname(domain))) + 1;
		domain = domain->parent;
	}
}

/*
 * Generate an error response with the specified RCODE.
 */
query_state_type
query_error (struct query *q, nsd_rc_type rcode)
{
	if (rcode == NSD_RC_DISCARD) {
		return QUERY_DISCARDED;
	}
	
	buffer_clear(q->packet);
	
	QR_SET(q->packet);	   /* This is an answer.  */
	RCODE_SET(q->packet, (int) rcode); /* Error code.  */
	
	/* Truncate the question as well... */
	QDCOUNT_SET(q->packet, 0);
	ANCOUNT_SET(q->packet, 0);
	NSCOUNT_SET(q->packet, 0);
	ARCOUNT_SET(q->packet, 0);
	buffer_set_position(q->packet, QHEADERSZ);
	return QUERY_PROCESSED;
}

static query_state_type
query_formerr (struct query *query)
{
	return query_error(query, NSD_RC_FORMAT);
}

static void
query_cleanup(void *data)
{
	query_type *query = (query_type *) data;
	region_destroy(query->region);
}

query_type *
query_create(region_type *region, uint16_t *compressed_dname_offsets)
{
	query_type *query
		= (query_type *) region_alloc_zero(region, sizeof(query_type));
	query->region = region_create(xalloc, free);
	query->compressed_dname_offsets = compressed_dname_offsets;
	query->packet = buffer_create(region, QIOBUFSZ);
	region_add_cleanup(region, query_cleanup, query);
	return query;
}

void 
query_reset(query_type *q, size_t maxlen, int is_tcp)
{
	region_free_all(q->region);
	q->addrlen = sizeof(q->addr);
	q->maxlen = maxlen;
	q->reserved_space = 0;
	buffer_clear(q->packet);
	edns_init_record(&q->edns);
	q->tcp = is_tcp;
	q->qname = NULL;
	q->qtype = 0;
	q->qclass = 0;
	q->zone = NULL;
	q->domain = NULL;
	q->opcode = 0;
	q->cname_count = 0;
	q->delegation_domain = NULL;
	q->delegation_rrset = NULL;
	q->compressed_dname_count = 0;

	q->axfr_is_done = 0;
	q->axfr_zone = NULL;
	q->axfr_current_domain = NULL;
	q->axfr_current_rrset = NULL;
	q->axfr_current_rr = 0;
}

static void 
query_addtxt(struct query  *q,
	     const uint8_t *dname,
	     uint16_t       klass,
	     uint32_t       ttl,
	     const char    *txt)
{
	size_t txt_length = strlen(txt);
	uint8_t len = (uint8_t) txt_length;

	assert(txt_length <= UCHAR_MAX);
	
	/* Add the dname */
	if (dname >= buffer_begin(q->packet)
	    && dname <= buffer_current(q->packet))
	{
		buffer_write_u16(q->packet,
				 0xc000 | (dname - buffer_begin(q->packet)));
	} else {
		buffer_write(q->packet, dname + 1, *dname);
	}

	buffer_write_u16(q->packet, TYPE_TXT);
	buffer_write_u16(q->packet, klass);
	buffer_write_u32(q->packet, ttl);
	buffer_write_u16(q->packet, len + 1);
	buffer_write_u8(q->packet, len);
	buffer_write(q->packet, txt, len);
}

/*
 * Parse the question section of a query.  The normalized query name
 * is stored in QUERY->name, the class in QUERY->klass, and the type
 * in QUERY->type.
 */
static nsd_rc_type
process_query_section(query_type *query)
{
	uint8_t qnamebuf[MAXDOMAINLEN];

	uint8_t *dst = qnamebuf;
	uint8_t *query_name = buffer_at(query->packet, QHEADERSZ);
	uint8_t *src = query_name;
	size_t len;
	
	/* Lets parse the query name and convert it to lower case.  */
	while (*src) {
		/*
		 * If we are out of buffer limits or we have a pointer
		 * in question dname or the domain name is longer than
		 * MAXDOMAINLEN ...
		 */
		if ((*src & 0xc0) ||
		    (src + *src + 1 > buffer_end(query->packet)) || 
		    (src + *src + 1 > query_name + MAXDOMAINLEN))
		{
			return NSD_RC_FORMAT;
		}
		memcpy(dst, src, *src + 1);
		dst += *src + 1;
		src += *src + 1;
	}
	*dst++ = *src++;

	/* Make sure name is not too long or we have stripped packet... */
	len = src - query_name;
	if (len > MAXDOMAINLEN ||
	    (src + 2*sizeof(uint16_t) > buffer_end(query->packet)))
	{
		return NSD_RC_FORMAT;
	}
	buffer_set_position(query->packet, src - buffer_begin(query->packet));

	query->qname = dname_make(query->region, qnamebuf, 1);
	query->qtype = buffer_read_u16(query->packet);
	query->qclass = buffer_read_u16(query->packet);
	query->opcode = OPCODE(query->packet);

	return NSD_RC_OK;
}


/*
 * Process an optional EDNS OPT record.  Sets QUERY->EDNS to 0 if
 * there was no EDNS record, to -1 if there was an invalid or
 * unsupported EDNS record, and to 1 otherwise.  Updates QUERY->MAXLEN
 * if the EDNS record specifies a maximum supported response length.
 *
 * Return 0 on failure, 1 on success.
 */
static nsd_rc_type
process_edns(struct query *q)
{
	if (q->edns.status == EDNS_ERROR) {
		return NSD_RC_FORMAT;
	}
	if (q->edns.status == EDNS_OK) {
		/* Only care about UDP size larger than normal... */
		if (!q->tcp && q->edns.maxlen > UDP_MAX_MESSAGE_LEN) {
			if (q->edns.maxlen < EDNS_MAX_MESSAGE_LEN) {
				q->maxlen = q->edns.maxlen;
			} else {
				q->maxlen = EDNS_MAX_MESSAGE_LEN;
			}
			
#if defined(INET6) && !defined(IPV6_USE_MIN_MTU)
			/*
			 * Use IPv6 minimum MTU to avoid sending
			 * packets that are too large for some links.
			 * IPv6 will not automatically fragment in
			 * this case (unlike IPv4).
			 */
			if (q->addr.ss_family == AF_INET6
			    && q->maxlen > IPV6_MIN_MTU)
			{
				q->maxlen = IPV6_MIN_MTU;
			}
#endif
		}
		
		/* Strip the OPT resource record off... */
		buffer_set_position(q->packet, q->edns.position);
		buffer_set_limit(q->packet, q->edns.position);
		ARCOUNT_SET(q->packet, ARCOUNT(q->packet) - 1);
	}
	return NSD_RC_OK;
}

/*
 * Log notifies and return an RCODE_IMPL error to the client.
 *
 * XXX: erik: Is this the right way to handle notifies?
 */
static query_state_type
answer_notify (struct query *query)
{
	char namebuf[BUFSIZ];

	if (getnameinfo((struct sockaddr *) &(query->addr),
			query->addrlen, namebuf, sizeof(namebuf), 
			NULL, 0, NI_NUMERICHOST)
	    != 0)
	{
		log_msg(LOG_INFO, "notify for %s from unknown remote address",
			dname_to_string(query->qname, NULL));
	} else {
		log_msg(LOG_INFO, "notify for %s from %s",
			dname_to_string(query->qname, NULL), namebuf);
	}

	return query_error(query, NSD_RC_IMPL);
}


/*
 * Answer a query in the CHAOS class.
 */
static query_state_type
answer_chaos(struct nsd *nsd, query_type *q)
{
	AA_CLR(q->packet);
	switch (q->qtype) {
	case TYPE_ANY:
	case TYPE_TXT:
		if ((q->qname->name_size == 11
		     && memcmp(dname_name(q->qname), "\002id\006server", 11) == 0) || 
		    (q->qname->name_size ==  15
		     && memcmp(dname_name(q->qname), "\010hostname\004bind", 15) == 0))
		{
			/* Add ID */
			query_addtxt(q,
				     buffer_begin(q->packet) + QHEADERSZ,
				     CLASS_CH,
				     0,
				     nsd->identity);
			ANCOUNT_SET(q->packet, ANCOUNT(q->packet) + 1);
		} else if ((q->qname->name_size == 16
			    && memcmp(dname_name(q->qname), "\007version\006server", 16) == 0) ||
			   (q->qname->name_size == 14
			    && memcmp(dname_name(q->qname), "\007version\004bind", 14) == 0))
		{
			/* Add version */
			query_addtxt(q,
				     buffer_begin(q->packet) + QHEADERSZ,
				     CLASS_CH,
				     0,
				     nsd->version);
			ANCOUNT_SET(q->packet, ANCOUNT(q->packet) + 1);
		}
		break;
	default:
		RCODE_SET(q->packet, RCODE_REFUSE);
		break;
	}

	return QUERY_PROCESSED;
}


/*
 * Find the covering NSEC for a non-existent domain name.  Normally
 * the NSEC will be located at CLOSEST_MATCH, except when it is an
 * empty non-terminal.  In this case the NSEC may be located at the
 * previous domain name (in canonical ordering).
 */
static domain_type *
find_covering_nsec(domain_type *closest_match,
		   zone_type   *zone,
		   rrset_type **nsec_rrset)
{
	assert(closest_match);
	assert(nsec_rrset);

	while (closest_match) {
		*nsec_rrset = domain_find_rrset(closest_match, zone, TYPE_NSEC);
		if (*nsec_rrset) {
			return closest_match;
		}
		if (closest_match == zone->apex) {
			/* Don't look outside the current zone.  */
			return NULL;
		}
		closest_match = domain_previous(closest_match);
	}
	return NULL;
}


struct additional_rr_types
{
	uint16_t        rr_type;
	rr_section_type rr_section;
};

struct additional_rr_types default_additional_rr_types[] = {
	{ TYPE_A, ADDITIONAL_A_SECTION },
	{ TYPE_AAAA, ADDITIONAL_AAAA_SECTION },
	{ 0, (rr_section_type) 0 }
};

struct additional_rr_types rt_additional_rr_types[] = {
	{ TYPE_A, ADDITIONAL_A_SECTION },
	{ TYPE_AAAA, ADDITIONAL_AAAA_SECTION },
	{ TYPE_X25, ADDITIONAL_OTHER_SECTION },
	{ TYPE_ISDN, ADDITIONAL_OTHER_SECTION },
	{ 0, (rr_section_type) 0 }
};

static void
add_additional_rrsets(struct query *query, answer_type *answer,
		      rrset_type *master_rrset, size_t rdata_index,
		      int allow_glue, struct additional_rr_types types[])
{
	size_t i;
	
	assert(query);
	assert(answer);
	assert(master_rrset);
	assert(rdata_atom_is_domain(rrset_rrtype(master_rrset), rdata_index));
	
	for (i = 0; i < master_rrset->rr_count; ++i) {
		int j;
		domain_type *additional = rdata_atom_domain(master_rrset->rrs[i].rdatas[rdata_index]);
		domain_type *match = additional;
		
		assert(additional);

		if (!allow_glue && domain_is_glue(match, query->zone))
			continue;
		
		/*
		 * Check to see if we need to generate the dependent
		 * based on a wildcard domain.
		 */
		while (!match->is_existing) {
			match = match->parent;
		}
		if (additional != match && domain_wildcard_child(match)) {
			domain_type *wildcard_child = domain_wildcard_child(match);
			domain_type *temp = (domain_type *) region_alloc(
				query->region, sizeof(domain_type));
			memcpy(&temp->node, &additional->node, sizeof(rbnode_t));
			temp->number = additional->number;
			temp->parent = match;
			temp->wildcard_child_closest_match = temp;
			temp->rrsets = wildcard_child->rrsets;
#ifdef PLUGINS
			temp->plugin_data = wildcard_child->plugin_data;
#endif
			temp->is_existing = wildcard_child->is_existing;
			additional = temp;
		}

		for (j = 0; types[j].rr_type != 0; ++j) {
			rrset_type *rrset = domain_find_rrset(
				additional, query->zone, types[j].rr_type);
			if (rrset) {
				answer_add_rrset(answer, types[j].rr_section,
						 additional, rrset);
			}
		}
	}
}

static int
add_rrset(struct query   *query,
	  answer_type    *answer,
	  rr_section_type section,
	  domain_type    *owner,
	  rrset_type     *rrset)
{
	int result;
	
	assert(query);
	assert(answer);
	assert(owner);
	assert(rrset);
	assert(rrset_rrclass(rrset) == CLASS_IN);
	
	result = answer_add_rrset(answer, section, owner, rrset);
	switch (rrset_rrtype(rrset)) {
	case TYPE_NS:
		add_additional_rrsets(query, answer, rrset, 0, 1,
				      default_additional_rr_types);
		break;
	case TYPE_MB:
		add_additional_rrsets(query, answer, rrset, 0, 0,
				      default_additional_rr_types);
		break;
	case TYPE_MX:
	case TYPE_KX:
		add_additional_rrsets(query, answer, rrset, 1, 0,
				      default_additional_rr_types);
		break;
	case TYPE_RT:
		add_additional_rrsets(query, answer, rrset, 1, 0,
				      rt_additional_rr_types);
		break;
	default:
		break;
	}

	return result;
}


/*
 * Answer delegation information.
 *
 * DNSSEC: Include the DS RRset if present.  Otherwise include an NSEC
 * record proving the DS RRset does not exist.
 */
static void
answer_delegation(query_type *query, answer_type *answer)
{
	assert(answer);
	assert(query->delegation_domain);
	assert(query->delegation_rrset);
	
	AA_CLR(query->packet);
	add_rrset(query,
		  answer,
		  AUTHORITY_SECTION,
		  query->delegation_domain,
		  query->delegation_rrset);
	if (query->edns.dnssec_ok && zone_is_secure(query->zone)) {
		rrset_type *rrset;
		if ((rrset = domain_find_rrset(query->delegation_domain, query->zone, TYPE_DS))) {
			add_rrset(query, answer, AUTHORITY_SECTION,
				  query->delegation_domain, rrset);
		} else if ((rrset = domain_find_rrset(query->delegation_domain, query->zone, TYPE_NSEC))) {
			add_rrset(query, answer, AUTHORITY_SECTION,
				  query->delegation_domain, rrset);
		}
	}
	query->domain = query->delegation_domain;
}


/*
 * Answer SOA information.
 */
static void
answer_soa(struct query *query, answer_type *answer)
{
	query->domain = query->zone->apex;
	
	if (query->qclass != CLASS_ANY) {
		add_rrset(query, answer,
			  AUTHORITY_SECTION,
			  query->zone->apex,
			  query->zone->soa_rrset);
	}
}


/*
 * Answer that the domain name exists but there is no RRset with the
 * requested type.
 *
 * DNSSEC: Include the correct NSEC record proving that the type does
 * not exist.  In the wildcard no data (3.1.3.4) case the wildcard IS
 * NOT expanded, so the ORIGINAL parameter must point to the original
 * wildcard entry, not to the generated entry.
 */
static void
answer_nodata(struct query *query, answer_type *answer, domain_type *original)
{
	if (query->cname_count == 0) {
		answer_soa(query, answer);
	}
	
	if (query->edns.dnssec_ok && zone_is_secure(query->zone)) {
		domain_type *nsec_domain;
		rrset_type *nsec_rrset;

		nsec_domain = find_covering_nsec(original, query->zone, &nsec_rrset);
		if (nsec_domain) {
			add_rrset(query, answer, AUTHORITY_SECTION, nsec_domain, nsec_rrset);
		}
	}
}

static void
answer_nxdomain(query_type *query, answer_type *answer)
{
	if (query->cname_count == 0) {
		RCODE_SET(query->packet, RCODE_NXDOMAIN);
		answer_soa(query, answer);
	}
}


/*
 * Answer domain information (or SOA if we do not have an RRset for
 * the type specified by the query).
 */
static void
answer_domain(struct query *q, answer_type *answer,
	      domain_type *domain, domain_type *original)
{
	rrset_type *rrset;
	
	if (q->qtype == TYPE_ANY) {
		int added = 0;
		for (rrset = domain_find_any_rrset(domain, q->zone); rrset; rrset = rrset->next) {
			if (rrset->zone == q->zone
			    /*
			     * Don't include the RRSIG RRset when
			     * DNSSEC is used, because it is added
			     * automatically on an per-RRset basis.
			     */
			    && !(q->edns.dnssec_ok
				 && zone_is_secure(q->zone)
				 && rrset_rrtype(rrset) == TYPE_RRSIG))
			{
				add_rrset(q, answer, ANSWER_SECTION, domain, rrset);
				++added;
			}
		}
		if (added == 0) {
			answer_nodata(q, answer, original);
			return;
		}
	} else if ((rrset = domain_find_rrset(domain, q->zone, q->qtype))) {
		add_rrset(q, answer, ANSWER_SECTION, domain, rrset);
	} else if ((rrset = domain_find_rrset(domain, q->zone, TYPE_CNAME))) {
		size_t i;
		int added;

		/*
		 * If the CNAME is not added it is already in the
		 * answer, so we have a CNAME loop.  Don't follow the
		 * CNAME target in this case.
		 */
		added = add_rrset(q, answer, ANSWER_SECTION, domain, rrset);
		if (added) {
			++q->cname_count;
			for (i = 0; i < rrset->rr_count; ++i) {
				domain_type *closest_match = rdata_atom_domain(rrset->rrs[i].rdatas[0]);
				domain_type *closest_encloser = closest_match;
				
				while (!closest_encloser->is_existing)
					closest_encloser = closest_encloser->parent;
				
				answer_authoritative(q, answer, closest_match->number,
						     closest_match == closest_encloser,
						     closest_match, closest_encloser);
			}
		}
	} else {
		answer_nodata(q, answer, original);
		return;
	}

	q->domain = domain;
	
	if (q->qclass != CLASS_ANY && q->zone->ns_rrset) {
		add_rrset(q, answer, AUTHORITY_SECTION, q->zone->apex,
			  q->zone->ns_rrset);
	}
}


/*
 * Answer with authoritative data.  If a wildcard is matched the owner
 * name will be expanded to the domain name specified by
 * DOMAIN_NUMBER.  DOMAIN_NUMBER 0 (zero) is reserved for the original
 * query name.
 *
 * DNSSEC: Include the necessary NSEC records in case the request
 * domain name does not exist and/or a wildcard match does not exist.
 */
static void
answer_authoritative(struct query *q,
		     answer_type  *answer,
		     uint32_t      domain_number,
		     int           exact,
		     domain_type  *closest_match,
		     domain_type  *closest_encloser)
{
	domain_type *match;
	domain_type *original = closest_match;
	
	if (exact) {
		match = closest_match;
	} else if (domain_wildcard_child(closest_encloser)) {
		/* Generate the domain from the wildcard.  */
		domain_type *wildcard_child = domain_wildcard_child(closest_encloser);

		match = (domain_type *) region_alloc(q->region,
						     sizeof(domain_type));
		memcpy(&match->node, &wildcard_child->node, sizeof(rbnode_t));
		match->parent = closest_encloser;
		match->wildcard_child_closest_match = match;
		match->number = domain_number;
		match->rrsets = wildcard_child->rrsets;
#ifdef PLUGINS
		match->plugin_data = wildcard_child->plugin_data;
#endif
		match->is_existing = wildcard_child->is_existing;

		/*
		 * Remember the original domain in case a Wildcard No
		 * Data (3.1.3.4) response needs to be generated.  In
		 * this particular case the wildcard IS NOT
		 * expanded.
		 */
		original = wildcard_child;
	} else {
		match = NULL;
	}

	/* Authorative zone.  */
	if (q->edns.dnssec_ok && zone_is_secure(q->zone)) {
		if (match != closest_encloser) {
			domain_type *nsec_domain;
			rrset_type *nsec_rrset;
			
			/*
			 * No match found or generated from wildcard,
			 * include NSEC record.
			 */
			nsec_domain = find_covering_nsec(closest_match, q->zone, &nsec_rrset);
			if (nsec_domain) {
				add_rrset(q, answer, AUTHORITY_SECTION, nsec_domain, nsec_rrset);
			}
		}
		if (!match) {
			domain_type *nsec_domain;
			rrset_type *nsec_rrset;

			/*
			 * No match and no wildcard.  Include NSEC
			 * proving there is no wildcard.
			 */
			nsec_domain = find_covering_nsec(closest_encloser->wildcard_child_closest_match, q->zone, &nsec_rrset);
			if (nsec_domain) {
				add_rrset(q, answer, AUTHORITY_SECTION, nsec_domain, nsec_rrset);
			}
		}
	}
	
	if (match) {
		answer_domain(q, answer, match, original);
	} else {
		answer_nxdomain(q, answer);
	}
}

static void
answer_query(struct nsd *nsd, struct query *q)
{
	domain_type *closest_match;
	domain_type *closest_encloser;
	uint16_t offset;
	int exact;
	answer_type answer;

	exact = namedb_lookup(nsd->db, q->qname, &closest_match, &closest_encloser);
	if (!closest_encloser->is_existing) {
		exact = 0;
		while (closest_encloser != NULL && !closest_encloser->is_existing)
			closest_encloser = closest_encloser->parent;
	}

	q->domain = closest_encloser;
	
	q->zone = domain_find_zone(closest_encloser);
	if (!q->zone) {
		RCODE_SET(q->packet, RCODE_SERVFAIL);
		return;
	}

	answer_init(&answer);

	/*
	 * See 3.1.4.1 Responding to Queries for DS RRs in DNSSEC
	 * protocol.
	 */
	if (exact && q->qtype == TYPE_DS && closest_encloser == q->zone->apex) {
		/*
		 * Type DS query at a zone cut, use the responsible
		 * parent zone to generate the answer if we are
		 * authoritative for the parent zone.
		 */
		zone_type *zone = domain_find_parent_zone(q->zone);
		if (zone)
			q->zone = zone;
	}

	if (exact && q->qtype == TYPE_DS && closest_encloser == q->zone->apex) {
		/*
		 * Type DS query at the zone apex (and the server is
		 * not authoratitive for the parent zone).
		 */
		if (q->qclass == CLASS_ANY) {
			AA_CLR(q->packet);
		} else {
			AA_SET(q->packet);
		}
		answer_nodata(q, &answer, closest_encloser);
	} else {
		q->delegation_domain = domain_find_ns_rrsets(
			closest_encloser, q->zone, &q->delegation_rrset);

		if (!q->delegation_domain
		    || (exact && q->qtype == TYPE_DS && closest_encloser == q->delegation_domain))
		{
			if (q->qclass == CLASS_ANY) {
				AA_CLR(q->packet);
			} else {
				AA_SET(q->packet);
			}
			answer_authoritative(q, &answer, 0, exact,
					     closest_match, closest_encloser);
		}
		else {
			answer_delegation(q, &answer);
		}
	}

	offset = dname_label_offsets(q->qname)[domain_dname(closest_encloser)->label_count - 1] + QHEADERSZ;
	query_add_compression_domain(q, closest_encloser, offset);

	encode_answer(q, &answer);

	query_clear_compression_tables(q);
}

void
query_prepare_response(query_type *q)
{
	uint16_t flags;
	
	/*
	 * Preserve the data up-to the current packet's limit.
	 */
	buffer_set_position(q->packet, buffer_limit(q->packet));
	buffer_set_limit(q->packet, buffer_capacity(q->packet));
	
	/*
	 * Reserve space for the EDNS records if required.
	 */
	q->reserved_space = edns_reserved_space(&q->edns);
	
	/* Update the flags.  */
	flags = FLAGS(q->packet);
#ifdef DNSSEC
	flags &= 0x0110U;	/* Preserve the RD and CD flags.  */
#else
	flags &= 0x0100U;	/* Preserve the RD flag.  */
#endif
	flags |= 0x8000U;	/* Set the QR flag.  */
	FLAGS_SET(q->packet, flags);
}

/*
 * Processes the query.
 *
 */
query_state_type
query_process(query_type *q, nsd_type *nsd)
{
	/* The query... */
	nsd_rc_type rc;
	query_state_type query_state;
	uint16_t arcount;
	
	/* Sanity checks */
	if (QR(q->packet)) {
		/* Not a query? Drop it on the floor. */
		return QUERY_DISCARDED;
	}

	rc = process_query_section(q);
	if (rc != NSD_RC_OK) {
		return query_error(q, rc);
	}

	/* Update statistics.  */
	STATUP2(nsd, opcode, q->opcode);
	STATUP2(nsd, qtype, q->qtype);
	STATUP2(nsd, qclass, q->qclass);

	if (q->opcode != OPCODE_QUERY) {
		if (q->opcode == OPCODE_NOTIFY) {
			return answer_notify(q);
		} else {
			return query_error(q, NSD_RC_IMPL);
		}
	}

	/* Dont bother to answer more than one question at once... */
	if (QDCOUNT(q->packet) != 1 || TC(q->packet)) {
		FLAGS_SET(q->packet, 0);
		return query_formerr(q);
	}

	/* Dont allow any records in the answer or authority section... */
	if (ANCOUNT(q->packet) != 0 || NSCOUNT(q->packet) != 0) {
		return query_formerr(q);
	}

	arcount = ARCOUNT(q->packet);
	if (arcount > 0) {
		if (edns_parse_record(&q->edns, q->packet))
			--arcount;
	}
	if (arcount > 0) {
		return query_formerr(q);
	}

	/* Do we have any trailing garbage? */
#ifdef	STRICT_MESSAGE_PARSE
	if (buffer_remaining(q->packet) > 0) {
		/* If we're strict.... */
		return query_formerr(q);
	}
#endif
	/* Remove trailing garbage.  */
	buffer_set_limit(q->packet, buffer_position(q->packet));
	
	rc = process_edns(q);
	if (rc != NSD_RC_OK) {
		return query_error(q, rc);
	}

	query_prepare_response(q);
	
	if (q->qclass != CLASS_IN && q->qclass != CLASS_ANY) {
		if (q->qclass == CLASS_CH) {
			return answer_chaos(nsd, q);
		} else {
			return query_error(q, NSD_RC_REFUSE);
		}
	}

	query_state = answer_axfr_ixfr(nsd, q);
	if (query_state == QUERY_PROCESSED || query_state == QUERY_IN_AXFR) {
		return query_state;
	}

	answer_query(nsd, q);

	return QUERY_PROCESSED;
}

void
query_add_optional(query_type *q, nsd_type *nsd)
{
	struct edns_data *edns = &nsd->edns_ipv4;
#if defined(INET6)
	if (q->addr.ss_family == AF_INET6) {
		edns = &nsd->edns_ipv6;
	}
#endif
	switch (q->edns.status) {
	case EDNS_NOT_PRESENT:
		break;
	case EDNS_OK:
		buffer_write(q->packet, edns->ok, OPT_LEN);
		ARCOUNT_SET(q->packet, ARCOUNT(q->packet) + 1);

		STATUP(nsd, edns);
		break;
	case EDNS_ERROR:
		buffer_write(q->packet, edns->error, OPT_LEN);
		ARCOUNT_SET(q->packet, ARCOUNT(q->packet) + 1);

		STATUP(nsd, ednserr);
		break;
	}
}
