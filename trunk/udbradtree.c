/*
 * udbradtree -- radix tree for binary strings for in udb file.
 *
 * Copyright (c) 2011, NLnet Labs.  See LICENSE for license.
 */
#include "config.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "udbradtree.h"
#include "radtree.h"
#define RADTREE(ptr) ((struct udb_radtree_d*)UDB_PTR(ptr))
#define RADNODE(ptr) ((struct udb_radnode_d*)UDB_PTR(ptr))
#define RADARRAY(ptr) ((struct udb_radarray_d*)UDB_PTR(ptr))

int udb_radix_tree_create(udb_base* udb, udb_ptr* ptr)
{
	if(!udb_ptr_alloc_space(ptr, udb, udb_chunk_type_radtree,
		sizeof(struct udb_radtree_d)))
		return 0;
	udb_rel_ptr_init(&RADTREE(ptr)->root);
	RADTREE(ptr)->count = 0;
	return 1;
}

/** size in bytes of data in the array lookup structure */
static size_t size_of_lookup(udb_ptr* lookup)
{
	return sizeof(struct udb_radarray_d)+
		((size_t)RADARRAY(lookup)->capacity)*(
		sizeof(struct udb_radsel_d)+(size_t)RADARRAY(lookup)->str_cap);
}

/** size needed for a lookup array like this */
static size_t size_of_lookup_needed(uint16_t capacity, udb_radstrlen_t str_cap)
{
	return sizeof(struct udb_radarray_d)+ ((size_t)capacity)*(
		sizeof(struct udb_radsel_d)+(size_t)str_cap);
}

/** get the lookup array for a node */
static struct udb_radarray_d* lookup(udb_ptr* n)
{
	return (struct udb_radarray_d*)UDB_REL(*n->base,
		RADNODE(n)->lookup.data);
}

/** get a length in the lookup array */
static udb_radstrlen_t lookup_len(udb_ptr* n, unsigned i)
{
	return lookup(n)->array[i].len;
}

/** get a string in the lookup array */
static uint8_t* lookup_string(udb_ptr* n, unsigned i)
{
	return ((uint8_t*)&(lookup(n)->array[lookup(n)->capacity]))+
		i*lookup(n)->str_cap;
}

/** get a node in the lookup array */
static struct udb_radnode_d* lookup_node(udb_ptr* n, unsigned i)
{
	return (struct udb_radnode_d*)UDB_REL(*n->base,
		lookup(n)->array[i].node.data);
}

/** delete radnodes in postorder recursion, n is ptr to node */
static void udb_radnode_del_postorder(udb_base* udb, udb_ptr* n)
{
	unsigned i;
	udb_ptr sub, lookup;
	if(udb_ptr_is_null(n))
		return;
	udb_ptr_new(&lookup, udb, &RADNODE(n)->lookup);
	udb_ptr_init(&sub, udb);
	
	for(i=0; i<RADARRAY(&lookup)->len; i++) {
		udb_ptr_set_rptr(&sub, udb, &RADARRAY(&lookup)->array[i].node);
		udb_radnode_del_postorder(udb, &sub);
	}
	udb_ptr_unlink(&sub, udb);
	/* no need to zero relptrs because it all gets deleted */
	udb_ptr_free_space(&lookup, udb, size_of_lookup(&lookup));
	udb_ptr_unlink(&lookup, udb);
	udb_ptr_free_space(n, udb, sizeof(struct udb_radnode_d));
}

void udb_radix_tree_clear(udb_base* udb, udb_ptr* rt)
{
	udb_ptr root;
	udb_ptr_new(&root, udb, &RADTREE(rt)->root);
	/* free the root node (and its descendants, if any) */
	udb_radnode_del_postorder(udb, &root);
	udb_ptr_unlink(&root, udb);

	udb_rptr_zero(&RADTREE(rt)->root, udb);
	RADTREE(rt)->count = 0;
}

void udb_radix_tree_delete(udb_base* udb, udb_ptr* rt)
{
	udb_radix_tree_clear(udb, rt);
	udb_ptr_free_space(rt, udb, sizeof(struct udb_radtree_d));
}

/** 
 * Find a prefix of the key, in whole-nodes.
 * Finds the longest prefix that corresponds to a whole radnode entry.
 * There may be a slightly longer prefix in one of the array elements.
 * @param result: the longest prefix, the entry itself if *respos==len,
 *      otherwise an array entry, residx.  Output.
 * @param respos: pos in string where next unmatched byte is, if == len an
 *      exact match has been found.  If == 0 then a "" match was found.
 * @return false if no prefix found, not even the root "" prefix.
 */
static int udb_radix_find_prefix_node(udb_base* udb, udb_ptr* rt, uint8_t* k,
	udb_radstrlen_t len, udb_ptr* result, udb_radstrlen_t* respos)
{
	udb_radstrlen_t pos = 0;
	uint8_t byte;
	udb_ptr n;
	printf("prefix start %llx\n", (unsigned long long)result->data);
	udb_ptr_new(&n, udb, &RADTREE(rt)->root);
	printf("prefix afternew %llx\n", (unsigned long long)result->data);

	*respos = 0;
	printf("find_prefix assign root\n");
	udb_ptr_set_ptr(result, udb, &n);
	printf("firstassign got accomodate node %llx\n", 
			(unsigned long long)result->data);
	if(udb_ptr_is_null(&n)) {
		udb_ptr_unlink(&n, udb);
		return 0;
	}
	while(!udb_ptr_is_null(&n)) {
		if(pos == len) {
			break;
		}
		byte = k[pos];
		if(byte < RADNODE(&n)->offset) {
			break;
		}
		byte -= RADNODE(&n)->offset;
		if(byte >= lookup(&n)->len) {
			break;
		}
		pos++;
		if(lookup(&n)->array[byte].len != 0) {
			/* must match additional string */
			if(pos+lookup(&n)->array[byte].len > len) {
				break;
			}
			if(memcmp(&k[pos], lookup_string(&n, byte),
				lookup(&n)->array[byte].len) != 0) {
				break;
			}
			pos += lookup(&n)->array[byte].len;
		}
		udb_ptr_set_rptr(&n, udb, &lookup(&n)->array[byte].node);
		if(udb_ptr_is_null(&n)) {
			break;
		}
		*respos = pos;
		udb_ptr_set_ptr(result, udb, &n);
	}
	printf("endloop got accomodate node %llx\n", 
			(unsigned long long)result->data);
	udb_ptr_unlink(&n, udb);
	printf("endprefix got accomodate node %llx\n", 
			(unsigned long long)result->data);
	return 1;
}

/** zero the relptrs in radarray */
static void udb_radarray_zero_ptrs(udb_base* udb, udb_ptr* n)
{
	unsigned i;
	for(i=0; i<lookup(n)->len; i++) {
		udb_rptr_zero(&lookup(n)->array[i].node, udb);
	}
}

/** grow the radnode stringcapacity, copy existing elements */
static int udb_radnode_str_grow(udb_base* udb, udb_ptr* n, udb_radstrlen_t want)
{
	unsigned ns = ((unsigned)lookup(n)->str_cap)*2;
	unsigned i;
	udb_ptr a;
	printf("udb_radnode_str_grow str_cap=%d want=%d\n",
		(int)lookup(n)->str_cap, (int)want);
	if(want > ns)
		ns = want;
	if(ns > 65535) ns = 65535; /* MAX of udb_radstrlen_t range */
	/* if this fails, the tree is still usable */
	if(!udb_ptr_alloc_space(&a, udb, udb_chunk_type_radarray,
		size_of_lookup_needed(lookup(n)->capacity, ns)))
		return 0;
	memcpy(RADARRAY(&a), lookup(n), sizeof(struct udb_radarray_d));
	for(i = 0; i < lookup(n)->len; i++) {
		udb_rel_ptr_init(&RADARRAY(&a)->array[i].node);
		udb_rptr_set_rptr(&RADARRAY(&a)->array[i].node, udb,
			&lookup(n)->array[i].node);
		RADARRAY(&a)->array[i].len = lookup_len(n, i);
		memmove(((uint8_t*)(&RADARRAY(&a)->array[
			lookup(n)->capacity]))+i*ns,
			lookup_string(n, i), lookup(n)->str_cap);
	}
	udb_radarray_zero_ptrs(udb, n);
	udb_rptr_zero(&RADNODE(n)->lookup, udb);
	udb_rel_ptr_free_space(&RADNODE(n)->lookup, udb, size_of_lookup(n));
	udb_rptr_set_ptr(&RADNODE(n)->lookup, udb, &a);
	lookup(n)->str_cap = ns;
	udb_ptr_unlink(&a, udb);
	return 1;
}

/** grow the radnode array, copy existing elements to start of new array */
static int udb_radnode_array_grow(udb_base* udb, udb_ptr* n, size_t want)
{
	unsigned i;
	unsigned ns = ((unsigned)lookup(n)->capacity)*2;
	udb_ptr a;
	assert(want <= 256); /* cannot be more, range of uint8 */
	printf("udb_radnode_array_grow now=%d want=%d\n",
		(int)lookup(n)->capacity, (int)want);
	if(want > ns)
		ns = want;
	if(ns > 256) ns = 256;
	/* if this fails, the tree is still usable */
	if(!udb_ptr_alloc_space(&a, udb, udb_chunk_type_radarray,
		size_of_lookup_needed(ns, lookup(n)->str_cap)))
		return 0;
	assert(lookup(n)->len <= lookup(n)->capacity);
	assert(lookup(n)->capacity < ns);
	memcpy(RADARRAY(&a), lookup(n), sizeof(struct udb_radarray_d));
	for(i=0; i<lookup(n)->len; i++) {
		udb_rel_ptr_init(&RADARRAY(&a)->array[i].node);
		udb_rptr_set_rptr(&RADARRAY(&a)->array[i].node, udb,
			&lookup(n)->array[i].node);
		RADARRAY(&a)->array[i].len = lookup_len(n, i);
	}
	memset(&RADARRAY(&a)->array[lookup(n)->capacity], 0,
		ns*sizeof(struct udb_radsel_d));
	memmove(&RADARRAY(&a)->array[ns], lookup_string(n, 0),
		lookup(n)->len * lookup(n)->str_cap);
	udb_radarray_zero_ptrs(udb, n);
	udb_rptr_zero(&RADNODE(n)->lookup, udb);
	udb_rel_ptr_free_space(&RADNODE(n)->lookup, udb, size_of_lookup(n));
	udb_rptr_set_ptr(&RADNODE(n)->lookup, udb, &a);
	lookup(n)->capacity = ns;
	udb_ptr_unlink(&a, udb);
	return 1;
}

/** make empty array in radnode */
static int udb_radnode_array_create(udb_base* udb, udb_ptr* n)
{
	/* is there an array? */
	printf("udb_radnode_array_create start\n");
	if(RADNODE(n)->lookup.data == 0) {
		/* create array */
		udb_ptr a;
		uint16_t cap = 0;
		udb_radstrlen_t len = 0;
		if(!udb_ptr_alloc_space(&a, udb, udb_chunk_type_radarray,
			size_of_lookup_needed(cap, len)))
			return 0;
		memset(UDB_PTR(&a), 0, size_of_lookup_needed(cap, len));
		udb_rptr_set_ptr(&RADNODE(n)->lookup, udb, &a);
		RADARRAY(&a)->len = cap;
		RADARRAY(&a)->capacity = cap;
		RADARRAY(&a)->str_cap = len;
		RADNODE(n)->offset = 0;
		udb_ptr_unlink(&a, udb);
	}
	printf("udb_radnode_array_create end\n");
	return 1;
}

/** make space in radnode for another byte, or longer strings */
static int udb_radnode_array_space(udb_base* udb, udb_ptr* n, uint8_t byte,
	udb_radstrlen_t len)
{
	/* is there an array? */
	printf("udb_radnode_array_space start, byte=%d strlen=%d\n",
		(int)byte, (int)len);
	if(RADNODE(n)->lookup.data == 0 || lookup(n)->capacity == 0) {
		/* create array */
		udb_ptr a;
		uint16_t cap = 1;
		if(!udb_ptr_alloc_space(&a, udb, udb_chunk_type_radarray,
			size_of_lookup_needed(cap, len)))
			return 0;
		memset(UDB_PTR(&a), 0, size_of_lookup_needed(cap, len));
		udb_rptr_set_ptr(&RADNODE(n)->lookup, udb, &a);
		RADARRAY(&a)->len = cap;
		RADARRAY(&a)->capacity = cap;
		RADARRAY(&a)->str_cap = len;
		RADNODE(n)->offset = byte;
		udb_ptr_unlink(&a, udb);
		printf("udb_radnode_array_space end new\n");
		return 1;
	}

	/* make space for this stringsize */
	if(lookup(n)->str_cap < len) {
		printf("udb_radnode_array_space do stringsize\n");
		/* must resize for stringsize */
		if(!udb_radnode_str_grow(udb, n, len))
			return 0;
	}

	printf("udb_radnode_array_space do cases\n");
	/* other cases */
	/* is the array unused? */
	if(lookup(n)->len == 0 && lookup(n)->capacity != 0) {
		lookup(n)->len = 1;
		RADNODE(n)->offset = byte;
		memset(&lookup(n)->array[0], 0, sizeof(struct udb_radsel_d));
	/* is it below the offset? */
	} else if(byte < RADNODE(n)->offset) {
		/* is capacity enough? */
		int i;
		unsigned need = RADNODE(n)->offset-byte;
		if(lookup(n)->len+need > lookup(n)->capacity) {
			/* grow array */
			if(!udb_radnode_array_grow(udb, n, lookup(n)->len+need))
				return 0;
		}
		/* reshuffle items to end */
		for(i = lookup(n)->len-1; i >= 0; i--) {
			udb_rptr_set_rptr(&lookup(n)->array[need+i].node,
				udb, &lookup(n)->array[i].node);
			lookup(n)->array[need+i].len = lookup_len(n, i);
			/* fixup pidx */
			if(lookup(n)->array[i+need].node.data)
				lookup_node(n, i+need)->pidx = i+need;
		}
		memmove(lookup_string(n, need), lookup_string(n, 0),
			lookup(n)->len*lookup(n)->str_cap);
		/* zero the first */
		for(i = 0; i < (int)need; i++) {
			udb_rptr_zero(&lookup(n)->array[i].node, udb);
			lookup(n)->array[i].len = 0;
		}
		lookup(n)->len += need;
		RADNODE(n)->offset = byte;
	/* is it above the max? */
	} else if(byte - RADNODE(n)->offset >= lookup(n)->len) {
		/* is capacity enough? */
		unsigned need = (byte-RADNODE(n)->offset) - lookup(n)->len + 1;
		/* grow array */
		if(lookup(n)->len + need > lookup(n)->capacity) {
			if(!udb_radnode_array_grow(udb, n, lookup(n)->len+need))
				return 0;
		}
		/* added entries already zeroed */
		/* grow length */
		lookup(n)->len += need;
	}
	return 1;
}

/** make space for string size */
static int udb_radnode_str_space(udb_base* udb, udb_ptr* n, udb_radstrlen_t len)
{
	if(RADNODE(n)->lookup.data == 0) {
		return udb_radnode_array_space(udb, n, 0, len);
	}
	if(lookup(n)->str_cap < len) {
		/* must resize for stringsize */
		if(!udb_radnode_str_grow(udb, n, len))
			return 0;
	}
	return 1;
}

/** copy remainder from prefixes for a split:
 * plen: len prefix, l: longer bstring, llen: length of l. */
static void udb_radsel_prefix_remainder(udb_radstrlen_t plen, 
	uint8_t* l, udb_radstrlen_t llen,
	uint8_t* s, udb_radstrlen_t* slen)
{
	*slen = llen - plen;
	/* assert(*slen <= lookup(n)->str_cap); */
	memmove(s, l+plen, llen-plen);
}

/** create a prefix in the array strs */
static void udb_radsel_str_create(uint8_t* s, udb_radstrlen_t* slen,
	uint8_t* k, udb_radstrlen_t pos, udb_radstrlen_t len)
{
	*slen = len-pos;
	/* assert(*slen <= lookup(n)->str_cap); */
	memmove(s, k+pos, len-pos);
}

static udb_radstrlen_t
udb_bstr_common(uint8_t* x, udb_radstrlen_t xlen,
	uint8_t* y, udb_radstrlen_t ylen)
{
	assert(sizeof(radstrlen_t) == sizeof(udb_radstrlen_t));
	return bstr_common_ext(x, xlen, y, ylen);
}

static int
udb_bstr_is_prefix(uint8_t* p, udb_radstrlen_t plen,
	uint8_t* x, udb_radstrlen_t xlen)
{
	assert(sizeof(radstrlen_t) == sizeof(udb_radstrlen_t));
	return bstr_is_prefix_ext(p, plen, x, xlen);
}

/** grow array space for byte N after a string, (but if string shorter) */
static int
udb_radnode_array_space_strremain(udb_base* udb, udb_ptr* n,
	uint8_t* str, udb_radstrlen_t len, udb_radstrlen_t pos)
{
	printf("space strremain str len %d pos %d\n", (int)len, (int)pos);
	assert(pos < len);
	/* shift by one char because it goes in lookup array */
	return udb_radnode_array_space(udb, n, str[pos], len-(pos+1));
}


/** radsel create a split when two nodes have shared prefix.
 * @param udb: udb
 * @param n: node with the radsel that gets changed, it contains a node.
 * @param idx: the index of the radsel that gets changed.
 * @param k: key byte string
 * @param pos: position where the string enters the radsel (e.g. r.str)
 * @param len: length of k.
 * @param add: additional node for the string k.
 *      removed by called on failure.
 * @return false on alloc failure, no changes made.
 */
static int udb_radsel_split(udb_base* udb, udb_ptr* n, uint8_t idx, uint8_t* k,
	udb_radstrlen_t pos, udb_radstrlen_t len, udb_ptr* add)
{
	uint8_t* addstr = k+pos;
	udb_radstrlen_t addlen = len-pos;
	if(udb_bstr_is_prefix(addstr, addlen, lookup_string(n, idx),
		lookup_len(n, idx))) {
		udb_radstrlen_t split_len = 0;
		printf("radsel split with 'add'prefix\n");
		/* 'add' is a prefix of r.node */
		/* also for empty addstr */
		/* set it up so that the 'add' node has r.node as child */
		/* so, r.node gets moved below the 'add' node, but we do
		 * this so that the r.node stays the same pointer for its
		 * key name */
		assert(addlen != lookup_len(n, idx));
		assert(addlen < lookup_len(n, idx));
		/* make space for new string sizes */
		if(!udb_radnode_str_space(udb, n, addlen))
			return 0;
		if(lookup_len(n, idx) - addlen > 1)
			/* shift one because a char is in the lookup array */
			split_len = lookup_len(n, idx) - (addlen+1);
		if(!udb_radnode_str_space(udb, add, split_len))
			return 0;
		/* alloc succeeded, now link it in */
		udb_rptr_set_rptr(&RADNODE(add)->parent, udb,
			&lookup_node(n, idx)->parent);
		RADNODE(add)->pidx = lookup_node(n, idx)->pidx;
		udb_rptr_set_rptr(&lookup(add)->array[0].node, udb,
			&lookup(n)->array[idx].node);
		if(lookup_len(n, idx) - addlen > 1) {
			udb_radsel_prefix_remainder(addlen+1,
				lookup_string(n, idx), lookup_len(n, idx),
				lookup_string(add, 0),
				&lookup(add)->array[0].len);
		} else {
			lookup(add)->array[0].len = 0;
		}
		udb_rptr_set_ptr(&lookup_node(n, idx)->parent, udb, add);
		lookup_node(n, idx)->pidx = 0;

		udb_rptr_set_ptr(&lookup(n)->array[idx].node, udb, add);
		memmove(lookup_string(n, idx), addstr, addlen);
		lookup(n)->array[idx].len = addlen;
	} else if(udb_bstr_is_prefix(lookup_string(n, idx), lookup_len(n, idx),
		addstr, addlen)) {
		udb_radstrlen_t split_len = 0;
		udb_ptr rnode;
		printf("radsel split with 'r.node'prefix\n");
		/* r.node is a prefix of 'add' */
		/* set it up so that the 'r.node' has 'add' as child */
		/* and basically, r.node is already completely fine,
		 * we only need to create a node as its child */
		assert(addlen != lookup_len(n, idx));
		assert(lookup_len(n, idx) < addlen);
		udb_ptr_new(&rnode, udb, &lookup(n)->array[idx].node);
		/* make space for string length */
		if(addlen-lookup_len(n, idx) > 1) {
			/* shift one because a character goes into array */
			split_len = addlen - (lookup_len(n, idx)+1);
		}
		if(!udb_radnode_array_space(udb, &rnode,
			addstr[lookup_len(n, idx)], split_len)) {
			udb_ptr_unlink(&rnode, udb);
			return 0;
		}
		/* alloc succeeded, now link it in */
		udb_rptr_set_ptr(&RADNODE(add)->parent, udb, &rnode);
		RADNODE(add)->pidx = addstr[lookup_len(n, idx)] -
			RADNODE(&rnode)->offset;
		udb_rptr_set_ptr(&lookup(&rnode)->array[ RADNODE(add)->pidx ]
			.node, udb, add);
		if(addlen-lookup_len(n, idx) > 1) {
			udb_radsel_prefix_remainder(lookup_len(n, idx)+1,
				addstr, addlen,
				lookup_string(&rnode, RADNODE(add)->pidx),
				&lookup(&rnode)->array[ RADNODE(add)->pidx]
				.len);
		} else {
			lookup(&rnode)->array[ RADNODE(add)->pidx].len = 0;
		}
		udb_ptr_unlink(&rnode, udb);
	} else {
		/* okay we need to create a new node that chooses between 
		 * the nodes 'add' and r.node
		 * We do this so that r.node stays the same pointer for its
		 * key name. */
		udb_ptr com, rnode;
		udb_radstrlen_t common_len = udb_bstr_common(
			lookup_string(n, idx), lookup_len(n, idx),
			addstr, addlen);
		assert(common_len < lookup_len(n, idx));
		assert(common_len < addlen);
		printf("radsel split with common, common_len=%d\n",
			(int)common_len);
		printf("n,idx len %d  addlen %d\n",
			(int)lookup_len(n, idx), (int)addlen);
		udb_ptr_new(&rnode, udb, &lookup(n)->array[idx].node);

		/* create the new node for choice */
		if(!udb_ptr_alloc_space(&com, udb, udb_chunk_type_radnode,
			sizeof(struct udb_radnode_d))) {
			udb_ptr_unlink(&rnode, udb);
			return 0; /* out of space */
		}
		memset(UDB_PTR(&com), 0, sizeof(struct udb_radnode_d));
		/* make stringspace for the two substring choices */
		/* this allocates the com->lookup array */
		if(!udb_radnode_array_space_strremain(udb, &com,
			lookup_string(n, idx), lookup_len(n, idx), common_len)
		   || !udb_radnode_array_space_strremain(udb, &com,
			addstr, addlen, common_len)) {
			udb_ptr_unlink(&rnode, udb);
			if(RADNODE(&com)->lookup.data)
				udb_rel_ptr_free_space(&RADNODE(&com)->lookup,
					udb, size_of_lookup(&com));
			udb_ptr_free_space(&com, udb,
				sizeof(struct udb_radnode_d));
			return 0;
		}
		/* create stringspace for the shared prefix */
		if(!udb_radnode_str_space(udb, &rnode, common_len)) {
			udb_ptr_unlink(&rnode, udb);
			udb_rel_ptr_free_space(&RADNODE(&com)->lookup,
				udb, size_of_lookup(&com));
			udb_ptr_free_space(&com, udb,
				sizeof(struct udb_radnode_d));
			return 0;
		}
		/* allocs succeeded, proceed to link it all up */
		udb_rptr_set_rptr(&RADNODE(&com)->parent, udb,
			&RADNODE(&rnode)->parent);
		RADNODE(&com)->pidx = RADNODE(&rnode)->pidx;
		udb_rptr_set_ptr(&RADNODE(&rnode)->parent, udb, &com);
		RADNODE(&rnode)->pidx = lookup_string(n, idx)[common_len] -
			RADNODE(&com)->offset;
		udb_rptr_set_ptr(&RADNODE(add)->parent, udb, &com);
		RADNODE(add)->pidx = addstr[common_len] -
			RADNODE(&com)->offset;
		udb_rptr_set_ptr(&lookup(&com)->array[RADNODE(&rnode)->pidx]
			.node, udb, &rnode);
		if(lookup_len(n, idx)-common_len > 1) {
			udb_radsel_prefix_remainder(common_len+1,
			lookup_string(n, idx), lookup_len(n, idx),
			lookup_string(&com, RADNODE(&rnode)->pidx),
			&lookup(&com)->array[RADNODE(&rnode)->pidx].len);
		} else {
			lookup(&com)->array[RADNODE(&rnode)->pidx].len= 0;
		}
		udb_rptr_set_ptr(&lookup(&com)->array[RADNODE(add)->pidx]
			.node, udb, add);
		if(addlen-common_len > 1) {
			udb_radsel_prefix_remainder(common_len+1,
			addstr, addlen,
			lookup_string(&com, RADNODE(add)->pidx),
			&lookup(&com)->array[RADNODE(add)->pidx].len);
		} else {
			lookup(&com)->array[RADNODE(add)->pidx].len = 0;
		}
		memmove(lookup_string(n, idx), addstr, common_len);
		lookup(n)->array[idx].len = common_len;
		udb_rptr_set_ptr(&lookup(n)->array[idx].node, udb, &com);
		udb_ptr_unlink(&rnode, udb);
		udb_ptr_unlink(&com, udb);
	}
	return 1;
}

uint64_t* result_data = NULL;
udb_void udb_radix_insert(udb_base* udb, udb_ptr* rt, uint8_t* k,
        udb_radstrlen_t len, udb_ptr* elem, udb_ptr* result)
{
	udb_void ret;
	udb_ptr add, n; /* type udb_radnode_d */
	udb_radstrlen_t pos = 0;
	printf("udb_radix_insert len=%d\n", (int)len);
	/* create new element to add */
	if(!udb_ptr_alloc_space(&add, udb, udb_chunk_type_radnode,
		sizeof(struct udb_radnode_d))) {
		return 0; /* alloc failure */
	}
	memset(UDB_PTR(&add), 0, sizeof(struct udb_radnode_d));
	printf("udb_radix_insert start add radarray space\n");
	udb_rptr_set_ptr(&RADNODE(&add)->elem, udb, elem);
	if(!udb_radnode_array_create(udb, &add)) {
		udb_ptr_free_space(&add, udb, sizeof(struct udb_radnode_d));
		return 0; /* alloc failure */
	}
	printf("udb_radix_insert ptr init\n");
	udb_ptr_init(&n, udb);
	result_data = &n.data;

	/* find out where to add it */
	printf("udb_radix_insert find_prefix, n=%llx\n",
		(unsigned long long)n.data);
	if(!udb_radix_find_prefix_node(udb, rt, k, len, &n, &pos)) {
		/* new root */
		assert(RADTREE(rt)->root.data == 0);
		if(len == 0) {
			udb_rptr_set_ptr(&RADTREE(rt)->root, udb, &add);
		} else {
			/* add a root to point to new node */
			udb_ptr_zero(&n, udb);
			if(!udb_ptr_alloc_space(&n, udb,
				udb_chunk_type_radnode,
				sizeof(struct udb_radnode_d))) {
				udb_rel_ptr_free_space(&RADNODE(&add)->lookup,
					udb, size_of_lookup(&add));
				udb_ptr_free_space(&add, udb,
					sizeof(struct udb_radnode_d));
				udb_ptr_unlink(&n, udb);
				return 0; /* alloc failure */
			}
			memset(RADNODE(&n), 0, sizeof(struct udb_radnode_d));
			/* this creates the array lookup structure for n */
			if(!udb_radnode_array_space(udb, &n, k[0], len-1)) {
				udb_rel_ptr_free_space(&RADNODE(&add)->lookup,
					udb, size_of_lookup(&add));
				udb_ptr_free_space(&n, udb,
					sizeof(struct udb_radnode_d));
				udb_ptr_free_space(&add, udb,
					sizeof(struct udb_radnode_d));
				return 0; /* alloc failure */
			}
			udb_rptr_set_ptr(&RADNODE(&add)->parent, udb, &n);
			RADNODE(&add)->pidx = 0;
			udb_rptr_set_ptr(&lookup(&n)->array[0].node, udb, &add);
			if(len > 1) {
				udb_radsel_prefix_remainder(1, k, len,
					lookup_string(&n, 0),
					&lookup(&n)->array[0].len);
			}
			udb_rptr_set_ptr(&RADTREE(rt)->root, udb, &n);
		}
	} else if(pos == len) {
		/* found an exact match */
		if(RADNODE(&n)->elem.data) {
			/* already exists, failure */
			udb_rel_ptr_free_space(&RADNODE(&add)->lookup,
					udb, size_of_lookup(&add));
			udb_ptr_free_space(&add, udb,
				sizeof(struct udb_radnode_d));
			udb_ptr_unlink(&n, udb);
			return 0;
		}
		udb_rptr_set_ptr(&RADNODE(&n)->elem, udb, elem);
		udb_rel_ptr_free_space(&RADNODE(&add)->lookup,
			udb, size_of_lookup(&add));
		udb_ptr_free_space(&add, udb,
			sizeof(struct udb_radnode_d));
		udb_ptr_set_ptr(&add, udb, &n);
	} else {
		/* n is a node which can accomodate */
		uint8_t byte;
		assert(pos < len);
		byte = k[pos];
		printf("insert got accomodate node %llx\n", 
			(unsigned long long)n.data);

		/* see if it falls outside of array */
		if(byte < RADNODE(&n)->offset || byte-RADNODE(&n)->offset >=
			lookup(&n)->len) {
			/* make space in the array for it; adjusts offset */
			if(!udb_radnode_array_space(udb, &n, byte,
				len-(pos+1))) {
				udb_rel_ptr_free_space(&RADNODE(&add)->lookup,
					udb, size_of_lookup(&add));
				udb_ptr_free_space(&add, udb,
					sizeof(struct udb_radnode_d));
				udb_ptr_unlink(&n, udb);
				return 0;
			}
			assert(byte>=RADNODE(&n)->offset && byte-RADNODE(&n)->
				offset<lookup(&n)->len);
			byte -= RADNODE(&n)->offset;
			/* see if more prefix needs to be split off */
			printf("outside of array, split off pos %d len %d\n",
				(int)pos, (int)len);
			if(pos+1 < len) {
				udb_radsel_str_create(lookup_string(&n, byte),
					&lookup(&n)->array[byte].len,
					k, pos+1, len);
			}
			/* insert the new node in the new bucket */
			udb_rptr_set_ptr(&RADNODE(&add)->parent, udb, &n);
			RADNODE(&add)->pidx = byte;
			udb_rptr_set_ptr(&lookup(&n)->array[byte].node, udb,
				&add);
		/* so a bucket exists and byte falls in it */
		} else if(lookup(&n)->array[byte - RADNODE(&n)->offset]
			.node.data == 0) {
			/* use existing bucket */
			printf("existbucket byte %d %c, split off pos %d len %d\n",
				(int)byte, byte, (int)pos, (int)len);
			byte -= RADNODE(&n)->offset;
			if(pos+1 < len) {
				/* make space and split off more prefix */
				if(!udb_radnode_str_space(udb, &n,
					len-(pos+1))) {
					udb_rel_ptr_free_space(
						&RADNODE(&add)->lookup,
						udb, size_of_lookup(&add));
					udb_ptr_free_space(&add, udb,
						sizeof(struct udb_radnode_d));
					udb_ptr_unlink(&n, udb);
					return 0;
				}
				udb_radsel_str_create(lookup_string(&n, byte),
					&lookup(&n)->array[byte].len,
					k, pos+1, len);
			}
			/* insert the new node in the new bucket */
			udb_rptr_set_ptr(&RADNODE(&add)->parent, udb, &n);
			RADNODE(&add)->pidx = byte;
			udb_rptr_set_ptr(&lookup(&n)->array[byte].node, udb,
				&add);
		} else {
			/* use bucket but it has a shared prefix,
			 * split that out and create a new intermediate
			 * node to split out between the two.
			 * One of the two might exactmatch the new 
			 * intermediate node */
			if(!udb_radsel_split(udb, &n, byte-RADNODE(&n)->offset,
				k, pos+1, len, &add)) {
				udb_rel_ptr_free_space(&RADNODE(&add)->lookup,
					udb, size_of_lookup(&add));
				udb_ptr_free_space(&add, udb,
					sizeof(struct udb_radnode_d));
				udb_ptr_unlink(&n, udb);
				return 0;
			}
		}
	}
	RADTREE(rt)->count ++;
	ret = add.data;
	udb_ptr_init(result, udb);
	udb_ptr_set_ptr(result, udb, &add);
	udb_ptr_unlink(&add, udb);
	udb_ptr_unlink(&n, udb);
	return ret;
}

/** delete a radnode */
static void udb_radnode_delete(udb_base* udb, udb_ptr* n)
{
	if(udb_ptr_is_null(n))
		return;
	printf("radnode delete %llx\n", (unsigned long long)n->data);
	udb_radarray_zero_ptrs(udb, n);
	printf("radnode lookupdelete %llx\n", (unsigned long long)n->data);
	udb_rel_ptr_free_space(&RADNODE(n)->lookup, udb,
		size_of_lookup(n));
	printf("radnode freenode %llx\n", (unsigned long long)n->data);
	udb_ptr_free_space(n, udb, sizeof(struct udb_radnode_d));
}

/** Cleanup node with one child, it is removed and joined into parent[x] str */
static int
udb_radnode_cleanup_onechild(udb_base* udb, udb_ptr* n)
{
	udb_ptr par, child;
	uint8_t pidx = RADNODE(n)->pidx;
	radstrlen_t joinlen;
	udb_ptr_new(&par, udb, &RADNODE(n)->parent);
	udb_ptr_new(&child, udb, &lookup(n)->array[0].node);

	/* node had one child, merge them into the parent. */
	/* keep the child node, so its pointers stay valid. */

	/* at parent, append child->str to array str */
	assert(pidx < lookup(&par)->len);
	joinlen = lookup_len(&par, pidx) + lookup_len(n, 0) + 1;
	/* make stringspace for the joined string */
	if(!udb_radnode_str_space(udb, &par, joinlen)) {
		/* cleanup failed due to out of memory */
		/* the tree is inefficient, with node n still existing */
		udb_ptr_unlink(&par, udb);
		udb_ptr_unlink(&child, udb);
		udb_ptr_zero(n, udb);
		return 0;
	}
	/* the string(par, pidx) is already there */
	/* the array lookup is gone, put its character in the lookup string*/
	lookup_string(&par, pidx)[lookup_len(&par, pidx)] =
		RADNODE(&child)->pidx + RADNODE(n)->offset;
	memmove(lookup_string(&par, pidx)+lookup_len(&par, pidx)+1,
		lookup_string(n, 0), lookup_len(n, 0));
	lookup(&par)->array[pidx].len = joinlen;
	/* and set the node to our child. */
	udb_rptr_set_ptr(&lookup(&par)->array[pidx].node, udb, &child);
	udb_rptr_set_ptr(&RADNODE(&child)->parent, udb, &par);
	RADNODE(&child)->pidx = pidx;
	/* we are unlinked, delete our node */
	udb_radnode_delete(udb, n);
	udb_ptr_unlink(&par, udb);
	udb_ptr_unlink(&child, udb);
	udb_ptr_zero(n, udb);
	return 1;
}

/** reduce the size of radarray, does a malloc */
static int
udb_radarray_reduce(udb_base* udb, udb_ptr* n, uint16_t cap,
	udb_radstrlen_t strcap)
{
	udb_ptr a;
	unsigned i;
	assert(lookup(n)->len <= cap);
	assert(cap <= lookup(n)->capacity);
	assert(strcap <= lookup(n)->str_cap);
	if(!udb_ptr_alloc_space(&a, udb, udb_chunk_type_radarray,
		size_of_lookup_needed(cap, strcap)))
		return 0;
	memcpy(RADARRAY(&a), lookup(n), sizeof(struct udb_radarray_d));
	for(i=0; i<lookup(n)->len; i++) {
		udb_rel_ptr_init(&RADARRAY(&a)->array[i].node);
		udb_rptr_set_rptr(&RADARRAY(&a)->array[i].node, udb,
			&lookup(n)->array[i].node);
		RADARRAY(&a)->array[i].len = lookup_len(n, i);
		memmove(((uint8_t*)(&RADARRAY(&a)->array[cap]))+i*strcap,
			lookup_string(n, i), lookup_len(n, i));
	}
	udb_radarray_zero_ptrs(udb, n);
	udb_rel_ptr_free_space(&RADNODE(n)->lookup, udb, size_of_lookup(n));
	udb_rptr_set_ptr(&RADNODE(n)->lookup, udb, &a);
	RADARRAY(&a)->capacity = cap;
	RADARRAY(&a)->str_cap = strcap;
	udb_ptr_unlink(&a, udb);
	return 1;
}

/** find the max stringlength in the array */
static udb_radstrlen_t udb_radarray_max_len(udb_ptr* n)
{
	unsigned i;
	udb_radstrlen_t maxlen = 0;
	for(i=0; i<lookup(n)->len; i++) {
		if(lookup(n)->array[i].node.data &&
			lookup(n)->array[i].len > maxlen)
			maxlen = lookup(n)->array[i].len;
	}
	return maxlen;
}

/** see if radarray can be reduced (by a factor of two) */
static int
udb_radarray_reduce_if_needed(udb_base* udb, udb_ptr* n)
{
	udb_radstrlen_t maxlen = udb_radarray_max_len(n);
	if((lookup(n)->len <= lookup(n)->capacity/2
		|| maxlen <= lookup(n)->str_cap/2) &&
		(lookup(n)->len != lookup(n)->capacity ||
		lookup(n)->str_cap != maxlen))
		return udb_radarray_reduce(udb, n, lookup(n)->len, maxlen);
	return 1;
}

static int
udb_radnode_array_clean_all(udb_base* udb, udb_ptr* n)
{
	printf("udb_radnode_array_clean_all\n");
	RADNODE(n)->offset = 0;
	lookup(n)->len = 0;
	/* reallocate lookup to a smaller capacity structure */
	return udb_radarray_reduce(udb, n, 0, 0);
}

/** remove NULL nodes from front of array */
static int
udb_radnode_array_clean_front(udb_base* udb, udb_ptr* n)
{
	/* move them up and adjust offset */
	unsigned idx, shuf = 0;
	/* remove until a nonNULL entry */
	while(shuf < lookup(n)->len && lookup(n)->array[shuf].node.data == 0)
		shuf++;
	printf("udb_radnode_array_clean_front %d\n", (int)shuf);
	if(shuf == 0)
		return 1;
	if(shuf == lookup(n)->len) {
		/* the array is empty, the tree is inefficient */
		return udb_radnode_array_clean_all(udb, n);
	}
	assert(shuf < lookup(n)->len);
	assert((int)shuf <= 255-(int)RADNODE(n)->offset);
	/* move them */
	for(idx=0; idx<lookup(n)->len; idx++) {
		udb_rptr_set_rptr(&lookup(n)->array[idx].node, udb,
			&lookup(n)->array[shuf+idx].node);
		lookup(n)->array[idx].len = lookup_len(n, shuf+idx);
	}
	RADNODE(n)->offset += shuf;
	lookup(n)->len -= shuf;
	for(idx=0; idx<lookup(n)->len; idx++)
		if(lookup(n)->array[idx].node.data)
			lookup_node(n, idx)->pidx = idx;

	/* see if capacity has to shrink */
	return udb_radarray_reduce_if_needed(udb, n);
}

/** remove NULL nodes from end of array */
static int
udb_radnode_array_clean_end(udb_base* udb, udb_ptr* n)
{
	/* shorten it */
	unsigned shuf = 0;
	/* remove until a nonNULL entry */
	/* remove until a nonNULL entry */
	while(shuf < lookup(n)->len && lookup(n)->array[lookup(n)->len-1-shuf]
		.node.data == 0)
		shuf++;
	printf("udb_radnode_array_clean_end %d\n", (int)shuf);
	if(shuf == 0)
		return 1;
	if(shuf == lookup(n)->len) {
		/* the array is empty, the tree is inefficient */
		return udb_radnode_array_clean_all(udb, n);
	}
	assert(shuf < lookup(n)->len);
	lookup(n)->len -= shuf;
	/* array elements can stay where they are */
	/* see if capacity has to shrink */
	return udb_radarray_reduce_if_needed(udb, n);
}

/** clean up radnode leaf, where we know it has a parent */
static int
udb_radnode_cleanup_leaf(udb_base* udb, udb_ptr* n, udb_ptr* par)
{
	uint8_t pidx;
	/* node was a leaf */

	/* delete leaf node, but store parent+idx */
	pidx = RADNODE(n)->pidx;
	assert(pidx < lookup(par)->len);

	/** set parent ptr to this node to NULL before deleting the node,
	 * because otherwise ptrlinks fail */
	udb_rptr_zero(&lookup(par)->array[pidx].node, udb);

	udb_radnode_delete(udb, n);

	/* set parent+idx entry to NULL str and node.*/
	lookup(par)->array[pidx].len = 0;

	/* see if par offset or len must be adjusted */
	if(lookup(par)->len == 1) {
		/* removed final element from array */
		if(!udb_radnode_array_clean_all(udb, par))
			return 0;
	} else if(pidx == 0) {
		/* removed first element from array */
		if(!udb_radnode_array_clean_front(udb, par))
			return 0;
	} else if(pidx == lookup(par)->len-1) {
		/* removed last element from array */
		if(!udb_radnode_array_clean_end(udb, par))
			return 0;
	}
	return 1;
}

/** 
 * Cleanup a radix node that was made smaller, see if it can 
 * be merged with others.
 * @param udb: the udb
 * @param rt: tree to remove root if needed.
 * @param n: node to cleanup
 * @return false on alloc failure.
 */
static int
udb_radnode_cleanup(udb_base* udb, udb_ptr* rt, udb_ptr* n)
{
	while(!udb_ptr_is_null(n)) {
		printf("radnode cleanup of %llx\n",
			(unsigned long long)n->data);
		if(RADNODE(n)->elem.data) {
			/* cannot delete node with a data element */
			printf("cleanup end at elem\n");
			udb_ptr_zero(n, udb);
			return 1;
		} else if(lookup(n)->len == 1 && RADNODE(n)->parent.data) {
			printf("cleanup onechild into parent\n");
			return udb_radnode_cleanup_onechild(udb, n);
		} else if(lookup(n)->len == 0) {
			udb_ptr par;
			printf("cleanup leaf node\n");
			if(!RADNODE(n)->parent.data) {
				/* root deleted */
				udb_rptr_zero(&RADTREE(rt)->root, udb);
				udb_radnode_delete(udb, n);
				return 1;
			}
			udb_ptr_new(&par, udb, &RADNODE(n)->parent);
			/* remove and delete the leaf node */
			if(!udb_radnode_cleanup_leaf(udb, n, &par)) {
				udb_ptr_unlink(&par, udb);
				return 0;
			}
			/* see if parent can now be cleaned up */
			udb_ptr_set_ptr(n, udb, &par);
			udb_ptr_unlink(&par, udb);
		} else {
			printf("cleanup end\n");
			/* node cannot be cleaned up */
			udb_ptr_zero(n, udb);
			return 1;
		}
	}
	/* ENOTREACH */
	return 1;
}

void udb_radix_delete(udb_base* udb, udb_ptr* rt, udb_ptr* n)
{
	if(udb_ptr_is_null(n))
		return;
	udb_rptr_zero(&RADNODE(n)->elem, udb);
	RADTREE(rt)->count --;
	if(!udb_radnode_cleanup(udb, rt, n)) {
		/* out of memory in cleanup.  the elem ptr is NULL, but
		 * the radix tree could be inefficient. */
	}
}

udb_void udb_radix_search(udb_ptr* rt, uint8_t* k, udb_radstrlen_t len)
{
	/* since we only perform reads, and no udb_mallocs or udb_frees
	 * we know the pointers stay the same */
	struct udb_radnode_d* n;
	udb_radstrlen_t pos = 0;
	uint8_t byte;
	void* base = *rt->base;

	n = (struct udb_radnode_d*)UDB_REL(base, RADTREE(rt)->root.data);
#define NARRAY(n) ((struct udb_radarray_d*)UDB_REL(base, n->lookup.data))
#define NSTR(n, byte) (((uint8_t*)(&NARRAY(n)->array[NARRAY(n)->capacity]))+byte*NARRAY(n)->str_cap)
	while(n != *rt->base) {
		if(pos == len)
			return UDB_SYSTOREL(*rt->base, n);
		byte = k[pos];
		if(byte < n->offset)
			return 0;
		byte -= n->offset;
		if(byte >= NARRAY(n)->len)
			return 0;
		pos++;
		if(NARRAY(n)->array[byte].len != 0) {
			/* must match additional string */
			if(NARRAY(n)->array[byte].len > len)
				return 0; /* no match */
			if(memcmp(&k[pos], NSTR(n, byte),
				NARRAY(n)->array[byte].len) != 0)
				return 0; /* no match */
			pos += NARRAY(n)->array[byte].len;
		}
		n = (struct udb_radnode_d*)UDB_REL(base,
			NARRAY(n)->array[byte].node.data);
	}
	return 0;
}

/** go to last elem-containing node in this subtree (excl self) */
static void
udb_radnode_last_in_subtree(udb_base* udb, udb_ptr* n)
{
	int idx;
	/* try last entry in array first */
	for(idx=((int)lookup(n)->len)-1; idx >= 0; idx--) {
		if(lookup(n)->array[idx].node.data) {
			udb_ptr s;
			udb_ptr_init(&s, udb);
			udb_ptr_set_rptr(&s, udb, &lookup(n)->array[idx].node);
			/* does it have entries in its subtrees? */
			if(lookup(&s)->len > 0) {
				udb_radnode_last_in_subtree(udb, &s);
				if(!udb_ptr_is_null(&s)) {
					udb_ptr_set_ptr(n, udb, &s);
					udb_ptr_unlink(&s, udb);
					return;
				}
			}
			udb_ptr_set_rptr(&s, udb, &lookup(n)->array[idx].node);
			/* no, does it have an entry itself? */
			if(RADNODE(&s)->elem.data) {
				udb_ptr_set_ptr(n, udb, &s);
				udb_ptr_unlink(&s, udb);
				return;
			}
			udb_ptr_unlink(&s, udb);
		}
	}
	udb_ptr_zero(n, udb);
}

/** last in subtree, incl self */
static void
udb_radnode_last_in_subtree_incl_self(udb_base* udb, udb_ptr* n)
{
	udb_ptr self;
	udb_ptr_init(&self, udb);
	udb_ptr_set_ptr(&self, udb, n);
	udb_radnode_last_in_subtree(udb, n);
	if(!udb_ptr_is_null(n)) {
		udb_ptr_unlink(&self, udb);
		return;
	}
	if(RADNODE(&self)->elem.data) {
		udb_ptr_set_ptr(n, udb, &self);
		udb_ptr_unlink(&self, udb);
		return;
	}
	udb_ptr_zero(n, udb);
	udb_ptr_unlink(&self, udb);
}

/** return first elem-containing node in this subtree (excl self) */
static void
udb_radnode_first_in_subtree(udb_base* udb, udb_ptr* n)
{
	unsigned idx;
	/* try every subnode */
	for(idx=0; idx<lookup(n)->len; idx++) {
		if(lookup(n)->array[idx].node.data) {
			udb_ptr s;
			udb_ptr_init(&s, udb);
			udb_ptr_set_rptr(&s, udb, &lookup(n)->array[idx].node);
			/* does it have elem itself? */
			if(RADNODE(&s)->elem.data) {
				udb_ptr_set_ptr(n, udb, &s);
				udb_ptr_unlink(&s, udb);
				return;
			}
			/* try its subtrees */
			udb_radnode_first_in_subtree(udb, &s);
			if(!udb_ptr_is_null(&s)) {
				udb_ptr_set_ptr(n, udb, &s);
				udb_ptr_unlink(&s, udb);
				return;
			}

		}
	}
	udb_ptr_zero(n, udb);
}

/** Find an entry in arrays from idx-1 to 0 */
static void
udb_radnode_find_prev_from_idx(udb_base* udb, udb_ptr* n, unsigned from)
{
	unsigned idx = from;
	while(idx > 0) {
		idx --;
		if(lookup(n)->array[idx].node.data) {
			udb_ptr_set_rptr(n, udb, &lookup(n)->array[idx].node);
			udb_radnode_last_in_subtree_incl_self(udb, n);
			if(!udb_ptr_is_null(n))
				return;
		}
	}
	udb_ptr_zero(n, udb);
}

/** return self or a previous element */
static int udb_ret_self_or_prev(udb_base* udb, udb_ptr* n, udb_ptr* result)
{
	if(RADNODE(n)->elem.data) {
		udb_ptr_set_ptr(result, udb, n);
	} else {
		udb_ptr_set_ptr(result, udb, n);
		udb_radix_prev(udb, result);
	}
	udb_ptr_unlink(n, udb);
	return 0;
}


int udb_radix_find_less_equal(udb_base* udb, udb_ptr* rt, uint8_t* k,
        udb_radstrlen_t len, udb_ptr* result)
{
	udb_ptr n;
	udb_radstrlen_t pos = 0;
	uint8_t byte;
	int r;
	/* set result to NULL */
	udb_ptr_init(result, udb);
	if(RADTREE(rt)->count == 0) {
		/* empty tree */
		return 0;
	}
	udb_ptr_new(&n, udb, &RADTREE(rt)->root);
	while(pos < len) {
		byte = k[pos];
		if(byte < RADNODE(&n)->offset) {
			/* so the previous is the element itself */
			/* or something before this element */
			return udb_ret_self_or_prev(udb, &n, result);
		}
		byte -= RADNODE(&n)->offset;
		if(byte >= lookup(&n)->len) {
			/* so, the previous is the last of array, or itself */
			/* or something before this element */
			udb_ptr_set_ptr(result, udb, &n);
			udb_radnode_last_in_subtree_incl_self(udb, result);
			if(udb_ptr_is_null(result)) {
				udb_ptr_set_ptr(result, udb, &n);
				udb_radix_prev(udb, result);
			}
			goto done_fail;
		}
		pos++;
		if(!lookup(&n)->array[byte].node.data) {
			/* no match */
			/* Find an entry in arrays from byte-1 to 0 */
			udb_ptr_set_ptr(result, udb, &n);
			udb_radnode_find_prev_from_idx(udb, result, byte);
			if(!udb_ptr_is_null(result))
				goto done_fail;
			/* this entry or something before it */
			udb_ptr_zero(result, udb);
			return udb_ret_self_or_prev(udb, &n, result);
		}
		if(lookup_len(&n, byte) != 0) {
			/* must match additional string */
			if(pos+lookup_len(&n, byte) > len) {
				/* the additional string is longer than key*/
				if( (r=memcmp(&k[pos], lookup_string(&n, byte),
					len-pos)) <= 0) {
					/* and the key is before this node */
					udb_ptr_set_rptr(result, udb,
						&lookup(&n)->array[byte].node);
					udb_radix_prev(udb, result);
				} else {
					/* the key is after the additional
					 * string, thus everything in that
					 * subtree is smaller. */
					udb_ptr_set_rptr(result, udb,
						&lookup(&n)->array[byte].node);
					udb_radnode_last_in_subtree_incl_self(udb, result);
					/* if somehow that is NULL,
					 * then we have an inefficient tree:
					 * byte+1 is larger than us, so find
					 * something in byte-1 and before */
					if(udb_ptr_is_null(result)) {
						udb_ptr_set_rptr(result, udb,
						&lookup(&n)->array[byte].node);
						udb_radix_prev(udb, result);
					}
				}
				goto done_fail; /* no match */
			}
			if( (r=memcmp(&k[pos], lookup_string(&n, byte),
				lookup_len(&n, byte))) < 0) {
				udb_ptr_set_rptr(result, udb,
					&lookup(&n)->array[byte].node);
				udb_radix_prev(udb, result);
				goto done_fail; /* no match */
			} else if(r > 0) {
				/* the key is larger than the additional
				 * string, thus everything in that subtree
				 * is smaller */
				udb_ptr_set_rptr(result, udb,
					&lookup(&n)->array[byte].node);
				udb_radnode_last_in_subtree_incl_self(udb, result);
				/* if we have an inefficient tree */
				if(udb_ptr_is_null(result)) {
					udb_ptr_set_rptr(result, udb,
						&lookup(&n)->array[byte].node);
					udb_radix_prev(udb, result);
				}
				goto done_fail; /* no match */
			}
			pos += lookup_len(&n, byte);
		}
		udb_ptr_set_rptr(&n, udb, &lookup(&n)->array[byte].node);
	}
	if(RADNODE(&n)->elem.data) {
		/* exact match */
		udb_ptr_set_ptr(result, udb, &n);
		udb_ptr_unlink(&n, udb);
		return 1;
	}
	/* there is a node which is an exact match, but it has no element */
	udb_ptr_set_ptr(result, udb, &n);
	udb_radix_prev(udb, result);
done_fail:
	udb_ptr_unlink(&n, udb);
	return 0;
}

void udb_radix_first(udb_base* udb, udb_ptr* rt, udb_ptr* p)
{
	udb_ptr_init(p, udb);
	if(!rt || udb_ptr_is_null(rt) || RADTREE(rt)->count == 0)
		return;
	udb_ptr_set_rptr(p, udb, &RADTREE(rt)->root);
	if(RADNODE(p)->elem.data)
		return;
	udb_radix_next(udb, p);
}

void udb_radix_last(udb_base* udb, udb_ptr* rt, udb_ptr* p)
{
	udb_ptr_init(p, udb);
	if(!rt || udb_ptr_is_null(rt) || RADTREE(rt)->count == 0)
		return;
	udb_ptr_set_rptr(p, udb, &RADTREE(rt)->root);
	udb_radnode_last_in_subtree_incl_self(udb, p);
}

void udb_radix_next(udb_base* udb, udb_ptr* n)
{
	udb_ptr s;
	udb_ptr_init(&s, udb);
	if(lookup(n)->len) {
		/* go down */
		udb_ptr_set_ptr(&s, udb, n);
		udb_radnode_first_in_subtree(udb, &s);
		if(!udb_ptr_is_null(&s)) {
			udb_ptr_set_ptr(n, udb, &s);
			udb_ptr_unlink(&s, udb);
			return;
		}
	}
	/* go up - the parent->elem is not useful, because it is before us */
	while(RADNODE(n)->parent.data) {
		unsigned idx = RADNODE(n)->pidx;
		udb_ptr_set_rptr(n, udb, &RADNODE(n)->parent);
		idx++;
		for(; idx < lookup(n)->len; idx++) {
			/* go down the next branch */
			if(lookup(n)->array[idx].node.data) {
				udb_ptr_set_rptr(&s, udb,
					&lookup(n)->array[idx].node);
				/* node itself */
				if(RADNODE(&s)->elem.data) {
					udb_ptr_set_ptr(n, udb, &s);
					udb_ptr_unlink(&s, udb);
					return;
				}
				/* or subtree */
				udb_radnode_first_in_subtree(udb, &s);
				if(!udb_ptr_is_null(&s)) {
					udb_ptr_set_ptr(n, udb, &s);
					udb_ptr_unlink(&s, udb);
					return;
				}
			}
		}
	}
	udb_ptr_unlink(&s, udb);
	udb_ptr_zero(n, udb);
}

void udb_radix_prev(udb_base* udb, udb_ptr* n)
{
	/* must go up, since all array nodes are after this node */
	while(RADNODE(n)->parent.data) {
		uint8_t idx = RADNODE(n)->pidx;
		udb_ptr s;
		udb_ptr_set_rptr(n, udb, &RADNODE(n)->parent);
		assert(lookup(n)->len > 0); /* since we are a child */
		/* see if there are elements in previous branches there */
		udb_ptr_init(&s, udb);
		udb_ptr_set_ptr(&s, udb, n);
		udb_radnode_find_prev_from_idx(udb, &s, idx);
		if(!udb_ptr_is_null(&s)) {
			udb_ptr_set_ptr(n, udb, &s);
			udb_ptr_unlink(&s, udb);
			return;
		}
		udb_ptr_unlink(&s, udb);
		/* the current node is before the array */
		if(RADNODE(n)->elem.data)
			return;
	}
	udb_ptr_zero(n, udb);
}
