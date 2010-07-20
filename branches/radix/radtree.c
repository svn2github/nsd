/*
 * radtree -- generic radix tree for binary strings.
 *
 * Copyright (c) 2010, NLnet Labs.  See LICENSE for license.
 */
#ifndef RADIX_TEST
#include "config.h"
#endif
#ifdef USE_RADIX_TREE
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "radtree.h"

#include <stdio.h>
#include <ctype.h>

/*
 * define RADIX_TEST to make a unit test executable
 */

struct radtree* radix_tree_create(void)
{
	struct radtree* rt = (struct radtree*)malloc(sizeof(*rt));
	if(!rt) return NULL;
	radix_tree_init(rt);
	return rt;
}

void radix_tree_init(struct radtree* rt)
{
	rt->root = NULL;
	rt->count = 0;
}

/** delete radnodes in postorder recursion */
static void radnode_del_postorder(struct radnode* n)
{
	unsigned i;
	if(!n) return;
	for(i=0; i<n->len; i++) {
		radnode_del_postorder(n->array[i].node);
		free(n->array[i].str);
	}
	free(n->array);
	free(n);
}

void radix_tree_clear(struct radtree* rt)
{
	radnode_del_postorder(rt->root);
	rt->root = NULL;
	rt->count = 0;
}

void radix_tree_delete(struct radtree* rt)
{
	if(!rt) return;
	radix_tree_clear(rt);
	free(rt);
}

/** return last elem-containing node in this subtree (excl self) */
static struct radnode*
radnode_last_in_subtree(struct radnode* n)
{
	int idx;
	/* try last entry in array first */
	for(idx=((int)n->len)-1; idx >= 0; idx--) {
		if(n->array[idx].node) {
			/* does it have entries in its subtrees? */
			if(n->array[idx].node->len > 0) {
				struct radnode* s = radnode_last_in_subtree(
					n->array[idx].node);
				if(s) return s;
			}
			/* no, does it have an entry itself? */
			if(n->array[idx].node->elem)
				return n->array[idx].node;
		}
	}
	return NULL;
}

/** last in subtree, incl self */
static struct radnode*
radnode_last_in_subtree_incl_self(struct radnode* n)
{
	struct radnode* s = radnode_last_in_subtree(n);
	if(s) return s;
	if(n->elem) return n;
	return NULL;
}

/** return first elem-containing node in this subtree (excl self) */
static struct radnode*
radnode_first_in_subtree(struct radnode* n)
{
	unsigned idx;
	struct radnode* s;
	/* try every subnode */
	for(idx=0; idx<n->len; idx++) {
		if(n->array[idx].node) {
			/* does it have elem itself? */
			if(n->array[idx].node->elem)
				return n->array[idx].node;
			/* try its subtrees */
			if((s=radnode_first_in_subtree(n->array[idx].node))!=0)
				return s;
		}
	}
	return NULL;
}

/** Find an entry in arrays from idx-1 to 0 */
static struct radnode*
radnode_find_prev_from_idx(struct radnode* n, unsigned from)
{
	unsigned idx = from;
	while(idx > 0) {
		idx --;
		if(n->array[idx].node) {
			struct radnode* s = radnode_last_in_subtree_incl_self(
				n->array[idx].node);
			if(s) return s;
		}
	}
	return NULL;
}

/** 
 * Find a prefix of the key, in whole-nodes.
 * Finds the longest prefix that corresponds to a whole radnode entry.
 * There may be a slightly longer prefix in one of the array elements.
 * @param result: the longest prefix, the entry itself if *respos==len,
 * 	otherwise an array entry, residx.
 * @param respos: pos in string where next unmatched byte is, if == len an
 * 	exact match has been found.  If == 0 then a "" match was found.
 * @return false if no prefix found, not even the root "" prefix.
 */
static int radix_find_prefix_node(struct radtree* rt, uint8_t* k,
	radstrlen_t len, struct radnode** result, radstrlen_t* respos)
{
	struct radnode* n = rt->root;
	radstrlen_t pos = 0;
	uint8_t byte;
	*respos = 0;
	*result = n;
	if(!n) return 0;
	while(n) {
		if(pos == len) {
			return 1;
		}
		byte = k[pos];
		if(byte < n->offset) {
			return 1;
		}
		byte -= n->offset;
		if(byte >= n->len) {
			return 1;
		}
		pos++;
		if(n->array[byte].len != 0) {
			/* must match additional string */
			if(pos+n->array[byte].len > len) {
				return 1;
			}
			if(memcmp(&k[pos], n->array[byte].str,
				n->array[byte].len) != 0) {
				return 1;
			}
			pos += n->array[byte].len;
		}
		n = n->array[byte].node;
		if(!n) return 1;
		*respos = pos;
		*result = n;
	}
	return 1;
}

/** grow array to at least the given size, offset unchanged */
static int
radnode_array_grow(struct radnode* n, unsigned want)
{
	unsigned ns = ((unsigned)n->capacity)*2;
	struct radsel* a;
	assert(want <= 256); /* cannot be more, range of uint8 */
	if(want > ns)
		ns = want;
	if(ns > 256) ns = 256;
	/* we do not use realloc, because we want to keep the old array
	 * in case alloc fails, so that the tree is still usable */
	a = (struct radsel*)malloc(ns*sizeof(struct radsel));
	if(!a) return 0;
	assert(n->len <= n->capacity);
	assert(n->capacity < ns);
	memcpy(&a[0], &n->array[0], n->len*sizeof(struct radsel));
	free(n->array);
	n->array = a;
	n->capacity = ns;
	return 1;
}

/** make space in radnode array for another byte */
static int
radnode_array_space(struct radnode* n, uint8_t byte)
{
	/* is there an array? */
	if(!n->array || n->capacity == 0) {
		n->array = (struct radsel*)malloc(sizeof(struct radsel));
		memset(&n->array[0], 0, sizeof(struct radsel));
		n->len = 1;
		n->capacity = 1;
		n->offset = byte;
	/* is the array unused? */
	} else if(n->len == 0 && n->capacity != 0) {
		n->len = 1;
		n->offset = byte;
		memset(&n->array[0], 0, sizeof(struct radsel));
	/* is it below the offset? */
	} else if(byte < n->offset) {
		/* is capacity enough? */
		unsigned idx;
		unsigned need = n->offset-byte;
		if(n->len+need > n->capacity) {
			/* grow array */
			if(!radnode_array_grow(n, n->len+need))
				return 0;
		}
		/* reshuffle items to end */
		memmove(&n->array[need], &n->array[0],
				n->len*sizeof(struct radsel));
		/* fixup pidx */
		for(idx = 0; idx < n->len; idx++) {
			if(n->array[idx+need].node)
				n->array[idx+need].node->pidx = idx+need;
		}
		/* zero the first */
		memset(&n->array[0], 0, need*sizeof(struct radsel));
		n->len = n->len+need;
		n->offset = byte;
	/* is it above the max? */
	} else if(byte-n->offset >= n->len) {
		/* is capacity enough? */
		unsigned need = (byte-n->offset) - n->len + 1;
		/* grow array */
		if(n->len + need > n->capacity) {
			if(!radnode_array_grow(n, n->len+need))
				return 0;
		}
		/* zero added entries */
		memset(&n->array[n->len], 0, need*sizeof(struct radsel));
		/* grow length */
		n->len += need;
	}
	return 1;
}

/** create a prefix in the array strs */
static int
radsel_str_create(struct radsel* r, uint8_t* k, radstrlen_t pos,
	radstrlen_t len)
{
	r->str = (uint8_t*)malloc(sizeof(uint8_t)*(len-pos));
	if(!r->str)
		return 0; /* out of memory */
	memmove(r->str, k+pos, len-pos);
	r->len = len-pos;
	return 1;
}

/** see if one byte string p is a prefix of another x (equality is true) */
static int
bstr_is_prefix(uint8_t* p, radstrlen_t plen, uint8_t* x, radstrlen_t xlen)
{
	/* if plen is zero, it is an (empty) prefix */
	if(plen == 0)
		return 1;
	/* if so, p must be shorter */
	if(plen > xlen)
		return 0;
	return (memcmp(p, x, plen) == 0);
}

/** number of bytes in common for the two strings */
static radstrlen_t
bstr_common(uint8_t* x, radstrlen_t xlen, uint8_t* y, radstrlen_t ylen)
{
	unsigned i, max = ((xlen<ylen)?xlen:ylen);
	for(i=0; i<max; i++) {
		if(x[i] != y[i])
			return i;
	}
	return max;
}

/** alocate remainder from prefixes for a split:
 * plen: len prefix, l: longer bstring, llen: length of l. */
static int
radsel_prefix_remainder(radstrlen_t plen,
	uint8_t* l, radstrlen_t llen,
	uint8_t** s, radstrlen_t* slen)
{
	*slen = llen - plen;
	*s = (uint8_t*)malloc((*slen)*sizeof(uint8_t));
	if(!*s)
		return 0;
	memmove(*s, l+plen, llen-plen);
	return 1;
}

/** radsel create a split when two nodes have shared prefix.
 * @param r: radsel that gets changed, it contains a node.
 * @param k: key byte string
 * @param pos: position where the string enters the radsel (e.g. r.str)
 * @param len: length of k.
 * @param add: additional node for the string k.
 * 	removed by called on failure.
 * @return false on alloc failure, no changes made.
 */
static int
radsel_split(struct radsel* r, uint8_t* k, radstrlen_t pos, radstrlen_t len,
	struct radnode* add)
{
	uint8_t* addstr = k+pos;
	radstrlen_t addlen = len-pos;
	if(bstr_is_prefix(addstr, addlen, r->str, r->len)) {
		uint8_t* split_str=NULL, *dupstr=NULL;
		radstrlen_t split_len=0;
		/* 'add' is a prefix of r.node */
		/* also for empty addstr */
		/* set it up so that the 'add' node has r.node as child */
		/* so, r.node gets moved below the 'add' node, but we do
		 * this so that the r.node stays the same pointer for its
		 * key name */
		assert(addlen != r->len);
		assert(addlen < r->len);
		if(r->len-addlen > 1) {
			/* shift one because a char is in the lookup array */
			if(!radsel_prefix_remainder(addlen+1, r->str, r->len,
				&split_str, &split_len))
				return 0;
		}
		if(addlen != 0) {
			dupstr = (uint8_t*)malloc(addlen*sizeof(uint8_t));
			if(!dupstr) {
				free(split_str);
				return 0;
			}
			memcpy(dupstr, addstr, addlen);
		}
		if(!radnode_array_space(add, r->str[addlen])) {
			free(split_str);
			free(dupstr);
			return 0;
		}
		/* alloc succeeded, now link it in */
		add->parent = r->node->parent;
		add->pidx = r->node->pidx;
		add->array[0].node = r->node;
		add->array[0].str = split_str;
		add->array[0].len = split_len;
		r->node->parent = add;
		r->node->pidx = 0;

		r->node = add;
		free(r->str);
		r->str = dupstr;
		r->len = addlen;
	} else if(bstr_is_prefix(r->str, r->len, addstr, addlen)) {
		uint8_t* split_str = NULL;
		radstrlen_t split_len = 0;
		/* r.node is a prefix of 'add' */
		/* set it up so that the 'r.node' has 'add' as child */
		/* and basically, r.node is already completely fine,
		 * we only need to create a node as its child */
		assert(addlen != r->len);
		assert(r->len < addlen);
		if(addlen-r->len > 1) {
			/* shift one because a character goes into array */
			if(!radsel_prefix_remainder(r->len+1, addstr, addlen,
				&split_str, &split_len))
				return 0;
		}
		if(!radnode_array_space(r->node, addstr[r->len])) {
			free(split_str);
			return 0;
		}
		/* alloc succeeded, now link it in */
		add->parent = r->node;
		add->pidx = addstr[r->len] - r->node->offset;
		r->node->array[add->pidx].node = add;
		r->node->array[add->pidx].str = split_str;
		r->node->array[add->pidx].len = split_len;
	} else {
		/* okay we need to create a new node that chooses between 
		 * the nodes 'add' and r.node
		 * We do this so that r.node stays the same pointer for its
		 * key name. */
		uint8_t* common_str=NULL, *s1_str=NULL, *s2_str=NULL;
		radstrlen_t common_len, s1_len=0, s2_len=0;
		common_len = bstr_common(r->str, r->len, addstr, addlen);
		assert(common_len < r->len);
		assert(common_len < addlen);

		/* create the new node for choice */
		struct radnode* com = (struct radnode*)calloc(1, sizeof(*com));
		if(!com) return 0; /* out of memory */

		/* create the two substrings for subchoices */
		if(r->len-common_len > 1) {
			/* shift by one char because it goes in lookup array */
			if(!radsel_prefix_remainder(common_len+1,
				r->str, r->len, &s1_str, &s1_len)) {
				free(com);
				return 0;
			}
		}
		if(addlen-common_len > 1) {
			if(!radsel_prefix_remainder(common_len+1,
				addstr, addlen, &s2_str, &s2_len)) {
				free(com);
				free(s1_str);
				return 0;
			}
		}

		/* create the shared prefix to go in r */
		if(common_len > 0) {
			common_str = (uint8_t*)malloc(
				common_len*sizeof(uint8_t*));
			if(!common_str) {
				free(com);
				free(s1_str);
				free(s2_str);
				return 0;
			}
			memcpy(common_str, addstr, common_len);
		}

		/* make space in the common node array */
		if(!radnode_array_space(com, r->str[common_len]) ||
			!radnode_array_space(com, addstr[common_len])) {
			free(com->array);
			free(com);
			free(common_str);
			free(s1_str);
			free(s2_str);
			return 0;
		}

		/* allocs succeeded, proceed to link it all up */
		com->parent = r->node->parent;
		com->pidx = r->node->pidx;
		r->node->parent = com;
		r->node->pidx = r->str[common_len]-com->offset;
		add->parent = com;
		add->pidx = addstr[common_len]-com->offset;
		com->array[r->node->pidx].node = r->node;
		com->array[r->node->pidx].str = s1_str;
		com->array[r->node->pidx].len = s1_len;
		com->array[add->pidx].node = add;
		com->array[add->pidx].str = s2_str;
		com->array[add->pidx].len = s2_len;
		free(r->str);
		r->str = common_str;
		r->len = common_len;
		r->node = com;
	}
	return 1;
}

struct radnode* radix_insert(struct radtree* rt, uint8_t* k, radstrlen_t len,
        void* elem)
{
	struct radnode* n;
	radstrlen_t pos = 0;
	/* create new element to add */
	struct radnode* add = (struct radnode*)calloc(1, sizeof(*add));
	if(!add) return NULL; /* out of memory */
	add->elem = elem;

	/* find out where to add it */
	if(!radix_find_prefix_node(rt, k, len, &n, &pos)) {
		/* new root */
		assert(rt->root == NULL);
		if(len == 0) {
			rt->root = add;
		} else {
			/* add a root to point to new node */
			n = (struct radnode*)calloc(1, sizeof(*n));
			if(!n) return NULL;
			if(!radnode_array_space(n, k[0])) {
				free(n->array);
				free(n);
				free(add);
				return NULL;
			}
			add->parent = n;
			add->pidx = 0;
			n->array[0].node = add;
			if(len > 1) {
				if(!radsel_prefix_remainder(1, k, len,
					&n->array[0].str, &n->array[0].len)) {
					free(n->array);
					free(n);
					free(add);
					return NULL;
				}
			}
			rt->root = n;
		}
	} else if(pos == len) {
		/* found an exact match */
		if(n->elem) {
			/* already exists, failure */
			free(add);
			return NULL;
		}
		n->elem = elem;
		free(add);
		add = n;
	} else {
		/* n is a node which can accomodate */
		uint8_t byte;
		assert(pos < len);
		byte = k[pos];

		/* see if it falls outside of array */
		if(byte < n->offset || byte-n->offset >= n->len) {
			/* make space in the array for it; adjusts offset */
			if(!radnode_array_space(n, byte)) {
				free(add);
				return NULL;
			}
			assert(byte>=n->offset && byte-n->offset<n->len);
			byte -= n->offset;
			/* see if more prefix needs to be split off */
			if(pos+1 < len) {
				if(!radsel_str_create(&n->array[byte],
					k, pos+1, len)) {
					free(add);
					return NULL;
				}
			}
			/* insert the new node in the new bucket */
			add->parent = n;
			add->pidx = byte;
			n->array[byte].node = add;
		/* so a bucket exists and byte falls in it */
		} else if(n->array[byte-n->offset].node == NULL) {
			/* use existing bucket */
			byte -= n->offset;
			if(pos+1 < len) {
				/* split off more prefix */
				if(!radsel_str_create(&n->array[byte],
					k, pos+1, len)) {
					free(add);
					return NULL;
				}
			}
			/* insert the new node in the new bucket */
			add->parent = n;
			add->pidx = byte;
			n->array[byte].node = add;
		} else {
			/* use bucket but it has a shared prefix,
			 * split that out and create a new intermediate
			 * node to split out between the two.
			 * One of the two might exactmatch the new 
			 * intermediate node */
			if(!radsel_split(&n->array[byte-n->offset], k, pos+1,
				len, add)) {
				free(add);
				return NULL;
			}
		}
	}

	rt->count ++;
	return add;
}

/** Delete a radnode */
static void radnode_delete(struct radnode* n)
{
	unsigned i;
	if(!n) return;
	for(i=0; i<n->len; i++) {
		/* safe to free NULL str */
		free(n->array[i].str);
	}
	free(n->array);
	free(n);
}

/** Cleanup node with one child, it is removed and joined into parent[x] str */
static int
radnode_cleanup_onechild(struct radnode* n, struct radnode* par)
{
	uint8_t* join;
	radstrlen_t joinlen;
	uint8_t pidx = n->pidx;
	struct radnode* child = n->array[0].node;
	/* node had one child, merge them into the parent. */
	/* keep the child node, so its pointers stay valid. */

	/* at parent, append child->str to array str */
	assert(pidx < par->len);
	joinlen = par->array[pidx].len + n->array[0].len + 1;
	join = (uint8_t*)malloc(joinlen*sizeof(uint8_t));
	if(!join) {
		/* cleanup failed due to out of memory */
		/* the tree is inefficient, with node n still existing */
		return 0;
	}
	/* we know that .str and join are malloced, thus aligned */
	memcpy(join, par->array[pidx].str, par->array[pidx].len);
	/* the array lookup is gone, put its character in the lookup string*/
	join[par->array[pidx].len] = child->pidx + n->offset;
	/* but join+len may not be aligned */
	memmove(join+par->array[pidx].len+1, n->array[0].str, n->array[0].len);
	free(par->array[pidx].str);
	par->array[pidx].str = join;
	par->array[pidx].len = joinlen;
	/* and set the node to our child. */
	par->array[pidx].node = child;
	child->parent = par;
	child->pidx = pidx;
	/* we are unlinked, delete our node */
	radnode_delete(n);
	return 1;
}

/** remove array of nodes */
static void
radnode_array_clean_all(struct radnode* n)
{
	n->offset = 0;
	n->len = 0;
	/* see if capacity can be reduced */
	if(n->capacity > 16) {
		free(n->array);
		n->array = NULL;
		n->capacity = 0;
	}
}

/** remove NULL nodes from front of array */
static void
radnode_array_clean_front(struct radnode* n)
{
	/* move them up and adjust offset */
	unsigned idx, shuf = 0;
	/* remove until a nonNULL entry */
	while(shuf < n->len && n->array[shuf].node == NULL)
		shuf++;
	if(shuf == 0)
		return;
	if(shuf == n->len) {
		/* the array is empty, the tree is inefficient */
		radnode_array_clean_all(n);
		return;
	}
	assert(shuf < n->len);
	assert((int)shuf <= 255-(int)n->offset);
	memmove(&n->array[0], &n->array[shuf],
		(n->len - shuf)*sizeof(struct radsel));
	n->offset += shuf;
	n->len -= shuf;
	for(idx=0; idx<n->len; idx++)
		if(n->array[idx].node)
			n->array[idx].node->pidx = idx;
	/* note that capacity stays the same */
}

/** remove NULL nodes from end of array */
static void
radnode_array_clean_end(struct radnode* n)
{
	/* shorten it */
	unsigned shuf = 0;
	/* remove until a nonNULL entry */
	while(shuf < n->len && n->array[n->len-1-shuf].node == NULL)
		shuf++;
	if(shuf == 0)
		return;
	if(shuf == n->len) {
		/* the array is empty, the tree is inefficient */
		radnode_array_clean_all(n);
		return;
	}
	assert(shuf < n->len);
	n->len -= shuf;
	/* array elements can stay where they are */
	/* note that capacity stays the same */
}

/** clean up radnode leaf, where we know it has a parent */
static void
radnode_cleanup_leaf(struct radnode* n, struct radnode* par)
{
	uint8_t pidx;
	/* node was a leaf */
	/* delete leaf node, but store parent+idx */
	pidx = n->pidx;
	radnode_delete(n);

	/* set parent+idx entry to NULL str and node.*/
	assert(pidx < par->len);
	free(par->array[pidx].str);
	par->array[pidx].str = NULL;
	par->array[pidx].len = 0;
	par->array[pidx].node = NULL;

	/* see if par offset or len must be adjusted */
	if(par->len == 1) {
		/* removed final element from array */
		radnode_array_clean_all(par);
	} else if(pidx == 0) {
		/* removed first element from array */
		radnode_array_clean_front(par);
	} else if(pidx == par->len-1) {
		/* removed last element from array */
		radnode_array_clean_end(par);
	}
}

/** 
 * Cleanup a radix node that was made smaller, see if it can 
 * be merged with others.
 * @param rt: tree to remove root if needed.
 * @param n: node to cleanup
 * @return false on alloc failure.
 */
static int
radnode_cleanup(struct radtree* rt, struct radnode* n)
{
	while(n) {
		if(n->elem) {
			/* cannot delete node with a data element */
			return 1;
		} else if(n->len == 1 && n->parent) {
			return radnode_cleanup_onechild(n, n->parent);
		} else if(n->len == 0) {
			struct radnode* par = n->parent;
			if(!par) {
				/* root deleted */
				radnode_delete(n);
				rt->root = NULL;
				return 1;
			}
			/* remove and delete the leaf node */
			radnode_cleanup_leaf(n, par);
			/* see if parent can now be cleaned up */
			n = par;
		} else {
			/* node cannot be cleaned up */
			return 1;
		}
	}
	/* ENOTREACH */
	return 1;
}

void radix_delete(struct radtree* rt, struct radnode* n)
{
	if(!n) return;
	n->elem = NULL;
	rt->count --;
	if(!radnode_cleanup(rt, n)) {
		/* out of memory in cleanup.  the elem ptr is NULL, but
		 * the radix tree could be inefficient. */
	}
}

struct radnode* radix_search(struct radtree* rt, uint8_t* k, radstrlen_t len)
{
	struct radnode* n = rt->root;
	radstrlen_t pos = 0;
	uint8_t byte;
	while(n) {
		if(pos == len)
			return n->elem?n:NULL;
		byte = k[pos];
		if(byte < n->offset)
			return NULL;
		byte -= n->offset;
		if(byte >= n->len)
			return NULL;
		pos++;
		if(n->array[byte].len != 0) {
			/* must match additional string */
			if(n->array[byte].len > len)
				return NULL; /* no match */
			if(memcmp(&k[pos], n->array[byte].str,
				n->array[byte].len) != 0)
				return NULL; /* no match */
			pos += n->array[byte].len;
		}
		n = n->array[byte].node;
	}
	return NULL;
}

/** return self or a previous element */
static int ret_self_or_prev(struct radnode* n, struct radnode** result)
{
	if(n->elem)
		*result = n;
	else	*result = radix_prev(n);
	return 0;
}

int radix_find_less_equal(struct radtree* rt, uint8_t* k, radstrlen_t len,
        struct radnode** result)
{
	struct radnode* n = rt->root;
	radstrlen_t pos = 0;
	uint8_t byte;
	int r;
	if(!n) {
		/* empty tree */
		*result = NULL;
		return 0;
	}
	while(pos < len) {
		byte = k[pos];
		if(byte < n->offset) {
			/* so the previous is the element itself */
			/* or something before this element */
			return ret_self_or_prev(n, result);
		}
		byte -= n->offset;
		if(byte >= n->len) {
			/* so, the previous is the last of array, or itself */
			/* or something before this element */
			if((*result=radnode_last_in_subtree_incl_self(n))==0)
				*result = radix_prev(n);
			return 0;
		}
		pos++;
		if(!n->array[byte].node) {
			/* no match */
			/* Find an entry in arrays from byte-1 to 0 */
			*result = radnode_find_prev_from_idx(n, byte);
			if(*result)
				return 0;
			/* this entry or something before it */
			return ret_self_or_prev(n, result);
		}
		if(n->array[byte].len != 0) {
			/* must match additional string */
			if(pos+n->array[byte].len > len) {
				/* the additional string is longer than key*/
				if( (r=memcmp(&k[pos], n->array[byte].str,
					len-pos)) <= 0) {
				  /* and the key is before this node */
				  *result = radix_prev(n->array[byte].node);
				} else {
					/* the key is after the additional
					 * string, thus everything in that
					 * subtree is smaller. */
				  	*result=radnode_last_in_subtree_incl_self(n->array[byte].node);
					/* if somehow that is NULL,
					 * then we have an inefficient tree:
					 * byte+1 is larger than us, so find
					 * something in byte-1 and before */
					if(!*result)
						*result = radix_prev(n->array[byte].node);
				}
				return 0; /* no match */
			}
			if( (r=memcmp(&k[pos], n->array[byte].str,
				n->array[byte].len)) < 0) {
				*result = radix_prev(n->array[byte].node);
				return 0; /* no match */
			} else if(r > 0) {
				/* the key is larger than the additional
				 * string, thus everything in that subtree
				 * is smaller */
				*result=radnode_last_in_subtree_incl_self(n->array[byte].node);
				/* we have an inefficient tree */
				if(!*result) *result = radix_prev(n->array[byte].node);
				return 0; /* no match */
			}
			pos += n->array[byte].len;
		}
		n = n->array[byte].node;
	}
	if(n->elem) {
		/* exact match */
		*result = n;
		return 1;
	}
	/* there is a node which is an exact match, but it has no element */
	*result = radix_prev(n);
	return 0;
}


struct radnode* radix_first(struct radtree* rt)
{
	struct radnode* n;
	if(!rt || !rt->root) return NULL;
	n = rt->root;
	if(n->elem) return n;
	return radix_next(n);
}

struct radnode* radix_last(struct radtree* rt)
{
	if(!rt || !rt->root) return NULL;
	return radnode_last_in_subtree_incl_self(rt->root);
}

struct radnode* radix_next(struct radnode* n)
{
	if(n->len) {
		/* go down */
		struct radnode* s = radnode_first_in_subtree(n);
		if(s) return s;
	}
	/* go up - the parent->elem is not useful, because it is before us */
	while(n->parent) {
		unsigned idx = n->pidx;
		n = n->parent;
		idx++;
		for(; idx < n->len; idx++) {
			/* go down the next branch */
			if(n->array[idx].node) {
				struct radnode* s;
				/* node itself */
				if(n->array[idx].node->elem)
					return n->array[idx].node;
				/* or subtree */
				s = radnode_first_in_subtree(
					n->array[idx].node);
				if(s) return s;
			}
		}
	}
	return NULL;
}

struct radnode* radix_prev(struct radnode* n)
{
	/* must go up, since all array nodes are after this node */
	while(n->parent) {
		uint8_t idx = n->pidx;
		struct radnode* s;
		n = n->parent;
		assert(n->len > 0); /* since we are a child */
		/* see if there are elements in previous branches there */
		s = radnode_find_prev_from_idx(n, idx);
		if(s) return s;
		/* the current node is before the array */
		if(n->elem)
			return n;
	}
	return NULL;
}

/** convert one character from domain-name to radname */
static uint8_t char_d2r(uint8_t c)
{
	if(c < 'A') return c+1; /* make space for 00 */
	else if(c <= 'Z') return c-'A'+'a'; /* lowercase */
	else return c;
}

/** convert one character from radname to domain-name (still lowercased) */
static uint8_t char_r2d(uint8_t c)
{
	assert(c != 0); /* end of label */
	if(c <= 'A') return c-1;
	else return c;
}

/** copy and convert a range of characters */
static void cpy_d2r(uint8_t* to, uint8_t* from, int len)
{
	int i;
	for(i=0; i<len; i++)
		to[i] = char_d2r(from[i]);
}

/** copy and convert a range of characters */
static void cpy_r2d(uint8_t* to, uint8_t* from, uint8_t len)
{
	uint8_t i;
	for(i=0; i<len; i++)
		to[i] = char_r2d(from[i]);
}

/* radname code: domain to radix-bstring */
void radname_d2r(uint8_t* k, radstrlen_t* len, uint8_t* dname, size_t dlen)
{
	/* the domain name is converted as follows,
	 * to preserve the normal (NSEC) ordering of domain names.
	 * lowercased, and 'end-of-label' is a '00' byte,
	 * bytes 00-'A' are +1 moved to make space for 00 byte.
	 * final root label is not appended (string ends).
	 * because the only allowed empty label is the final root label,
	 * we can also remove the last 00 label-end.
	 * The total result length is one-or-two less than the dname.
	 * 
	 * examples (numbers are bytes, letters are ascii):
	 * - root: dname: 0, radname: ''
	 * - nl.:  dname: 3nl0, radname: 'nl'
	 * - labs.nl: dname 4labs3nl0, radname: 'nl0labs'
	 * - x.labs.nl: dname 1x4labs3nl0, radname: 'nl0labs0x'
	 */

	/* conversion by putting the label starts on a stack */
	uint8_t* labstart[130];
	unsigned int lab = 0, kpos, dpos = 0;
	/* sufficient space */
	assert(k && dname);
	assert(dlen <= 256); /* and therefore not more than 128 labels */
	assert(*len >= dlen);
	assert(dlen > 0); /* even root label has dlen=1 */

	/* root */
	if(dlen == 1) {
		assert(dname[0] == 0);
		*len = 0;
		return;
	}
	
	/* walk through domain name and remember label positions */
	do {
		/* compression pointers not allowed */
		if((dname[dpos] & 0xc0)) {
			*len = 0;
			return; /* format error */
		}
		labstart[lab++] = &dname[dpos];
		if(dpos + dname[dpos] + 1 >= dlen) {
			*len = 0;
			return; /* format error */
		}
		/* skip the label contents */
		dpos += dname[dpos];
		dpos ++;
	} while(dname[dpos] != 0);
	/* exit condition makes root label not in labelstart stack */
	/* because the root was handled before, we know there is some text */
	assert(lab > 0);
	lab-=1;
	kpos = *labstart[lab];
	cpy_d2r(k, labstart[lab]+1, kpos);
	/* if there are more labels, copy them over */
	while(lab) {
		/* put 'end-of-label' 00 to end previous label */
		k[kpos++]=0;
		/* append the label */
		lab--;
		cpy_d2r(k+kpos, labstart[lab]+1, *labstart[lab]);
		kpos += *labstart[lab];
	}
	/* done */
	assert(kpos == dlen-2); /* no rootlabel, one less label-marker */
	*len = kpos;
}

/* radname code: radix-bstring to domain */
void radname_r2d(uint8_t* k, radstrlen_t len, uint8_t* dname, size_t* dlen)
{
	/* find labels and push on stack */
	uint8_t* labstart[130];
	uint8_t lablen[130];
	unsigned int lab = 0, dpos, kpos = 0;
	/* sufficient space */
	assert(k && dname);
	assert((size_t)*dlen >= (size_t)len+2);
	assert(len <= 256);
	/* root label */
	if(len == 0) {
		assert(*dlen > 0);
		dname[0]=0;
		*dlen=1;
		return;
	}
	/* find labels */
	while(kpos < len) {
		lablen[lab]=0;
			labstart[lab]=&k[kpos];
		/* skip to next label */
		while(kpos < len && k[kpos] != 0) {
			lablen[lab]++;
			kpos++;
		}
		lab++;
		/* skip 00 byte for label-end */
		if(kpos < len) {
			assert(k[kpos] == 0);
			kpos++;
		}
	}
	/* copy the labels over to the domain name */
	dpos = 0;
	while(lab) {
		lab--;
		/* label length */
		dname[dpos++] = lablen[lab];
		/* label content */
		cpy_r2d(dname+dpos, labstart[lab], lablen[lab]);
		dpos += lablen[lab];
	}
	/* append root label */
	dname[dpos++] = 0;
	/* assert the domain name is wellformed */
	assert((int)dpos == (int)len+2);
	assert(dname[dpos-1] == 0); /* ends with root label */
	*dlen = dpos;
}

/** insert by domain name */
struct radnode*
radname_insert(struct radtree* rt, uint8_t* d, size_t max, void* elem)
{
	/* convert and insert */
	uint8_t radname[300];
	radstrlen_t len = (radstrlen_t)sizeof(radname);
	if(max > sizeof(radname))
		return NULL; /* too long */
	radname_d2r(radname, &len, d, max);
	return radix_insert(rt, radname, len, elem);
}

/** delete by domain name */
void
radname_delete(struct radtree* rt, uint8_t* d, size_t max)
{
	/* search and remove */
	struct radnode* n = radname_search(rt, d, max);
	if(n) radix_delete(rt, n);
}

/* search for exact match of domain name, converted to radname in tree */
struct radnode* radname_search(struct radtree* rt, uint8_t* d, size_t max)
{
	/* stack of labels in the domain name */
	uint8_t* labstart[130];
	unsigned int lab, dpos, lpos;
	struct radnode* n = rt->root;
	uint8_t byte;
	radstrlen_t i;
	uint8_t b;

	/* search for root? it is '' */
	if(max < 1)
		return NULL;
	if(d[0] == 0) {
		if(!n) return NULL;
		return n->elem?n:NULL;
	}

	/* find labels stack in domain name */
	lab = 0;
	dpos = 0;
	/* must have one label, since root is specialcased */
	do {
		if((d[dpos] & 0xc0))
			return NULL; /* compression ptrs not allowed error */
		labstart[lab++] = &d[dpos];
		if(dpos + d[dpos] + 1 >= max)
			return NULL; /* format error: outside of bounds */
		/* skip the label contents */
		dpos += d[dpos];
		dpos ++;
	} while(d[dpos] != 0);
	/* exit condition makes that root label is not in the labstarts */
	/* now: dpos+1 is length of domain name. lab is number of labels-1 */

	/* start processing at the last label */
	lab-=1;
	lpos = 0;
	while(n) {
		/* fetch next byte this label */
		if(lpos < *labstart[lab])
			/* lpos+1 to skip labelstart, lpos++ to move forward */
			byte = char_d2r(labstart[lab][++lpos]);
		else {
			if(lab == 0) /* last label - we're done */
				return n->elem?n:NULL;
			/* next label, search for byte 00 */
			lpos = 0;
			lab--;
			byte = 0;
		}
		/* find that byte in the array */
		if(byte < n->offset)
			return NULL;
		byte -= n->offset;
		if(byte >= n->len)
			return NULL;
		if(n->array[byte].len != 0) {
			/* must match additional string */
			/* see how many bytes we need and start matching them*/
			for(i=0; i<n->array[byte].len; i++) {
				/* next byte to match */
				if(lpos < *labstart[lab])
					b = char_d2r(labstart[lab][++lpos]);
				else {
					/* if last label, no match since
					 * we are in the additional string */
					if(lab == 0)
						return NULL; 
					/* next label, search for byte 00 */
					lpos = 0;
					lab--;
					b = 0;
				}
				if(n->array[byte].str[i] != b)
					return NULL; /* not matched */
			}
		}
		n = n->array[byte].node;
	}
	return NULL;
}

/* find domain name or smaller or equal domain name in radix tree */
int radname_find_less_equal(struct radtree* rt, uint8_t* d, size_t max,
        struct radnode** result)
{
	/* stack of labels in the domain name */
	uint8_t* labstart[130];
	unsigned int lab, dpos, lpos;
	struct radnode* n = rt->root;
	uint8_t byte;
	radstrlen_t i;
	uint8_t b;

	/* empty tree */
	if(!n) {
		*result = NULL;
		return 0;
	}

	/* search for root? it is '' */
	if(max < 1) {
		*result = NULL;
		return 0; /* parse error, out of bounds */
	}
	if(d[0] == 0) {
		if(n->elem) {
			*result = n;
			return 1;
		}
		/* no smaller element than the root */
		*result = NULL;
		return 0;
	}

	/* find labels stack in domain name */
	lab = 0;
	dpos = 0;
	/* must have one label, since root is specialcased */
	do {
		if((d[dpos] & 0xc0)) {
			*result = NULL;
			return 0; /* compression ptrs not allowed error */
		}
		labstart[lab++] = &d[dpos];
		if(dpos + d[dpos] + 1 >= max) {
			*result = NULL; /* format error: outside of bounds */
			return 0;
		}
		/* skip the label contents */
		dpos += d[dpos];
		dpos ++;
	} while(d[dpos] != 0);
	/* exit condition makes that root label is not in the labstarts */
	/* now: dpos+1 is length of domain name. lab is number of labels-1 */

	/* start processing at the last label */
	lab-=1;
	lpos = 0;
	while(1) {
		/* fetch next byte this label */
		if(lpos < *labstart[lab])
			/* lpos+1 to skip labelstart, lpos++ to move forward */
			byte = char_d2r(labstart[lab][++lpos]);
		else {
			if(lab == 0) {
				/* last label - we're done */
				/* exact match */
				if(n->elem) {
					*result = n;
					return 1;
				}
				/* there is a node which is an exact match,
				 * but there no element in it */
				*result = radix_prev(n);
				return 0;
			}
			/* next label, search for byte 0 the label separator */
			lpos = 0;
			lab--;
			byte = 0;
		}
		/* find that byte in the array */
		if(byte < n->offset)
			/* so the previous is the element itself */
			/* or something before this element */
			return ret_self_or_prev(n, result);
		byte -= n->offset;
		if(byte >= n->len) {
			/* so, the previous is the last of array, or itself */
			/* or something before this element */
			*result = radnode_last_in_subtree_incl_self(n);
			if(!*result)
				*result = radix_prev(n);
			return 0;
		}
		if(!n->array[byte].node) {
			/* no match */
			/* Find an entry in arrays from byte-1 to 0 */
			*result = radnode_find_prev_from_idx(n, byte);
			if(*result)
				return 0;
			/* this entry or something before it */
			return ret_self_or_prev(n, result);
		}
		if(n->array[byte].len != 0) {
			/* must match additional string */
			/* see how many bytes we need and start matching them*/
			for(i=0; i<n->array[byte].len; i++) {
				/* next byte to match */
				if(lpos < *labstart[lab])
					b = char_d2r(labstart[lab][++lpos]);
				else {
					/* if last label, no match since
					 * we are in the additional string */
					if(lab == 0) {
						/* dname ended, thus before
						 * this array element */
						*result =radix_prev(
							n->array[byte].node);
						return 0; 
					}
					/* next label, search for byte 00 */
					lpos = 0;
					lab--;
					b = 0;
				}
				if(b < n->array[byte].str[i]) {
					*result =radix_prev(
						n->array[byte].node);
					return 0; 
				} else if(b > n->array[byte].str[i]) {
					/* the key is after the additional,
					 * so everything in its subtree is
					 * smaller */
					*result = radnode_last_in_subtree_incl_self(n->array[byte].node);
					/* if that is NULL, we have an
					 * inefficient tree, find in byte-1*/
					if(!*result)
						*result = radix_prev(n->array[byte].node);
					return 0;
				}
			}
		}
		n = n->array[byte].node;
	}
	/* ENOTREACH */
	return 0;
}

#include "dname.h"
/* find NSD dname or smaller or equal domain name in radix tree */
int radix_dname_find_less_equal(struct radtree* rt, const struct dname* d,
        struct radnode** result)
{
	/* stack of labels in the domain name */
	unsigned int lab, lpos;
	struct radnode* n = rt->root;
	uint8_t byte;
	radstrlen_t i;
	uint8_t b;

	/* empty tree */
	if(!n) {
		*result = NULL;
		return 0;
	}

	if(d->label_count == 1) {
		if(n->elem) {
			*result = n;
			return 1;
		}
		/* no smaller element than the root */
		*result = NULL;
		return 0;
	}

	/* must have one label, since root is specialcased */
	/* now: dpos+1 is length of domain name. lab is number of labels-1 */
	/* start processing at the last label */
	/* labels count up to the last label */
	lab = 1;
	lpos = 0;
	while(1) {
		/* fetch next byte this label */
		if(lpos < *dname_label(d, lab))
			/* lpos+1 to skip labelstart, lpos++ to move forward */
			byte = char_d2r(dname_label(d, lab)[++lpos]);
		else {
			if(++lab == d->label_count) {
				/* last label - we're done */
				/* exact match */
				if(n->elem) {
					*result = n;
					return 1;
				}
				/* there is a node which is an exact match,
				 * but there no element in it */
				*result = radix_prev(n);
				return 0;
			}
			/* next label, search for byte 0 the label separator */
			lpos = 0;
			byte = 0;
		}
		/* find that byte in the array */
		if(byte < n->offset)
			/* so the previous is the element itself */
			/* or something before this element */
			return ret_self_or_prev(n, result);
		byte -= n->offset;
		if(byte >= n->len) {
			/* so, the previous is the last of array, or itself */
			/* or something before this element */
			*result = radnode_last_in_subtree_incl_self(n);
			if(!*result)
				*result = radix_prev(n);
			return 0;
		}
		if(!n->array[byte].node) {
			/* no match */
			/* Find an entry in arrays from byte-1 to 0 */
			*result = radnode_find_prev_from_idx(n, byte);
			if(*result)
				return 0;
			/* this entry or something before it */
			return ret_self_or_prev(n, result);
		}
		if(n->array[byte].len != 0) {
			/* must match additional string */
			/* see how many bytes we need and start matching them*/
			for(i=0; i<n->array[byte].len; i++) {
				/* next byte to match */
				if(lpos < *dname_label(d, lab))
					b = char_d2r(dname_label(d, lab)[++lpos]);
				else {
					/* if last label, no match since
					 * we are in the additional string */
					if(++lab == d->label_count) {
						/* dname ended, thus before
						 * this array element */
						*result =radix_prev(
							n->array[byte].node);
						return 0; 
					}
					/* next label, search for byte 00 */
					lpos = 0;
					b = 0;
				}
				if(b < n->array[byte].str[i]) {
					*result =radix_prev(
						n->array[byte].node);
					return 0; 
				} else if(b > n->array[byte].str[i]) {
					/* the key is after the additional,
					 * so everything in its subtree is
					 * smaller */
					*result = radnode_last_in_subtree_incl_self(n->array[byte].node);
					/* if that is NULL, we have an
					 * inefficient tree, find in byte-1*/
					if(!*result)
						*result = radix_prev(n->array[byte].node);
					return 0;
				}
			}
		}
		n = n->array[byte].node;
	}
	/* ENOTREACH */
	return 0;
}


#ifdef RADIX_TEST

/*********** test code ************/
/** test data for radix tree tests */
struct teststr {
	struct radnode* mynode;
	uint8_t* mystr;
	radstrlen_t mylen;
	/* if a domain name, the domain name in original format */
	uint8_t* dname;
	size_t dname_len;
};

/** check invariants and count number of elems */
static size_t test_check_invariants(struct radnode* n)
{
	size_t num = 0;
	if(!n) return 0;
	if(n->elem) num++;
	assert(n->len <= n->capacity);
	assert(n->capacity <= 256);
	assert(((int)n->offset) + ((int)n->len) <= 256);
	if(n->array == NULL) {
		assert(n->capacity == 0);
		assert(n->len == 0);
		assert(n->offset == 0);
	} else {
		unsigned idx;
		assert(n->capacity != 0);
		for(idx=0; idx<n->len; idx++) {
			struct radsel* r = &n->array[idx];
			if(r->node == NULL) {
				assert(r->str == NULL);
				assert(r->len == 0);
			} else {
				if(r->len == 0) {
					assert(r->str == NULL);
				} else {
					assert(r->str != NULL);
				}
				assert(r->node->parent == n);
				assert(r->node->pidx == idx);
				num += test_check_invariants(r->node);
			}
		}
	}
	return num;
}

/** find all elems in the list and check that the name as indicated by the
 * lookup structure matches the one in the element */
static void
test_check_list_keys(struct radnode* n, struct teststr** all, size_t* all_idx,
	size_t all_num, uint8_t* fullkey, radstrlen_t fullkey_len,
	radstrlen_t fullkey_max)
{
	unsigned idx;
	if(!n) return;
	if(n->elem) {
		/* check this elements key */
		struct teststr* t = (struct teststr*)n->elem;
		assert(t->mynode == n);
		assert(t->mylen == fullkey_len);
		assert(memcmp(t->mystr, fullkey, fullkey_len) == 0);
		/* add to all list */
		assert( (*all_idx) < all_num);
		all[ (*all_idx)++ ] = t;
	}
	for(idx=0; idx<n->len; idx++) {
		struct radsel* r = &n->array[idx];
		radstrlen_t newlen = fullkey_len;
		if(!r->node)
			continue;
		/* lengthen fullkey with the character and r->str */
		assert(newlen+1 < fullkey_max);
		fullkey[newlen++] = idx + n->offset;
		if(r->len != 0) {
			assert(newlen+r->len < fullkey_max);
			memmove(fullkey+newlen, r->str, r->len);
			newlen += r->len;
		}
		test_check_list_keys(r->node, all, all_idx, all_num, fullkey,
			newlen, fullkey_max);
	}
}

/** compare byte strings like the tree does */
static int bstr_cmp(uint8_t* x, radstrlen_t lenx, uint8_t* y, radstrlen_t leny)
{
	size_t m = (lenx<leny)?lenx:leny;
	if(m != 0 && memcmp(x, y, m) != 0)
		return memcmp(x, y, m);
	if(lenx < leny)
		return -1;
	else if(lenx > leny)
		return +1;
	return 0;
}

/** compare for qsort */
int test_sort_cmp(const void *a, const void *b)
{
	struct teststr* x = *(struct teststr**)a;
	struct teststr* y = *(struct teststr**)b;
	return bstr_cmp(x->mystr, x->mylen, y->mystr, y->mylen);
}

/** check walk functions */
static void test_check_walk(struct radtree* rt, struct teststr** all,
	size_t num)
{
	struct radnode* n;
	unsigned idx;

	/* check _first */
	n = radix_first(rt);
	if(num == 0) {
		assert(n == NULL);
	} else {
		assert(n == all[0]->mynode);
	}

	/* check _last */
	n = radix_last(rt);
	if(num == 0) {
		assert(n == NULL);
	} else {
		assert(n == all[num-1]->mynode);
	}

	/* check _next */
	for(idx = 0; idx < num; idx++) {
		n = radix_next(all[idx]->mynode);
		if(idx == num-1) {
			assert(n == NULL);
		} else {
			assert(n == all[idx+1]->mynode);
		}
	}

	/* check _prev */
	for(idx = 0; idx < num; idx++) {
		n = radix_prev(all[idx]->mynode);
		if(idx == 0) {
			assert(n == NULL);
		} else {
			assert(n == all[idx-1]->mynode);
		}
	}
}

/** check search function */
static void test_check_search(struct radtree* rt, struct teststr** all,
	size_t num)
{
	struct radnode* n;
	unsigned idx;
	for(idx = 0; idx < num; idx++) {
		n = radix_search(rt, all[idx]->mystr, all[idx]->mylen);
		assert(n == all[idx]->mynode);
	}
}

/** check closest match function for exact matches */
static void test_check_closest_match_exact(struct radtree* rt,
	struct teststr** all, size_t num)
{
	struct radnode* n;
	unsigned idx;
	for(idx = 0; idx < num; idx++) {
		n = NULL;
		if(radix_find_less_equal(rt, all[idx]->mystr,
			all[idx]->mylen, &n)) {
			/* check if exact match is correct */
			assert(n == all[idx]->mynode);
		} else {
			/* should have returned true: exact match */
			assert(0);
		}
	}
}

/** get a random value */
static unsigned
get_ran_val(unsigned max)
{
	unsigned r = random();
	double ret = ((double)r * (double)max) / (1.0 + RAND_MAX);
	return (unsigned)ret;
}

/** generate random string and length */
static void
gen_ran_str_len(uint8_t* buf, radstrlen_t* len, radstrlen_t max)
{
	radstrlen_t i;
	*len = get_ran_val(5);
	assert(*len < max);
	buf[*len] = 0; /* zero terminate for easy debug */
	for(i=0; i< *len; i++) {
		/*buf[i] = get_ran_val(256); */
		buf[i] = 'a' + get_ran_val(26);
	}
}

/** generate random domain name and length */
static void
gen_ran_dname(uint8_t* buf, radstrlen_t* len, radstrlen_t max)
{
	int numlabs, labs;
	radstrlen_t i, lablen, pos;

	/* number nonzero labels */
	labs = get_ran_val(1000);
	if(labs < 10) numlabs = 0;
	else if(labs < 100) numlabs = 1;
	else if(labs < 1000) numlabs = 2;
	else numlabs = 3;

	pos = 0;
	for(labs=0; labs<numlabs; labs++) {
		/* add another nonzero label */
		lablen = get_ran_val(3)+1;
		assert(pos + lablen + 1 < max);
		buf[pos++] = lablen;
		for(i=0; i<lablen; i++) {
			/*buf[i] = get_ran_val(256); */
			buf[pos++] = 'a' + get_ran_val(26);
		}
	}
	buf[pos++] = 0; /* zero terminate for easy debug */
	assert(pos < max);
	*len = pos;
	assert(strlen((char*)buf)+1 == *len);
}

/** check closest match function for inexact matches */
static void test_check_closest_match_inexact(struct radtree* rt)
{
	uint8_t buf[1024];
	radstrlen_t len;
	struct radnode* n;
	struct teststr* t;
	int i = 0, num=1000;
	/* what strings to try out? random */
	/* how to check result? use prev and next (they work checked before)*/
	for(i=0; i<num; i++) {
		/* generate random string */
		gen_ran_str_len(buf, &len, sizeof(buf));
		n = NULL;
		if(radix_find_less_equal(rt, buf, len, &n)) {
			assert(n);
			assert(n->elem);
			/* check exact match */
			t = (struct teststr*)n->elem;
			assert(t->mylen == len);
			assert(memcmp(t->mystr, buf, len) == 0);
		} else {
			/* check inexact match */
			if(n == NULL) {
				/* no elements in rt or before first item */
				if(rt->count != 0) {
					n = radix_first(rt);
					t = (struct teststr*)n->elem;
					assert(bstr_cmp(buf, len,
					  t->mystr, t->mylen) < 0);
				}
			} else {
				struct radnode* nx;
				assert(n->elem);
				/* n is before the item */
				t = (struct teststr*)n->elem;
				assert(bstr_cmp(t->mystr, t->mylen,
					buf, len) < 0);
				/* the next item is NULL or after it */
				nx = radix_next(n);
				if(nx) {
					t = (struct teststr*)nx->elem;
					assert(bstr_cmp(t->mystr, t->mylen,
						buf, len) > 0);
				}
			}
		}
	}
}

/** perform lots of checks on the test tree */
static void test_checks(struct radtree* rt)
{
	struct teststr* all[10240];
	size_t i=0;
	uint8_t fullkey_buf[1024];

	/* tree structure invariants */
	size_t num = test_check_invariants(rt->root);
	assert(num == rt->count);

	/* otherwise does not fit in array */
	assert(num < sizeof(all)/sizeof(struct teststr*));

	/* check that keys appended match test-elem contents, and also
	 * produce a list of all elements */
	test_check_list_keys(rt->root, all, &i, num, fullkey_buf, 0, 
		sizeof(fullkey_buf));
	assert(i == num);

	/* qsort that list */
	qsort(all, num, sizeof(struct teststr*), &test_sort_cmp);

	test_check_walk(rt, all, num);

	/* check searches for every element */
	test_check_search(rt, all, num);

	/* check closest_match_searches for every exact element */
	test_check_closest_match_exact(rt, all, num);
	/* check closest_match_searches for every inexact element */
	test_check_closest_match_inexact(rt);
}

/** check radname_search */
static void test_check_dname_search(struct radtree* rt)
{
	struct radnode* n;
	for(n = radix_first(rt); n ; n = radix_next(n)) {
		struct teststr* s = (struct teststr*)n->elem;
		struct radnode* found;
		assert(n && s);
		found = radname_search(rt, s->dname, s->dname_len);
		assert(found);
		assert(found == n);
	}
}

/** check radname_less_or_equal for exact */
static void test_check_dname_closest_exact(struct radtree* rt)
{
	struct radnode* n;
	for(n = radix_first(rt); n ; n = radix_next(n)) {
		struct teststr* s = (struct teststr*)n->elem;
		struct radnode* found;
		assert(n && s);
		if(radname_find_less_equal(rt, s->dname, s->dname_len, &found)){
			/* exact match is expected */
			assert(found);
			assert(found == n);
		} else {
			assert(0);
		}
	}
}

/** check radname_less_or_equal for inexact */
static void test_check_dname_closest_inexact(struct radtree* rt)
{
	uint8_t dname[1024];
	radstrlen_t dlen;
	uint8_t radname[1024];
	radstrlen_t rlen;
	struct radnode* n;
	struct teststr* t;
	int i = 0, num=1000;
	/* what strings to try out? random */
	/* how to check result? use prev and next (they work checked before)*/
	for(i=0; i<num; i++) {
		/* generate random string */
		gen_ran_dname(dname, &dlen, sizeof(dname));
		rlen = sizeof(radname);
		/* test the radname_lookup function internal conversion of
		 * the dname to radname against the d2r function */
		radname_d2r(radname, &rlen, dname, (size_t)dlen);
		n = NULL;
		if(radname_find_less_equal(rt, dname, (size_t)dlen, &n)) {
			assert(n);
			assert(n->elem);
			/* check exact match */
			t = (struct teststr*)n->elem;
			assert(t->mylen == rlen);
			assert(memcmp(t->mystr, radname, rlen) == 0);
		} else {
			/* check inexact match */
			if(n == NULL) {
				/* no elements in rt or before first item */
				if(rt->count != 0) {
					n = radix_first(rt);
					t = (struct teststr*)n->elem;
					assert(bstr_cmp(radname, rlen,
					  t->mystr, t->mylen) < 0);
				}
			} else {
				struct radnode* nx;
				assert(n->elem);
				/* n is before the item */
				t = (struct teststr*)n->elem;
				assert(bstr_cmp(t->mystr, t->mylen,
					radname, rlen) < 0);
				/* the next item is NULL or after it */
				nx = radix_next(n);
				if(nx) {
					t = (struct teststr*)nx->elem;
					assert(bstr_cmp(t->mystr, t->mylen,
						radname, rlen) > 0);
				}
			}
		}
	}
}

/** test checks for domain names */
static void test_checks_dname(struct radtree* rt)
{
	/* test_checks is already performed */
	/* check the exact match search for every exact element */
	test_check_dname_search(rt);
	test_check_dname_closest_exact(rt);
	test_check_dname_closest_inexact(rt);
}

static void test_print_str(uint8_t* str, radstrlen_t len)
{
	radstrlen_t x;
	for(x=0; x<len; x++) {
		char c = ((char*)str)[x];
		if(c == 0) fprintf(stderr, ".");
		else fprintf(stderr, "%c", c);
	}
}

static void test_node_print(struct radnode* n, int depth)
{
	int i;
	uint8_t idx;
	if(!n) return;
	for(i=0; i<depth; i++) fprintf(stderr, " ");
	if(n->parent)
		fprintf(stderr, "%c node=%p.", 
			n->pidx+n->parent->offset?n->pidx+n->parent->offset:'.',
			n);
	else
		fprintf(stderr, "rootnode=%p.", n);
	fprintf(stderr, " pidx=%d off=%d(%c) len=%d cap=%d parent=%p\n",
		n->pidx, n->offset, isprint(n->offset)?n->offset:'.',
		n->len, n->capacity, n->parent);
	for(i=0; i<depth; i++) fprintf(stderr, " ");
	if(n->elem) {
		/* for test setup */
		struct teststr* s = (struct teststr*)n->elem;
		fprintf(stderr, "  elem '");
		test_print_str(s->mystr, s->mylen);
		fprintf(stderr, "'\n");
		assert(s->mynode == n);
	} else fprintf(stderr, "  elem NULL\n");
	for(idx=0; idx<n->len; idx++) {
		struct radsel* d = &n->array[idx];
		if(!d->node) {
			assert(d->str == NULL);
			assert(d->len == 0);
			continue;
		}
		for(i=0; i<depth; i++) fprintf(stderr, " ");
		if(n->offset+idx == 0) fprintf(stderr, "[.]");
		else fprintf(stderr, "[%c]", n->offset + idx);
		if(d->str) {
			fprintf(stderr, "+'");
			test_print_str(d->str, d->len);
			fprintf(stderr, "'");
			assert(d->len != 0);
		} else {
			assert(d->len == 0);
		}
		if(d->node) {
			fprintf(stderr, " node=%p\n", d->node);
			test_node_print(d->node, depth+2);
		} else 	fprintf(stderr, " node NULL\n");
	}
}

static void test_tree_print(struct radtree* rt)
{
	fprintf(stderr, "radtree %u elements\n", (unsigned)rt->count);
	test_node_print(rt->root, 0);
}

static void
test_insert_string(struct radtree* rt, char* str)
{
	size_t len = strlen(str);
	struct teststr* s = (struct teststr*)calloc(1, sizeof(*s));
	struct radnode* n;
	assert(s);
	s->mylen = len;
	s->mystr = (uint8_t*)strdup(str);
	assert(s->mystr);
	fprintf(stderr, "radix insert: '%s'\n", str);
	n = radix_insert(rt, s->mystr, s->mylen, s);
	s->mynode = n;
	assert(n);
	/*test_tree_print(rt);*/
	test_checks(rt);
}

static void
test_insert_dname(struct radtree* rt, uint8_t* dname, size_t len)
{
	struct teststr* s;
	struct radnode* n;
	/* see if the dname is already in the tree */
	if(radname_search(rt, dname, len))
		return;
	s = (struct teststr*)calloc(1, sizeof(*s));
	assert(s);
	s->dname_len = len;
	s->dname = (uint8_t*)malloc(len);
	assert(s->dname);
	memcpy(s->dname, dname, len);
	/* convert it */
	s->mystr = (uint8_t*)malloc(len);
	s->mylen = len;
	assert(s->mystr);
	radname_d2r(s->mystr, &s->mylen, dname, len);
	/* check that its inverse conversion is the original */
	if(1) {
		uint8_t buf[1024];
		size_t len = sizeof(buf);
		radname_r2d(s->mystr, s->mylen, buf, &len);
		assert(s->dname_len == len);
		assert(memcmp(s->dname, buf, len) == 0);
	}

	fprintf(stderr, "radix insert: ");
	test_print_str(s->mystr, s->mylen);
	fprintf(stderr, "\n");
	n = radix_insert(rt, s->mystr, s->mylen, s);
	s->mynode = n;
	assert(n);
	/*test_tree_print(rt);*/
	test_checks(rt);
	test_checks_dname(rt);
}

/** browse all elem's from tree with a for loop */
static void test_browse(struct radtree* rt)
{
	struct radnode* n;
	for(n = radix_first(rt); n; n = radix_next(n)) {
		struct teststr* s = (struct teststr*)n->elem;
		fprintf(stderr, "radix %p \telem ", n);
		test_print_str(s->mystr, s->mylen);
		fprintf(stderr, "\n");
		assert(s->mynode == n);
	}
}

/** delete all elem's from tree with a for loop */
static void test_del(struct radtree* rt)
{
	struct radnode* n;
	for(n = radix_first(rt); n; n = radix_next(n)) {
		struct teststr* s = (struct teststr*)n->elem;
		fprintf(stderr, "del %p \telem ", n);
		test_print_str(s->mystr, s->mylen);
		fprintf(stderr, "\n");
		assert(s->mynode == n);
		free(s->mystr);
		free(s);
	}
}

/** unit tests for radix functions */
void unit_radix(void)
{
	assert(bstr_is_prefix((uint8_t*)"", 0, (uint8_t*)"", 0));
	assert(bstr_is_prefix((uint8_t*)"foo", 3, (uint8_t*)"foobar", 6));
	assert(bstr_is_prefix((uint8_t*)"foobar", 6, (uint8_t*)"foo", 3)==0);
	assert(bstr_is_prefix((uint8_t*)"zoobar", 6, (uint8_t*)"foobar", 3)==0);
	assert(bstr_is_prefix((uint8_t*)"zoo", 3, (uint8_t*)"foo", 3)==0);
	assert(bstr_is_prefix((uint8_t*)"ozo", 3, (uint8_t*)"ofo", 3)==0);
	assert(bstr_is_prefix((uint8_t*)"ofo", 3, (uint8_t*)"ofo", 3));

	assert(bstr_common((uint8_t*)"", 0, (uint8_t*)"", 0) == 0);
	assert(bstr_common((uint8_t*)"foo", 3, (uint8_t*)"foobar", 6) == 3);
	assert(bstr_common((uint8_t*)"foobar", 6, (uint8_t*)"foo", 3) == 3);
	assert(bstr_common((uint8_t*)"zoobar", 6, (uint8_t*)"foobar", 3)==0);
	assert(bstr_common((uint8_t*)"zoo", 3, (uint8_t*)"foo", 3)==0);
	assert(bstr_common((uint8_t*)"ozo", 3, (uint8_t*)"ofo", 3)==1);
	assert(bstr_common((uint8_t*)"ofo", 3, (uint8_t*)"ofo", 3)==3);

	fprintf(stderr, "unit_radix ok\n");
}

/* delete a random key */
static void
test_del_a_key(struct radtree* rt)
{
	unsigned x = get_ran_val(rt->count);
	unsigned i = 0;
	struct radnode* n = radix_first(rt);
	struct teststr* t;
	while(i++ < x) {
		n = radix_next(n);
	}
	if(!n) return;
	assert(n->elem);
	t = (struct teststr*)n->elem;
	fprintf(stderr, "delkey %p \telem ", n);
	test_print_str(t->mystr, t->mylen);
	fprintf(stderr, "\n");
	radix_delete(rt, n);
	test_checks(rt);

	/* and delete the test elem */
	free(t->mystr);
	free(t);
}

/* random add and dell test */
static void
test_ran_add_del(struct radtree* rt)
{
	unsigned i, num = 1000;
	unsigned target = 10;
	for(i=0; i<num; i++) {
		/* add or del? */
		unsigned ran = random();
		if(  (rt->count < target && ran%4 != 0)
			|| (ran%2 == 0)) {
			uint8_t key[1024];
			radstrlen_t len;
			/* new string key */
			gen_ran_str_len(key, &len, sizeof(key));
			if(!radix_search(rt, key, len)) {
				test_insert_string(rt, (char*)key);
			}
		} else {
			test_del_a_key(rt);
		}

	}
	test_tree_print(rt);
	while(rt->count != 0) {
		test_del_a_key(rt);
	}
}

/* random add and dell for dnames test */
static void
test_dname_add_del(struct radtree* rt)
{
	unsigned i, num = 1000;
	unsigned target = 10;
	test_checks(rt);
	test_checks_dname(rt);
	for(i=0; i<num; i++) {
		/* add or del? */
		unsigned ran = random();
		if(  (rt->count < target && ran%4 != 0)
			|| (ran%2 == 0)) {
			uint8_t key[1024];
			radstrlen_t len;
			/* new string key */
			gen_ran_dname(key, &len, sizeof(key));
			test_insert_dname(rt, key, len);
		} else {
			test_del_a_key(rt);
			test_checks_dname(rt);
		}

	}
	test_tree_print(rt);
	test_checks(rt);
	test_checks_dname(rt);
	while(rt->count != 0) {
		test_del_a_key(rt);
		test_checks_dname(rt);
	}
}

/** test radname conversion */
static void test_radname(void)
{
	uint8_t d[1024];
	size_t dlen;
	uint8_t r[1024];
	radstrlen_t rlen;
	
	dlen = 1;
	rlen = sizeof(r);
	memcpy(d, "\000", dlen);
	radname_d2r(r, &rlen, d, dlen);
	assert(rlen == 0);

	dlen = 4;
	rlen = sizeof(r);
	memcpy(d, "\002nl\000", dlen);
	radname_d2r(r, &rlen, d, dlen);
	assert(rlen == 2);
	assert(memcmp(r, "nl", rlen) == 0);

	dlen = 9;
	rlen = sizeof(r);
	memcpy(d, "\004labs\002nl\000", dlen);
	radname_d2r(r, &rlen, d, dlen);
	assert(rlen == 7);
	assert(memcmp(r, "nl\000labs", rlen) == 0);

	dlen = 11;
	rlen = sizeof(r);
	memcpy(d, "\001x\004labs\002nl\000", dlen);
	radname_d2r(r, &rlen, d, dlen);
	assert(rlen == 9);
	assert(memcmp(r, "nl\000labs\000x", rlen) == 0);

	rlen = 0;
	dlen = sizeof(d);
	radname_r2d(r, rlen, d, &dlen);
	assert(dlen == 1);
	assert(d[0] == 0);

	rlen = 2;
	dlen = sizeof(d);
	memcpy(r, "nl", rlen);
	radname_r2d(r, rlen, d, &dlen);
	assert(dlen == 4);
	assert(memcmp(d, "\002nl\000", dlen) == 0);

	rlen = 7;
	dlen = sizeof(d);
	memcpy(r, "nl\000labs", rlen);
	radname_r2d(r, rlen, d, &dlen);
	assert(dlen == 9);
	assert(memcmp(d, "\004labs\002nl\000", dlen) == 0);

	rlen = 9;
	dlen = sizeof(d);
	memcpy(r, "nl\000labs\000x", rlen);
	radname_r2d(r, rlen, d, &dlen);
	assert(dlen == 11);
	assert(memcmp(d, "\001x\004labs\002nl\000", dlen) == 0);

	fprintf(stderr, "radname: ok\n");
}

/* test main */
int main(void)
{
	struct radtree* rt;
	unsigned seed;
	fprintf(stderr, "test radtree\n");
	fprintf(stderr, "sizeof(radtree)=%d\n", (int)sizeof(struct radtree));
	fprintf(stderr, "sizeof(radnode)=%d\n", (int)sizeof(struct radnode));
	fprintf(stderr, "sizeof(radsel)=%d\n", (int)sizeof(struct radsel));

	/* init random */
	seed = time(NULL) ^ getpid();
	seed = 1279288340;
	fprintf(stderr, "srandom(%u)\n", seed);
	srandom(seed);

	/* test radname conversion */
	test_radname();

	rt = radix_tree_create();
	test_tree_print(rt);
	test_checks(rt);

	unit_radix();

	/*
	test_tree_print(rt);
	test_insert_string(rt, "nl.nlnetlabs");
	test_tree_print(rt);

	test_insert_string(rt, "nl");
	test_tree_print(rt);
	test_insert_string(rt, "nl.jabber");
	test_tree_print(rt);
	test_insert_string(rt, "");
	test_tree_print(rt);
	*/

	test_ran_add_del(rt);
	test_dname_add_del(rt);
	test_tree_print(rt);

	test_browse(rt);
	test_checks(rt);

	test_del(rt);
	radix_tree_delete(rt);
	return 0;
}

#endif /* RADIX_TEST */
#endif /* USE_RADIX_TREE */
