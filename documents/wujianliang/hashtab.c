/* Copyright (c) 1992-1999 by David Moore.  All rights reserved. */
/* $Id: hashtab.c,v 1.1.1.1 2006-12-23 13:58:17 laurent Exp $ */
/* #include "config.h" */

#include <stdlib.h>		/* NULL */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include "hashtab.h"

#define log_info printf



#ifndef MALLOC
#define MALLOC(r, t, c)		((r) = (t *) malloc(sizeof(t)*(c)))
#define FREE(r)			do { free(r); (r) = 0; } while (0)
#endif

#ifndef MAKE_ALLOCATOR
#define MAKE_ALLOCATOR(NAME) \
    union allocator_##NAME##_un { \
        struct NAME info; \
        union allocator_##NAME##_un *next; \
    }; \
    static union allocator_##NAME##_un *available_##NAME##s = NULL; \
    static long total_##NAME##s = 0; \
    static void generate_##NAME##s(long count) \
    { \
        union allocator_##NAME##_un *hunk; \
        long block_size, num, i; \
        while (count > 0) { \
	    block_size = 4096; \
	    while ((count * sizeof(union allocator_##NAME##_un)) >= \
                   (2*block_size) - 4) { \
		block_size *= 2; \
	    } \
	    num = (block_size - 4) / sizeof(union allocator_##NAME##_un); \
	    MALLOC(hunk, union allocator_##NAME##_un, num); \
	    if (!hunk) { \
		available_##NAME##s = NULL; \
		return; \
	    } \
	    for (i = 0; i < num; i++) { \
		hunk->next = available_##NAME##s; \
		available_##NAME##s = hunk; \
		hunk++; \
	    } \
	    count -= num; \
	} \
    } \
    static struct NAME *alloc_##NAME(void) \
    { \
        struct NAME *result; \
        if (!available_##NAME##s) generate_##NAME##s(1); \
        if (!available_##NAME##s) return NULL; \
	result = (struct NAME *) available_##NAME##s; \
	available_##NAME##s = available_##NAME##s->next; \
        total_##NAME##s++; \
	return result; \
    } \
    static void free_##NAME(struct NAME *i) \
    { \
        union allocator_##NAME##_un *x = (union allocator_##NAME##_un *) i; \
	x->next = available_##NAME##s; \
	available_##NAME##s = x; \
        total_##NAME##s--; \
    }
#endif

MAKE_ALLOCATOR(hash_entry)


/* Linked list of all hash tables we are managing. */
static hash_tab *hash_table_list = NULL;


/* These are the generic hashtable routines.  They _require_ that the first
   member of the entry be a string, and that string is taken as the key.
   The generic delete function simply free's it's argument. */
int compare_generic_hash(const void *entry1, const void *entry2)
{
    const char *str1 = (const char *) entry1;
    const char *str2 = (const char *) entry2;
    if (str1 == str2) return 0; /* Same string. */

    if (!str1) str1 = "";
    if (!str2) str2 = "";

    while (*str1 && tolower(*str1) == tolower(*str2)) {
        str1++;
        str2++;
    }

    return ((unsigned char) tolower(*str1)) -
	((unsigned char) tolower(*str2));
}


unsigned long make_key_generic_hash(const void *entry)
{
    const char *s = (const char *) entry;
    unsigned long hashval;

    if (!s) return 0;

    for (hashval = 0; *s != '\0'; s++)
        hashval = (((unsigned int) *s) | 0x20) + 31 * hashval;

    return hashval;
}


void delete_generic_hash(void *entry)
{
    FREE(entry);
}


static unsigned long compute_hash(hash_tab *table, const void *data)
{
    return (table->keyfn(data) % table->size);
}


static struct hash_entry *find_hash_internal(hash_tab *table, const unsigned long hashval, const void *match, struct hash_entry ***return_prev)
{
    struct hash_entry *curr;
    struct hash_entry **prev;
    compare_function cmpfn;
    int visits = 0;
    
    if (!table) return NULL;

    cmpfn = table->cmpfn;

    prev = &(table->table[hashval]);
    for (curr = *prev; curr; prev = &(curr->next), curr = curr->next) {
	visits++;
	if (cmpfn(match, curr->data) == 0) {
	    if (!table->inside_walk) {
		/* Move this entry to the head of the bucket. */
		*prev = curr->next;
		curr->next = table->table[hashval];
		table->table[hashval] = curr;
		prev = &(table->table[hashval]);
	    }

	    /* Mark this hit for statistics. */
	    table->hits_visited += visits;
	    table->hits++;

	    if (return_prev) *return_prev = prev;
	    return curr;
	}
    }

    table->misses_visited += visits + 1;
    table->misses++;

    return NULL;                  /* not found */
}


void *find_hash_entry(hash_tab *table, const void *match)
{
    struct hash_entry *entry;

    entry = find_hash_internal(table, compute_hash(table, match), match, NULL);

    return (entry) ? (void*)(entry->data) : NULL;
}


int add_hash_entry(hash_tab *table, const void *data)
{
    struct hash_entry *entry;
    unsigned long hashval;

    if (!table) return 1;
    
    hashval = compute_hash(table, data);
    
    entry = find_hash_internal(table, hashval, data, NULL);

    if (entry) {
	/* Free old entry. */
	table->delfn((void *) entry->data);
    } else {
	entry = alloc_hash_entry();
	if (!entry) {
	    fprintf(stderr, "Error adding hash entry: %s\n", strerror(errno));
	    return 1;
	}
	entry->next = table->table[hashval];
	table->table[hashval] = entry;

	table->entries++;
	if (table->entries > table->max_entries)
	    table->max_entries = table->entries;
	table->total_insert++;
    }
    
    /* Either we just created it, or we already found a valid one. */
    entry->data = data;
    return 0;
}


void clear_hash_entry(hash_tab *table, const void *data)
{
    struct hash_entry *entry;
    struct hash_entry **prev;
    unsigned long hashval;

    if (!table) return;

    hashval = compute_hash(table, data);
    
    entry = find_hash_internal(table, hashval, data, &prev);

    if (!entry) return;

    /* Found one.  Remove from linked list. */
    *prev = entry->next;

    /* If entry was the next location in a hash walk, skip it. */
    if (table->walk_loc == entry) {
	table->walk_loc = entry->next;
    }

    table->entries--;

    table->delfn((void *) entry->data);
    free_hash_entry(entry);
}


void free_hash_table(hash_tab *table)
{
    struct hash_entry **temp;	/* In the table array. */
    struct hash_entry *entry, *next;
    unsigned long i, size;
    
    if (!table) return;

    size = table->size;
    temp = table->table;
    for (i = 0; i < size; i++, temp++) {
	for (entry = *temp; entry; entry = next) {
	    next = entry->next;	/* Save it, since we free next. */
	    table->delfn((void *) entry->data);
	    free_hash_entry(entry);
	}
    }

    /* Remove from our linked list of tables. */
    *(table->prev) = table->next;
    if (table->next)
	table->next->prev = table->prev;

    FREE(table->table);
    FREE(table);
}

void clear_hash_table(hash_tab *table)
{
    struct hash_entry **temp;	/* In the table array. */
    struct hash_entry *entry, *next;
    unsigned long i, size;
    
    if (!table) return;

    size = table->size;
    temp = table->table;
    for (i = 0; i < size; i++, temp++) {
	for (entry = *temp; entry; entry = next) {
	    next = entry->next;	/* Save it, since we free next. */
	    table->delfn((void *) entry->data);
	    free_hash_entry(entry);
	}
    }

    /* Clear out the actual table. */
    temp = table->table;
    for (i = 0; i < size; i++, temp++)
	*temp = NULL;

    table->entries = 0;
}

hash_tab *init_hash_table(const char *id, compare_function cmpfn, key_function keyfn, delete_function delfn, unsigned long size)
{
    hash_tab *table;
    struct hash_entry **temp;
    unsigned long i;

    /* Malloc everything. */
    MALLOC(table, hash_tab, 1);
    if (!table) {
	fprintf(stderr, "malloc(%u): %s\n", sizeof(hash_tab), strerror(errno));
	return 0;
    }
    MALLOC(table->table, struct hash_entry *, size);
    if (!table->table) {
	//fprintf(stderr, "malloc(%lu): %s\n", sizeof(struct hash_entry*) * size,
	fprintf(stderr, "malloc(%lu): %s\n", sizeof(struct hash_entry) * size,
	    strerror(errno));
	return 0;
    }

    /* Clear out the actual table. */
    temp = table->table;
    for (i = 0; i < size; i++, temp++)
	*temp = NULL;

    /* Fill in everything. */
    table->id = id;
    table->cmpfn = cmpfn;
    table->keyfn = keyfn;
    table->delfn = delfn;
    table->size = size;
    table->walk_key = 0;
    table->walk_loc = NULL;
    table->inside_walk = 0;
    table->entries = 0;
    table->max_entries = 0;
    table->hits = 0;
    table->hits_visited = 0;
    table->misses = 0;
    table->misses_visited = 0;
    table->total_insert = 0;

    /* Stick in our linked list of hash tables. */
    if (hash_table_list)
	hash_table_list->prev = &(table->next);
    table->next = hash_table_list;
    table->prev = &hash_table_list;
    hash_table_list = table;
    
    return table;
}


/* Can do lookups during a walk, but insertions and deletions may
    cause problems. */
void init_hash_walk(hash_tab *table)
{
    table->walk_key = 0;
    table->walk_loc = NULL;
    table->inside_walk = 1;
}


void *next_hash_walk(hash_tab *table)
{
    struct hash_entry **temp;
    const void *result;
    unsigned long i, size;

    if (table->walk_loc) {
	result = table->walk_loc->data;
	table->walk_loc = table->walk_loc->next;
	return (void*)result;
    }

    size = table->size;
    temp = table->table + table->walk_key;

    for (i = table->walk_key; i < size; i++, temp++) {
	if (*temp) break;
    }

    if (i == table->size) {
	table->inside_walk = 0;
	return NULL;
    }

    result = (*temp)->data;
    table->walk_loc = (*temp)->next;
    table->walk_key = i + 1;

    return (void*)result;
}


void dump_hashtab_stats(hash_tab *table)
{
    int doing_all = 0;
    long total_ratio, hit_ratio, miss_ratio;
    double t;

    if (table == NULL) {
	/* Dump information on all of the hashtables. */
	doing_all = 1;
	table = hash_table_list;
    }

    for (; table; table = table->next) {
	if (table->hits_visited + table->misses_visited) {
	    t = 1000 * (((double) table->hits_visited + (double) table->misses_visited) / ((double) table->hits + (double) table->misses));
	    total_ratio = t;
	} else total_ratio = 0;
	if (table->hits_visited) {
	    t = 1000 * ((double) table->hits_visited / (double) table->hits);
	    hit_ratio = t;
	} else hit_ratio = 0;
	if (table->misses_visited) {
	    t = 1000 * ((double) table->misses_visited / (double) table->misses);
	    miss_ratio = t;
	} else miss_ratio = 0;

	fprintf(stderr,"\n");
	fprintf(stderr,"--- Statistics for: %s\n",
		 table->id);
	fprintf(stderr,"Table size: %ld.  Entries: %ld.\n",
		 table->size, table->entries);
	fprintf(stderr,"Total accesses: %ld.\n",
		 table->hits + table->misses);
	fprintf(stderr,"Hit accesses: %ld.  Miss accesses: %ld.\n",
		 table->hits, table->misses);
	fprintf(stderr,"Bucket probes requiring comparison: %ld\n",
		 table->hits_visited + table->misses_visited);
	fprintf(stderr,"Hit compares: %ld.  Miss compares: %ld.\n",
		 table->hits_visited, table->misses_visited);

	/* the closer this is to 1000 the better the hash fxn */
	fprintf(stderr,"Total access ratio: %ld (/1000)\n",
		 total_ratio);
	fprintf(stderr,"Hit ratio: %ld.  Miss ratio: %ld. (/1000)\n",
		 hit_ratio, miss_ratio); 
	fprintf(stderr,"Max entries stored: %ld.\n",
		 table->max_entries);

	if (!doing_all) break;
    }
}


long total_hash_entries(void)
{
    /* #### MAKE_ALLOCATOR can't pluralize well :) */
    return total_hash_entrys;
}


void init_hash_entries(const long count)
{
    /* #### MAKE_ALLOCATOR can't pluralize well :) */
    generate_hash_entrys(count);
}

extern long num_hash_entries(hash_tab *table)
{
    return table->entries;
}
