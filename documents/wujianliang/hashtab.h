/* $Id: hashtab.h,v 1.1.1.1 2006-12-23 13:58:17 laurent Exp $ */
#ifndef MUCK_HASHTAB_H
#define MUCK_HASHTAB_H

#ifdef __cplusplus
extern "C" {
#endif

/* Comparison function used to check if two hash table entries are the same.
   Should return 0 if the same, non-zero otherwise. */
typedef int (*compare_function)(const void *, const void *);

/* Key generating function.  Return the key for a hash table entry. */
typedef unsigned long (*key_function)(const void *);

/* Function to be called when a hash entry is to be deleted. */
typedef void (*delete_function)(void *);


struct hash_entry {
    struct hash_entry *next;	/* Linked list buckets for collisions. */
    const void	      *data;	/* Actual entry we are storing. */
};


typedef struct hash_tab_t {
    const char *id;		/* ''Name'' of hashtable, for stat display. */

    compare_function cmpfn;	/* Function to compare two entries. */
    key_function     keyfn;	/* Function to generate a key for an entry. */
    delete_function  delfn;	/* Function called when freeing an entry. */

    unsigned long size;		/* Size of the hashtable. */
    struct hash_entry **table;	/* Actual hashtable array. */

    unsigned long walk_key;	/* Current bucket when walking hash table. */
    struct hash_entry *walk_loc; /* Current entry when walking hash table. */
    int inside_walk;		/* Boolean set true when walking hash table. */

    unsigned long entries;	/* Total number of entries. */
    unsigned long max_entries;	/* Max # of entries ever stored. */

    unsigned long hits;		/* Total hits. */
    unsigned long hits_visited;	/* Total number of entries visited on hits. */
    
    unsigned long misses;	/* total misses. */
    unsigned long misses_visited; /* Total number of entried visited misses. */

    unsigned long total_insert;	/* Total number of entries ever inserted. */

    struct hash_tab_t *next;	/* Keep all hashtables in linked list. */
    struct hash_tab_t **prev;
} hash_tab;



extern void free_hash_table(hash_tab *table);
extern int compare_generic_hash(const void *entry1, const void *entry2);
extern unsigned long make_key_generic_hash(const void *entry);
extern void delete_generic_hash(void *entry);
extern void *find_hash_entry(hash_tab *table, const void *match);
extern int add_hash_entry(hash_tab *table, const void *data);
extern void clear_hash_entry(hash_tab *table, const void *data);
extern void clear_hash_table(hash_tab *table);
extern hash_tab *init_hash_table(const char *id, compare_function cmpfn, key_function keyfn, delete_function delfn, unsigned long size);
extern void init_hash_walk(hash_tab *table);
extern void *next_hash_walk(hash_tab *table);
extern void dump_hashtab_stats(hash_tab *table);
extern long total_hash_entries(void);
extern long num_hash_entries(hash_tab *table);
extern void init_hash_entries(const long count);

#ifdef __cplusplus
}
#endif

#endif /* MUCK_HASHTAB_H */
