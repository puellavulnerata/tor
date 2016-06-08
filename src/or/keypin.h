/* Copyright (c) 2014-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_KEYPIN_H
#define TOR_KEYPIN_H

#include "testsupport.h"

int keypin_check_and_add(const uint8_t *rsa_id_digest,
                         const uint8_t *ed25519_id_key,
                         const int replace_existing_entry);
int keypin_check(const uint8_t *rsa_id_digest,
                 const uint8_t *ed25519_id_key);

int keypin_open_journal(const char *fname);
int keypin_close_journal(void);
int keypin_load_journal(const char *fname);
void keypin_clear(void);
int keypin_check_lone_rsa(const uint8_t *rsa_id_digest);

#define KEYPIN_FOUND 0
#define KEYPIN_ADDED 1
#define KEYPIN_MISMATCH -1
#define KEYPIN_NOT_FOUND -2

#ifdef KEYPIN_PRIVATE

/* Forward typedefs */
typedef struct keypin_ent_st keypin_ent_t;
typedef struct keypin_journal_line_st keypin_journal_line_t;

/* Hash table structs */
HT_HEAD(rsamap, keypin_ent_st);
HT_HEAD(edmap, keypin_ent_st);

/**
 * In-memory representation of a key-pinning table entry.
 */
struct keypin_ent_st {
  HT_ENTRY(keypin_ent_st) rsamap_node;
  HT_ENTRY(keypin_ent_st) edmap_node;
  /** SHA1 hash of the RSA key */
  uint8_t rsa_id[DIGEST_LEN];
  /** Ed2219 key. */
  uint8_t ed25519_key[DIGEST256_LEN];
  /** If we're pruning, pointer to the line info in the pruner */
  keypin_journal_line_t *line_info;
};

/**
 * In-memory representation of a keypin journal file, used when pruning
 * duplicate/conflict entries.
 */

struct keypin_journal_line_st {
  /* Next/prev line pointers */
  keypin_journal_line_t *next, *prev;
  /* Parsed keypin entry, or NULL for a comment/reserved line? */
  keypin_ent_t *ent;
  /* Exact line so we can re-emit it correctly after pruning */
  char line[];
};

typedef struct keypin_journal_pruner_s {
  /*
   * Number of lines in the pruner, and number pruned for various
   * reasons.
   */
  int nlines;
  int nentries;
  int nlines_pruned_corrupt, nlines_pruned_duplicate, nlines_pruned_conflict;
  /* Doubly linked list of lines to preserve order and comment/reserved
   * lines */
  keypin_journal_line_t *head, *tail;
  /* Conflict/duplicate detection hash tables */
  struct rsamap pruner_rsamap;
  struct edmap pruner_edmap;
} keypin_journal_pruner_t;

STATIC keypin_ent_t * keypin_parse_journal_line(const char *cp);
STATIC int keypin_load_journal_impl(const char *data, size_t size,
                                    keypin_journal_pruner_t *pruner,
                                    int also_add_to_main_map);

MOCK_DECL(STATIC void, keypin_add_entry_to_map,
          (keypin_ent_t *ent, keypin_journal_pruner_t *pruner));
#endif

#endif

