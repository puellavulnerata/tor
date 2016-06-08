/* Copyright (c) 2014-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file keypin.c
 *
 * \brief Functions and structures for associating routers' RSA key
 * fingerprints with their ED25519 keys.
 */

#define KEYPIN_PRIVATE

#include "orconfig.h"
#include "compat.h"
#include "crypto.h"
#include "crypto_format.h"
#include "di_ops.h"
#include "ht.h"
#include "keypin.h"
#include "siphash.h"
#include "torint.h"
#include "torlog.h"
#include "util.h"
#include "util_format.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef _WIN32
#include <io.h>
#endif

/**
 * @file keypin.c
 * @brief Key-pinning for RSA and Ed25519 identity keys at directory
 *  authorities.
 *
 * This module implements a key-pinning mechanism to ensure that it's safe
 * to use RSA keys as identitifers even as we migrate to Ed25519 keys.  It
 * remembers, for every Ed25519 key we've seen, what the associated Ed25519
 * key is.  This way, if we see a different Ed25519 key with that RSA key,
 * we'll know that there's a mismatch.
 *
 * We persist these entries to disk using a simple format, where each line
 * has a base64-encoded RSA SHA1 hash, then a base64-endoded Ed25519 key.
 * Empty lines, misformed lines, and lines beginning with # are
 * ignored. Lines beginning with @ are reserved for future extensions.
 */

static int keypin_journal_append_entry(const uint8_t *rsa_id_digest,
                                       const uint8_t *ed25519_id_key);
static int keypin_check_and_add_impl(const uint8_t *rsa_id_digest,
                                     const uint8_t *ed25519_id_key,
                                     const int do_not_add,
                                     const int replace);
static void keypin_add_line_to_pruner(keypin_journal_pruner_t *p,
                                      keypin_ent_t *ent,
                                      const char *line, int len);
static int keypin_add_or_replace_entry_in_map(
    keypin_ent_t *ent,
    keypin_journal_pruner_t *pruner);
static void keypin_remove_entry_from_pruner(keypin_journal_pruner_t *p,
                                            keypin_ent_t *ent);

static struct rsamap the_rsa_map = HT_INITIALIZER();
static struct edmap the_ed_map = HT_INITIALIZER();

/** Hashtable helper: compare two keypin table entries and return true iff
 * they have the same RSA key IDs. */
static inline int
keypin_ents_eq_rsa(const keypin_ent_t *a, const keypin_ent_t *b)
{
  return tor_memeq(a->rsa_id, b->rsa_id, sizeof(a->rsa_id));
}

/** Hashtable helper: hash a keypin table entries based on its RSA key ID */
static inline unsigned
keypin_ent_hash_rsa(const keypin_ent_t *a)
{
return (unsigned) siphash24g(a->rsa_id, sizeof(a->rsa_id));
}

/** Hashtable helper: compare two keypin table entries and return true iff
 * they have the same ed25519 keys */
static inline int
keypin_ents_eq_ed(const keypin_ent_t *a, const keypin_ent_t *b)
{
  return tor_memeq(a->ed25519_key, b->ed25519_key, sizeof(a->ed25519_key));
}

/** Hashtable helper: hash a keypin table entries based on its ed25519 key */
static inline unsigned
keypin_ent_hash_ed(const keypin_ent_t *a)
{
return (unsigned) siphash24g(a->ed25519_key, sizeof(a->ed25519_key));
}

HT_PROTOTYPE(rsamap, keypin_ent_st, rsamap_node, keypin_ent_hash_rsa,
               keypin_ents_eq_rsa)
HT_GENERATE2(rsamap, keypin_ent_st, rsamap_node, keypin_ent_hash_rsa,
               keypin_ents_eq_rsa, 0.6, tor_reallocarray, tor_free_)

HT_PROTOTYPE(edmap, keypin_ent_st, edmap_node, keypin_ent_hash_ed,
               keypin_ents_eq_ed)
HT_GENERATE2(edmap, keypin_ent_st, edmap_node, keypin_ent_hash_ed,
               keypin_ents_eq_ed, 0.6, tor_reallocarray, tor_free_)

/**
 * Check whether we already have an entry in the key pinning table for a
 * router with RSA ID digest <b>rsa_id_digest</b> or for ed25519 key
 * <b>ed25519_id_key</b>.  If we have an entry that matches both keys,
 * return KEYPIN_FOUND. If we find an entry that matches one key but
 * not the other, return KEYPIN_MISMATCH.  If we have no entry for either
 * key, add such an entry to the table and return KEYPIN_ADDED.
 *
 * If <b>replace_existing_entry</b> is true, then any time we would have said
 * KEYPIN_FOUND, we instead add this entry anyway and return KEYPIN_ADDED.
 */
int
keypin_check_and_add(const uint8_t *rsa_id_digest,
                     const uint8_t *ed25519_id_key,
                     const int replace_existing_entry)
{
  return keypin_check_and_add_impl(rsa_id_digest, ed25519_id_key, 0,
                                   replace_existing_entry);
}

/**
 * As keypin_check_and_add, but do not add.  Return KEYPIN_NOT_FOUND if
 * we would add.
 */
int
keypin_check(const uint8_t *rsa_id_digest,
             const uint8_t *ed25519_id_key)
{
  return keypin_check_and_add_impl(rsa_id_digest, ed25519_id_key, 1, 0);
}

/**
 * Helper: implements keypin_check and keypin_check_and_add.
 */
static int
keypin_check_and_add_impl(const uint8_t *rsa_id_digest,
                          const uint8_t *ed25519_id_key,
                          const int do_not_add,
                          const int replace)
{
  keypin_ent_t search, *ent;
  memset(&search, 0, sizeof(search));
  memcpy(search.rsa_id, rsa_id_digest, sizeof(search.rsa_id));
  memcpy(search.ed25519_key, ed25519_id_key, sizeof(search.ed25519_key));

  /* Search by RSA key digest first */
  ent = HT_FIND(rsamap, &the_rsa_map, &search);
  if (ent) {
    tor_assert(fast_memeq(ent->rsa_id, rsa_id_digest, sizeof(ent->rsa_id)));
    if (tor_memeq(ent->ed25519_key, ed25519_id_key,sizeof(ent->ed25519_key))) {
      return KEYPIN_FOUND; /* Match on both keys. Great. */
    } else {
      if (!replace)
        return KEYPIN_MISMATCH; /* Found RSA with different Ed key */
    }
  }

  /* See if we know a different RSA key for this ed key */
  if (! replace) {
    ent = HT_FIND(edmap, &the_ed_map, &search);
    if (ent) {
      /* If we got here, then the ed key matches and the RSA doesn't */
      tor_assert(fast_memeq(ent->ed25519_key, ed25519_id_key,
                            sizeof(ent->ed25519_key)));
      tor_assert(fast_memneq(ent->rsa_id, rsa_id_digest, sizeof(ent->rsa_id)));
      return KEYPIN_MISMATCH;
    }
  }

  /* Okay, this one is new to us. */
  if (do_not_add)
    return KEYPIN_NOT_FOUND;

  ent = tor_memdup(&search, sizeof(search));
  int r = keypin_add_or_replace_entry_in_map(ent, NULL);
  if (! replace) {
    tor_assert(r == 1);
  } else {
    tor_assert(r != 0);
  }
  keypin_journal_append_entry(rsa_id_digest, ed25519_id_key);
  return KEYPIN_ADDED;
}

/**
 * Helper: add <b>ent</b> to the hash tables.
 */
MOCK_IMPL(STATIC void,
keypin_add_entry_to_map, (keypin_ent_t *ent, keypin_journal_pruner_t *pruner))
{
  if (!pruner) {
    HT_INSERT(rsamap, &the_rsa_map, ent);
    HT_INSERT(edmap, &the_ed_map, ent);
  } else {
    HT_INSERT(rsamap, &(pruner->pruner_rsamap), ent);
    HT_INSERT(edmap, &(pruner->pruner_edmap), ent);
  }
}

/**
 * Helper: add 'ent' to the maps, replacing any entries that contradict it.
 * Take ownership of 'ent', freeing it if needed.  If a pruner is passed in
 * use the hash tables in the pruner instead.
 *
 * Return 0 if the entry was a duplicate, -1 if there was a conflict,
 * and 1 if there was no conflict.
 */
static int
keypin_add_or_replace_entry_in_map(keypin_ent_t *ent,
                                   keypin_journal_pruner_t *pruner)
{
  int r = 1;
  struct rsamap *rsa_map = NULL;
  struct edmap *ed_map = NULL;

  if (!pruner) {
    /* Use the main map */
    rsa_map = &the_rsa_map;
    ed_map = &the_ed_map;
  } else {
    /* Use the pruner hash tables instead */
    rsa_map = &(pruner->pruner_rsamap);
    ed_map = &(pruner->pruner_edmap);
  }

  keypin_ent_t *ent2 = HT_FIND(rsamap, rsa_map, ent);
  keypin_ent_t *ent3 = HT_FIND(edmap, ed_map, ent);

  if (ent2 &&
      fast_memeq(ent2->ed25519_key, ent->ed25519_key, DIGEST256_LEN)) {
    /* We already have this mapping stored. Ignore it. */
    tor_free(ent);
    return 0;
  } else if (ent2 || ent3) {
    /* We have a conflict. (If we had no entry, we would have ent2 == ent3
     * == NULL. If we had a non-conflicting duplicate, we would have found
     * it above.)
     *
     * We respond by having this entry (ent) supersede all entries that it
     * contradicts (ent2 and/or ent3). In other words, if we receive
     * <rsa,ed>, we remove all <rsa,ed'> and all <rsa',ed>, for rsa'!=rsa
     * and ed'!= ed.
     */
    const keypin_ent_t *t;
    /* Correctly count how many conflicts we remove; return -1 or -2 */
    r = 0;
    /* Got an ent2? */
    if (ent2) {
      t = HT_REMOVE(rsamap, rsa_map, ent2);
      tor_assert(ent2 == t);
      t = HT_REMOVE(edmap, ed_map, ent2);
      tor_assert(ent2 == t);
      --r;
    }
    /* Got a distinct ent3? */
    if (ent3 && ent2 != ent3) {
      t = HT_REMOVE(rsamap, rsa_map, ent3);
      tor_assert(ent3 == t);
      t = HT_REMOVE(edmap, ed_map, ent3);
      tor_assert(ent3 == t);
      --r;
      if (pruner) keypin_remove_entry_from_pruner(pruner, ent3);
      else tor_free(ent3);
    }
    /* Be sure we only try to free ent2 if we had an ent2 */
    if (ent2) {
      if (pruner) keypin_remove_entry_from_pruner(pruner, ent2);
      else tor_free(ent2);
    }
    /*
     * We should always have this; if we don't and we return it, we're
     * incorrectly signalling a duplicate without having freed it and the
     * caller would leak, so assert it.
     */
    tor_assert(r < 0);
    /* Fall through */
  }

  keypin_add_entry_to_map(ent, pruner);
  return r;
}

/** Remove an entry from a pruner; we'll need to free the associated
 * line info with it and adjust the linked list.
 */
static void
keypin_remove_entry_from_pruner(keypin_journal_pruner_t *p,
                                keypin_ent_t *ent)
{
  keypin_journal_line_t *l = NULL;

  tor_assert(p != NULL);
  tor_assert(ent != NULL);

  /* If we're using a pruner, there should be line info */
  tor_assert(ent->line_info);
  l = ent->line_info;
  tor_assert(l->ent == ent);

  /* We've got the line; unlink it */
  if (l->next) l->next->prev = l->prev;
  else {
    /* This was the tail */
    tor_assert(p->tail == l);
    p->tail = l->prev;
  }

  if (l->prev) l->prev->next = l->next;
  else {
    /* This was the head */
    tor_assert(p->head == l);
    p->head = l->next;
  }

  l->next = l->prev = NULL;

  /* Now that it's unlinked, adjust the line counters in the pruner */
  tor_assert(p->nlines > 0);
  --(p->nlines);
  /* We're removing an entry, not just a line */
  tor_assert(p->nentries > 0);
  --(p->nentries);

  /* The caller already removed this from p's hash tables */
  /* Free the entry and the line */
  tor_free(ent);
  tor_free(l);
}

/**
 * Check whether we already have an entry in the key pinning table for a
 * router with RSA ID digest <b>rsa_id_digest</b>.  If we have no such entry,
 * return KEYPIN_NOT_FOUND.  If we find an entry that matches the RSA key but
 * which has an ed25519 key, return KEYPIN_MISMATCH.
 */
int
keypin_check_lone_rsa(const uint8_t *rsa_id_digest)
{
  keypin_ent_t search, *ent;
  memset(&search, 0, sizeof(search));
  memcpy(search.rsa_id, rsa_id_digest, sizeof(search.rsa_id));

  /* Search by RSA key digest first */
  ent = HT_FIND(rsamap, &the_rsa_map, &search);
  if (ent) {
    return KEYPIN_MISMATCH;
  } else {
    return KEYPIN_NOT_FOUND;
  }
}

/** Open fd to the keypinning journal file. */
static int keypin_journal_fd = -1;

/** Open the key-pinning journal to append to <b>fname</b>.  Return 0 on
 * success, -1 on failure. */
int
keypin_open_journal(const char *fname)
{
  /* O_SYNC ??*/
  int fd = tor_open_cloexec(fname, O_WRONLY|O_CREAT|O_BINARY, 0600);
  if (fd < 0)
    goto err;

  if (tor_fd_seekend(fd) < 0)
    goto err;

  /* Add a newline in case the last line was only partially written */
  if (write(fd, "\n", 1) < 1)
    goto err;

  /* Add something about when we opened this file. */
  char buf[80];
  char tbuf[ISO_TIME_LEN+1];
  format_iso_time(tbuf, approx_time());
  tor_snprintf(buf, sizeof(buf), "@opened-at %s\n", tbuf);
  if (write_all(fd, buf, strlen(buf), 0) < 0)
    goto err;

  keypin_journal_fd = fd;
  return 0;
 err:
  if (fd >= 0)
    close(fd);
  return -1;
}

/** Close the keypinning journal file. */
int
keypin_close_journal(void)
{
  if (keypin_journal_fd >= 0)
    close(keypin_journal_fd);
  keypin_journal_fd = -1;
  return 0;
}

/** Length of a keypinning journal line, including terminating newline. */
#define JOURNAL_LINE_LEN (BASE64_DIGEST_LEN + BASE64_DIGEST256_LEN + 2)

/** Add an entry to the keypinning journal to map <b>rsa_id_digest</b> and
 * <b>ed25519_id_key</b>. */
static int
keypin_journal_append_entry(const uint8_t *rsa_id_digest,
                            const uint8_t *ed25519_id_key)
{
  if (keypin_journal_fd == -1)
    return -1;
  char line[JOURNAL_LINE_LEN];
  digest_to_base64(line, (const char*)rsa_id_digest);
  line[BASE64_DIGEST_LEN] = ' ';
  digest256_to_base64(line + BASE64_DIGEST_LEN + 1,
                      (const char*)ed25519_id_key);
  line[BASE64_DIGEST_LEN+1+BASE64_DIGEST256_LEN] = '\n';

  if (write_all(keypin_journal_fd, line, JOURNAL_LINE_LEN, 0)<0) {
    log_warn(LD_DIRSERV, "Error while adding a line to the key-pinning "
             "journal: %s", strerror(errno));
    keypin_close_journal();
    return -1;
  }

  return 0;
}

/** Add a line to the pruner; this just goes into the line list so we can
 * correctly re-emit it later, and if a keypin_ent_t is provided, we also
 * add it to the right indices and prune.
 */
static void
keypin_add_line_to_pruner(keypin_journal_pruner_t *p,
                          keypin_ent_t *ent,
                          const char *line, int len)
{
  keypin_journal_line_t *l = NULL;
  keypin_ent_t *our_ent = NULL;
  int adding = 1, r;

  /* Asserts for sanity */
  tor_assert(p != NULL);
  tor_assert(line != NULL);

  if (ent) {
    /* Duplicate the entity; we take ownership from here */
    our_ent = tor_malloc_zero(sizeof(*our_ent));
    memcpy(our_ent, ent, sizeof(*our_ent));

    /*
     * Try adding it to the pruner map and find duplicates/conflicts.  If
     * there are conflicts, this will remove them from the pruner and adjust
     * the linked list and counters too.  If there are no duplicates or
     * conflicts, this will add ent to the pruner hash tables, but it
     * won't go in the linked list until we insert it below.
     */

    r = keypin_add_or_replace_entry_in_map(our_ent, p);
    if (r == 0) {
      /*
       * This was a duplicate; we just freed it and won't be adding
       * anything to the list, but should bump the duplicate counter.
       */
      adding = 0;
      ent = NULL;
      ++(p->nlines_pruned_duplicate);
    } else if (r < 0) {
      /*
       * This was a conflict; we removed and freed old entries and
       * inserted it into the pruner's hash table, so we must add it to
       * the linked list below.  We should bump the conflict counter.
       */
       p->nlines_pruned_conflict -= r;
    }
    /* else just add it */
  }

  /* If we're adding this one, add it */
  if (adding) {
    /* Allocate a line, as many chars as we need plus room for the NUL */
    l = tor_malloc_zero(sizeof(*l) + len + 1);
    /* Assign the entry pointer */
    if (our_ent) {
      l->ent = our_ent;
      l->ent->line_info = l;
      /* Update nentries here */
      ++(p->nentries);
    }
    /* Copy over the line */
    memcpy(l->line, line, len);
    l->line[len] = '\0';
    /* Insert it into the pruner at the end of the list */
    l->next = NULL;
    l->prev = p->tail;
    if (p->tail) p->tail->next = l;
    else p->head = l;
    p->tail = l;
    /* Update the pruner counters */
    ++(p->nlines);
  }
}

/** Load a journal from the <b>size</b>-byte region at <b>data</b>.  Return 0
 * on success, -1 on failure.  If pruner is not null, add info to it for
 * pruning the journal file.  If a pruner is supplied, skip adding entries
 * to the real keypin map unless also_add_to_main_map is set.
 */
STATIC int
keypin_load_journal_impl(const char *data, size_t size,
                         keypin_journal_pruner_t *pruner,
                         int also_add_to_main_map)
{
  const char *start = data, *end = data + size, *next;

  int n_corrupt_lines = 0;
  int n_entries = 0;
  int n_duplicates = 0;
  int n_conflicts = 0;
  int corrupt_flag;

  for (const char *cp = start; cp < end; cp = next) {
    const char *eol = memchr(cp, '\n', end-cp);
    const char *eos = eol ? eol : end;
    const size_t len = eos - cp;

    next = eol ? eol + 1 : end;

    if (len == 0) {
      /* We're skipping all whitespace lines below, so skip blanks too */
      if (pruner) keypin_add_line_to_pruner(pruner, NULL, cp, len);
      continue;
    }

    if (*cp == '@') {
      /* Lines that start with @ are reserved. Ignore for now. */
      if (pruner) keypin_add_line_to_pruner(pruner, NULL, cp, len);
      continue;
    }
    if (*cp == '#') {
      /* Lines that start with # are comments. */
      if (pruner) keypin_add_line_to_pruner(pruner, NULL, cp, len);
      continue;
    }

    /* Is it the right length?  (The -1 here is for the newline.) */
    if (len != JOURNAL_LINE_LEN - 1) {
      /* Lines with a bad length are corrupt unless they are empty.
       * Ignore them either way */
      corrupt_flag = 0;
      for (const char *s = cp; s < eos; ++s) {
        if (! TOR_ISSPACE(*s)) {
          /*
           * Never add corrupt lines to pruner, but if we're pruning, count
           * them there too.
           */
          if (pruner) ++(pruner->nlines_pruned_corrupt);
          if (!pruner || also_add_to_main_map) ++n_corrupt_lines;
          corrupt_flag = 1;
          break;
        }
      }

      /*
       * We're not dropping blanks above, so preserve these all-whitespace
       * lines when pruning too.
       */
      if (!corrupt_flag && pruner)
        keypin_add_line_to_pruner(pruner, NULL, cp, len);
      continue;
    }

    keypin_ent_t *ent = keypin_parse_journal_line(cp);

    if (ent == NULL) {
      /*
       * As above, note the corrupt line in the pruner too if we're using
       * one.
       */
      if (pruner) ++(pruner->nlines_pruned_corrupt);
      if (!pruner || also_add_to_main_map) ++n_corrupt_lines;
      continue;
    }

    /* Add the parsed line to the pruner */
    if (pruner) keypin_add_line_to_pruner(pruner, ent, cp, len);

    if (!pruner || also_add_to_main_map) {
      const int r = keypin_add_or_replace_entry_in_map(ent, NULL);
      if (r == 0) {
        ++n_duplicates;
      } else if (r < 0) {
        n_conflicts -= r;
      }

      ++n_entries;
    } else {
      /*
       * We didn't add the entity to the main map, and
       * keypin_add_line_to_pruner() will have copied it
       * for the pruner, so free it.
       */
      tor_free(ent);
    }
  }

  if (!pruner || also_add_to_main_map) {
    int severity = (n_corrupt_lines || n_duplicates) ? LOG_WARN : LOG_INFO;
    tor_log(severity, LD_DIRSERV,
            "Loaded %d entries from keypin journal. "
            "Found %d corrupt lines, %d duplicates, and %d conflicts.",
            n_entries, n_corrupt_lines, n_duplicates, n_conflicts);
  }

  return 0;
}

/**
 * Load a journal from the file called <b>fname</b>. Return 0 on success,
 * -1 on failure.
 */
int
keypin_load_journal(const char *fname)
{
  tor_mmap_t *map = tor_mmap_file(fname);
  if (!map) {
    if (errno == ENOENT)
      return 0;
    else
      return -1;
  }
  int r = keypin_load_journal_impl(map->data, map->size, NULL, 1);
  tor_munmap_file(map);
  return r;
}

/**
 * Load a journal from the file specified by fname into a pruner, then delete
 * it and replace it with the pruned version.  Return 0 on success,
 * -1 on failure.
 */
int
keypin_prune_journal(const char *fname)
{
  keypin_journal_pruner_t *pruner = NULL;
  keypin_journal_line_t *l;
  tor_mmap_t *map;
  int fd = -1;

  /* Mmap the file */
  map = tor_mmap_file(fname);
  if (!map) {
    if (errno == ENOENT)
      return 0;
    else
      return -1;
  }

  /* Create a pruner */
  pruner = keypin_create_pruner();

  /* Prune it */
  int r = keypin_load_journal_impl(map->data, map->size, pruner, 0);
  /* Unmap it */
  tor_munmap_file(map);

  if (r == 0) {
    /*
     * Loading into the pruner succeeded; truncate the old file and emit
     *
     * The output should always be smaller than the original file was, but
     * under really pessimal circumstances, something else might gobble up
     * a lot of disk space before we're done emitting and we might fail to
     * emit and end up losing the journal.
     *
     * The alternative would be to emit to a temp file and then only delete
     * the old journal when we've written the new one, but then we might fail
     * to prune when disk space is tight.
     */
    fd = tor_open_cloexec(fname, O_WRONLY|O_TRUNC|O_BINARY, 0600);
    if (fd < 0)
      goto err;

    l = pruner->head;
    while (l) {
      if (write_all(fd, l->line, strlen(l->line), 0) < 0)
        goto err;
      if (write(fd, "\n", 1) < 1)
        goto err;

      l = l->next;
    }

    close(fd);
  }

  log_info(LD_DIRSERV,
           "Pruned key-pinning journal; %d lines make %d entries, dropped "
           "%d as corrupt, %d as conflicting and %d as duplicates",
           pruner->nlines, pruner->nentries,
           pruner->nlines_pruned_corrupt, pruner->nlines_pruned_conflict,
           pruner->nlines_pruned_duplicate);

  keypin_free_pruner(pruner);

  return 0;

 err:
  log_warn(LD_DIRSERV, "Error while pruning key-pinning "
           "journal %s: %s", fname, strerror(errno));

  if (fd >= 0) close(fd);
  if (pruner) keypin_free_pruner(pruner);

  return -1;
}

/** Parse a single keypinning journal line entry from <b>cp</b>.  The input
 * does not need to be NUL-terminated, but it <em>does</em> need to have
 * KEYPIN_JOURNAL_LINE_LEN -1 bytes available to read.  Return a new entry
 * on success, and NULL on failure.
 */
STATIC keypin_ent_t *
keypin_parse_journal_line(const char *cp)
{
  /* XXXX assumes !USE_OPENSSL_BASE64 */
  keypin_ent_t *ent = tor_malloc_zero(sizeof(keypin_ent_t));

  if (base64_decode((char*)ent->rsa_id, sizeof(ent->rsa_id),
             cp, BASE64_DIGEST_LEN) != DIGEST_LEN ||
      cp[BASE64_DIGEST_LEN] != ' ' ||
      base64_decode((char*)ent->ed25519_key, sizeof(ent->ed25519_key),
             cp+BASE64_DIGEST_LEN+1, BASE64_DIGEST256_LEN) != DIGEST256_LEN) {
    tor_free(ent);
    return NULL;
  } else {
    return ent;
  }
}

/** Remove all entries from the keypinning table.*/
void
keypin_clear(void)
{
  int bad_entries = 0;
  {
    keypin_ent_t **ent, **next, *this;
    for (ent = HT_START(rsamap, &the_rsa_map); ent != NULL; ent = next) {
      this = *ent;
      next = HT_NEXT_RMV(rsamap, &the_rsa_map, ent);

      keypin_ent_t *other_ent = HT_REMOVE(edmap, &the_ed_map, this);
      bad_entries += (other_ent != this);

      tor_free(this);
    }
  }
  bad_entries += HT_SIZE(&the_ed_map);

  HT_CLEAR(edmap,&the_ed_map);
  HT_CLEAR(rsamap,&the_rsa_map);

  if (bad_entries) {
    log_warn(LD_BUG, "Found %d discrepencies in the the keypin database.",
             bad_entries);
  }
}

/** Allocate a new pruner */

STATIC keypin_journal_pruner_t *
keypin_create_pruner(void)
{
  keypin_journal_pruner_t *p = NULL;

  p = tor_malloc_zero(sizeof(*p));
  HT_INIT(rsamap, &(p->pruner_rsamap));
  HT_INIT(edmap, &(p->pruner_edmap));

  return p;
}

/** Free a pruner and all associated structures */

STATIC void
keypin_free_pruner(keypin_journal_pruner_t *p)
{
  keypin_ent_t **i, *to_remove;
  keypin_journal_line_t *l, *nextl;
  int entries_removed = 0, lines_removed = 0;

  if (!p) return;

  /* First, free the entries */
  i = HT_START(rsamap, &(p->pruner_rsamap));
  while (i) {
    to_remove = *i;

    if (to_remove) {
      /* Get it out of edmap too if it's there */
      HT_REMOVE(edmap, &(p->pruner_edmap), to_remove);

      /* Unlink it from the line */
      if (to_remove->line_info) {
        tor_assert(to_remove->line_info->ent == to_remove);
        to_remove->line_info->ent = NULL;
        to_remove->line_info = NULL;
      }

      ++entries_removed;
    }

    i = HT_NEXT_RMV(rsamap, &(p->pruner_rsamap), i);

    /* Free it */
    tor_free(to_remove);
  }

  /* Iterate over edmap too, just in case */
  i = HT_START(edmap, &(p->pruner_edmap));
  while (i) {
    to_remove = *i;

    if (to_remove) {
      /* Get it out of rsamap too if it's there (but it shouldn't be) */
      HT_REMOVE(rsamap, &(p->pruner_rsamap), to_remove);

      /* Unlink it from the line */
      if (to_remove->line_info) {
        tor_assert(to_remove->line_info->ent == to_remove);
        to_remove->line_info->ent = NULL;
        to_remove->line_info = NULL;
      }

      ++entries_removed;
    }

    i = HT_NEXT_RMV(edmap, &(p->pruner_edmap), i);

    /* Free it */
    tor_free(to_remove);
  }

  HT_CLEAR(rsamap, &(p->pruner_rsamap));
  HT_CLEAR(edmap, &(p->pruner_edmap));

  /* Now walk the linked list and free everything */
  l = p->head;
  while (l) {
    /* Save a next pointer */
    nextl = l->next;

    /* Unlink l */
    if (l->next) l->next->prev = l->prev;
    else p->tail = l->prev;
    if (l->prev) l->prev->next = l->next;
    else p->head = l->next;
    l->next = l->prev = NULL;

    /* Free l */
    tor_free(l);

    ++lines_removed;

    /* Advance */
    l = nextl;
  }

  /* Consistency check on the counters */
  tor_assert(lines_removed == p->nlines);
  tor_assert(entries_removed == p->nentries);

  /* Now free the pruner itself */
  tor_free(p);
}

