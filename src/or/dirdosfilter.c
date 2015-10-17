/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include <math.h>
#include <time.h>

#define DIRDOSFILTER_PRIVATE
#include "or.h"
#include "channel.h"
#include "circuitlist.h"
#include "config.h"
#include "dirdosfilter.h"
#include "directory.h"
#include "nodelist.h"
#include "policies.h"

/**
 * \file dirdosfilter.c
 * \brief Code to count connections by origin to dir servers, to detect
 * DoS attempts.
 */

/*
 * Counters are exponentially-weighted moving averages of connection events;
 * for simplicity they all age at the same rate.  The dirdosfilter_bump_*
 * functions, except dirdosfilter_bump_circuit_begindir() which increments
 * a non-aging per-circuit counter, all find the relevant counter for this
 * connection attempt, and either increment it or return that incrementation
 * would put it over the configured threshold.
 *
 * It is important to the implementation that only one such counter match
 * each connection attempt; if more than one such filter applied, we might
 * increment one counter, and then reject the attempt due to hitting the
 * threshold on the second - we'd need a mechanism to back out the increment
 * on the earlier counters to support that case.
 *
 * We need a global list of all counters in use so that, if the config
 * option for the decay rate changes, we can update them all using the
 * old decay rate to the time of change, and then apply the new decay
 * rate going forward.  If we ever see time go backward when updating a
 * counter, we should treat it as zero time having elapsed, but reset the
 * saved time in the counter to the time just observed so it decays normally
 * from that point onward.
 *
 * XXX 1: this would benefit from having real monotonic time
 *
 * XXX 2: there is a similar idiom in circuitmux_ewma.c, but with a more
 *        ad-hoc approach to scale factor changes (I think it can calculate
 *        incorrectly in some cases); there might be a benefit to refactoring
 *        to use common EWMA counter code, but it would definitely not be
 *        acceptable to put all counters in a common decay rate pool; the
 *        cmux ones sometimes take their rate from the consensus.
 */

typedef struct {
  /*
   * Averaged rate of connection attempts:
   *
   *        / oo                              / oo
   * r(T) = |     f(T - t) e^(-lambda t) dt / | e^(-lambda t) dt
   *        / 0                               / 0
   *
   *               / oo
   *      = lambda |    f(T - t) e^(-lambda t) dt
   *               / 0
   *
   * Where f is the underlying signal (in this case a sum of Dirac deltas)
   * for each point at which the counter is bumped, and lambda is the decay
   * rate.
   *
   * This satisfies a differential equation, which is of more interest for
   * continuous inputs, but considering it for Dirac delta valued f(T) points
   * to our ultimate algorithm:
   *
   * dr/dT = lambda (f(T) - r(T))
   *
   * Suppose f(T) = delta(T); then for T < 0, we have r(T) = 0, and at T = 0
   * dr/dT = lambda delta(0), so we have a discontinuous jump up to r(0) =
   * lambda, then an exponential decay at rate lambda back down toward 0.
   * Our discrete 'bump' inputs are just a sum of delta functions, and so at
   * each bump of size B we add B * lambda.  Since we smoothly decay between
   * bumps, we can just store the value as of the most recent bump, and the
   * time of that bump, and then at the next we use the difference of
   * timestamps to age the old value before adding the new bump.
   */

  double rate; /* Value of r(t) as of last_adjusted_tick */
  time_t last_adjusted_tick; /* Time of last update */
} dirdosfilter_counter_t;

/*
 * Hash table entry for DIRIND_ONEHOP and DIRIND_DIRECT cases
 */
typedef struct dirdosfilter_counter_map_entry_s {
  HT_ENTRY(dirdosfilter_counter_map_entry_s) node;
  tor_addr_t src_addr;
  dirdosfilter_counter_t *counter;
} dirdosfilter_counter_map_entry_t;

/*
 * Keep a list of counters so we can do global updates when the decay rate
 * changes
 */
static smartlist_t *dirdosfilter_counters = NULL;

/*
 * Current global decay rate
 */
static double dirdosfilter_lambda = 1.0;

/*
 * Maps to counters by indirection type
 */

/** One counter for DIRIND_ANONYMOUS */
static dirdosfilter_counter_t *anon_counter = NULL;
/** One counter for DIRIND_ANON_DIRPORT */
static dirdosfilter_counter_t *anon_dirport_counter = NULL;

/** Hash table from src_addr to counters for DIRIND_DIRECT */
HT_HEAD(dirdosfilter_counter_map, dirdosfilter_counter_map_entry_s);

struct dirdosfilter_counter_map direct_counters = HT_INITIALIZER();
struct dirdosfilter_counter_map onehop_counters = HT_INITIALIZER();

/* Hash table related prototypes */
static INLINE unsigned dirdosfilter_counter_map_hash(
    const dirdosfilter_counter_map_entry_t *ent);
static INLINE int dirdosfilter_counter_map_eq(
    const dirdosfilter_counter_map_entry_t *a,
    const dirdosfilter_counter_map_entry_t *b);

HT_PROTOTYPE(dirdosfilter_counter_map,
             dirdosfilter_counter_map_entry_s,
             node,
             dirdosfilter_counter_map_hash,
             dirdosfilter_counter_map_eq);

static void dirdosfilter_compact_ht(struct dirdosfilter_counter_map *ht,
                                    double cutoff);

/* General prototypes */
static int dirdosfilter_bump_anon_dirport(
                  const tor_addr_t *dst_addr,
                  uint16_t dst_port);
static int dirdosfilter_bump_anon(void);
static int dirdosfilter_bump_circuit_begindir(
                  uint64_t channel_id,
                  circid_t circ_id);
static int dirdosfilter_bump_direct(
                  const tor_addr_t *src_addr,
                  const tor_addr_t *dst_addr,
                  uint16_t dst_port);
static int dirdosfilter_bump_onehop(const tor_addr_t *src_addr);
static int dirdosfilter_counter_map_bump(struct dirdosfilter_counter_map *ht,
                                         const tor_addr_t *src_addr,
                                         time_t now,
                                         double threshold);
static void dirdosfilter_counter_free(dirdosfilter_counter_t *ctr);
static int dirdosfilter_counter_increment_and_test_with_time(
                 dirdosfilter_counter_t *ctr,
                 double increment,
                 double threshold,
                 time_t now);
static int dirdosfilter_counter_increment_and_test(
                 dirdosfilter_counter_t *ctr,
                 double increment,
                 double threshold);
static void dirdosfilter_counter_increment_with_time(
                 dirdosfilter_counter_t *ctr,
                 double increment,
                 time_t now);
static void dirdosfilter_counter_increment(dirdosfilter_counter_t *ctr,
                                           double increment);
static dirdosfilter_counter_t * dirdosfilter_counter_new_with_time(
                  double r, time_t now);
static dirdosfilter_counter_t * dirdosfilter_counter_new(double r);
static void dirdosfilter_counter_update_all(time_t now);
static void dirdosfilter_counter_update(dirdosfilter_counter_t *ctr,
                                       time_t now);
static dir_indirection_t dirdosfilter_guess_indirection_begindir(
                  const tor_addr_t *src_addr);
static dir_indirection_t dirdosfilter_guess_indirection_dirport(
                  const tor_addr_t *src_addr,
                  const tor_addr_t *dst_addr,
                  uint16_t dst_port);
static dir_indirection_t dirdosfilter_guess_indirection(
                  const tor_addr_t *src_addr,
                  const tor_addr_t *dst_addr,
                  uint16_t dst_port,
                  uint8_t begindir);

/* Generate hash table functions */
HT_GENERATE2(dirdosfilter_counter_map,
             dirdosfilter_counter_map_entry_s,
             node,
             dirdosfilter_counter_map_hash,
             dirdosfilter_counter_map_eq,
             0.5,
             tor_reallocarray_,
             tor_free_);

/** Evaluate the hash function for this entry */
static INLINE unsigned
dirdosfilter_counter_map_hash(const dirdosfilter_counter_map_entry_t *ent)
{
  return (unsigned) tor_addr_hash(&(ent->src_addr));
}

/** Compare if two map entries have the same key */
static INLINE int
dirdosfilter_counter_map_eq(const dirdosfilter_counter_map_entry_t *a,
                            const dirdosfilter_counter_map_entry_t *b)
{
  return !tor_addr_compare(&a->src_addr, &b->src_addr, CMP_EXACT);
}

/**
 * Look up a counter in the hash table for this source IP, creating one
 * if none is present, and then increment-and-test it as with
 * dirdosfilter_counter_increment_and_test_with_time().
 */

static int 
dirdosfilter_counter_map_bump(struct dirdosfilter_counter_map *ht,
                              const tor_addr_t *src_addr,
                              time_t now,
                              double threshold)
{
  int rv;
  dirdosfilter_counter_t *ctr = NULL;
  dirdosfilter_counter_map_entry_t search, *hashent = NULL;

  tor_assert(ht != NULL);
  tor_assert(src_addr != NULL);

  /* Check if we already have a counter for this source address */
  tor_addr_copy(&(search.src_addr), src_addr);
  hashent = HT_FIND(dirdosfilter_counter_map, ht, &search);
  if (hashent) {
    /* Got one; pull out a pointer to it */
    ctr = hashent->counter;
  } else {
    /* No counter; allocate and insert one */
    hashent = tor_malloc_zero(sizeof(*hashent));
    tor_addr_copy(&(hashent->src_addr), src_addr);
    hashent->counter = dirdosfilter_counter_new_with_time(0.0, now);
    HT_INSERT(dirdosfilter_counter_map, ht, hashent);

    /* Save a pointer to the counter */
    ctr = hashent->counter;
  }

  /* Assert we did get a counter */
  tor_assert(ctr != NULL);

  rv = dirdosfilter_counter_increment_and_test_with_time(
      ctr,
      1.0, /* increment is 1.0; just the one incoming connection per call */
      threshold, /* threshold is passed in and depends on which ht */
      now);

  return rv;
}

/**
 * Free a dirdosfilter_counter_t and remove it from the list
 */
static void
dirdosfilter_counter_free(dirdosfilter_counter_t *ctr)
{
  tor_assert(ctr != NULL);

  smartlist_remove(dirdosfilter_counters, ctr);
  tor_free(ctr);
}

/**
 * Update the specified counter for the supplied timestamp, and increment
 * it if incrementation would not put it over the threshold.  Return 1 if
 * incremented, 0 otherwise.
 */

static int
dirdosfilter_counter_increment_and_test_with_time(dirdosfilter_counter_t *ctr,
                                                  double increment,
                                                  double threshold,
                                                  time_t now)
{
  double bump;

  tor_assert(ctr != NULL);

  dirdosfilter_counter_update(ctr, now);
  bump = increment * dirdosfilter_lambda;

  if (ctr->rate + bump <= threshold) {
    ctr->rate += bump;
    return 1;
  } else {
    return 0;
  }
}

/**
 * Update the specified counter, and increment it if incrementation would
 * not put it over the threshold.  Return 1 if incremented, 0 otherwise.
 */

static int
dirdosfilter_counter_increment_and_test(dirdosfilter_counter_t *ctr,
                                        double increment,
                                        double threshold)
{
  return dirdosfilter_counter_increment_and_test_with_time(ctr, increment,
      threshold, time(NULL));
}

/**
 * Update and increment the specified counter for the supplied timestamp
 */

static void
dirdosfilter_counter_increment_with_time(dirdosfilter_counter_t *ctr,
                                         double increment,
                                         time_t now) {
  tor_assert(ctr != NULL);

  dirdosfilter_counter_update(ctr, now);
  ctr->rate += increment * dirdosfilter_lambda;
}

/**
 * Update and increment the specified counter
 */

static void
dirdosfilter_counter_increment(dirdosfilter_counter_t *ctr,
                               double increment)
{
  dirdosfilter_counter_increment_with_time(ctr, increment, time(NULL));
}

/**
 * Allocate a new dirdosfilter_counter_t with initial value r and
 * timestamp t and add it to the list
 */

static dirdosfilter_counter_t *
dirdosfilter_counter_new_with_time(double r, time_t t)
{
  dirdosfilter_counter_t *ctr;

  ctr = tor_malloc_zero(sizeof(*ctr));
  ctr->rate = r;
  ctr->last_adjusted_tick = t;

  /* Make sure the list exists */
  if (!dirdosfilter_counters) {
    dirdosfilter_counters = smartlist_new();
  }

  smartlist_add(dirdosfilter_counters, ctr);

  return ctr;
}

/**
 * Allocate a new dirdosfilter_counter_t with initial value r and
 * add it to the list
 */

static dirdosfilter_counter_t *
dirdosfilter_counter_new(double r)
{
  dirdosfilter_counter_t *ctr;

  ctr = tor_malloc_zero(sizeof(*ctr));
  ctr->rate = r;
  ctr->last_adjusted_tick = time(NULL);

  /* Make sure the list exists */
  if (!dirdosfilter_counters) {
    dirdosfilter_counters = smartlist_new();
  }

  smartlist_add(dirdosfilter_counters, ctr);

  return ctr;
}

/**
 * Update all counters to the present time using the global decay rate
 * dirdosfilter_lambda
 */

static void
dirdosfilter_counter_update_all(time_t now)
{
  if (dirdosfilter_counters != NULL) {
    SMARTLIST_FOREACH_BEGIN(dirdosfilter_counters,
                            dirdosfilter_counter_t *,
                            ctr) {
      dirdosfilter_counter_update(ctr, now);
    } SMARTLIST_FOREACH_END(ctr);
  }
}

/**
 * Update the counter to the present time using the global decay rate
 * dirdosfilter_lambda
 */

static void
dirdosfilter_counter_update(dirdosfilter_counter_t *ctr,
                            time_t now)
{
  unsigned int elapsed;
  double scale;

  tor_assert(ctr != NULL);

  /* Check if we haven't gone backward */
  if (now >= ctr->last_adjusted_tick) {
    elapsed = now - ctr->last_adjusted_tick;
  } else {
    /* No adjustment if time jumps back, but update the stored timestamp */
    elapsed = 0;
  }

  /* Adjust rate */
  scale = exp(- ((double)elapsed) * dirdosfilter_lambda);
  ctr->rate *= scale;

  /* Update stored timestamp */
  ctr->last_adjusted_tick = now;
}

/**
 * Guess the indirection type for an incoming connection in the case that
 * it began with a begindir cell over a circuit.  See comments for
 * dirdosfilter_guess_indirection() below.
 */

static dir_indirection_t
dirdosfilter_guess_indirection_begindir(const tor_addr_t *src_addr)
{
  smartlist_t *nodes_with_src_addr = NULL;
  /*
   * Default to ONEHOP, guess ANONYMOUS if it looks like it came from
   * a relay.
   */
  dir_indirection_t guess = DIRIND_ONEHOP;

  tor_assert(src_addr);

  /*
   * if this connection came from a known relay, we'll assume it's
   * DIRIND_ANONYMOUS.
   */

  nodes_with_src_addr = nodelist_find_nodes_with_address(src_addr);
  if (nodes_with_src_addr) {
    /*
     * This node must have an IPv4 or IPv6 address that matched our src_addr;
     * we might get false negatives if a node has a NAT configuration such
     * that its outgoing connections appear to have a different address than
     * it advertises in its descriptor.  We might get more than one node here
     * if they have distinct ORPorts.  We might get false positives if a
     * client and a relay share an address and the begindir we got originated
     * from the client.
     *
     * We check the is_running and is_valid bits to see if this node might
     * plausibly have been used as a relay just now.  If any of the nodes
     * matching src_addr, which was the previous hop of a circuit that
     * just produced a begindir cell, we assume DIRIND_ANONYMOUS.
     */
    SMARTLIST_FOREACH_BEGIN(nodes_with_src_addr, const node_t *, n) {
      /*
       * If we have a routerstatus, check it too in case we are an authority
       * which disagrees with the consensus about flags.
       */
      if ((n->is_valid && n->is_running) ||
          (n->rs ? (n->rs->is_valid && n->rs->is_flagged_running) : 0)) {
        /*
         * Okay, we have a plausible previous hop for a DIRIND_ANONYMOUS
         * circuit.
         */
        guess = DIRIND_ANONYMOUS;
        break;
      }
    } SMARTLIST_FOREACH_END(n);
    smartlist_free(nodes_with_src_addr);
  }

  return guess;
}

/**
 * Guess the indirection type for an incoming connection in the case that
 * it began with a connection to the dirport.  See comments for
 * dirdosfilter_guess_indirection() below.
 */

static dir_indirection_t
dirdosfilter_guess_indirection_dirport(const tor_addr_t *src_addr,
                                       const tor_addr_t *dst_addr,
                                       uint16_t dst_port)
{
  smartlist_t *nodes_with_src_addr = NULL;
  /*
   * Default to DIRECT_CONN, guess ANON_DIRPORT if it looks like it came from
   * a relay with a compatible exit policy.
   */
  dir_indirection_t guess = DIRIND_DIRECT_CONN;
  addr_policy_result_t pol_match;

  tor_assert(src_addr);
  tor_assert(dst_addr);
  tor_assert(dst_port != 0);

  /*
   * if this connection came from a known relay with a compatible exit
   * policy for the dst_addr/dst_port, we'll assume it's DIRIND_ANON_DIRPORT.
   */

  nodes_with_src_addr = nodelist_find_nodes_with_address(src_addr);
  if (nodes_with_src_addr) {
    /*
     * This node must have an IPv4 or IPv6 address that matched our src_addr
     * (but see caveats above for dirdosfilter_guess_indirection_begindir();
     * we had a connection to dst_addr/dst_port, so for each node we have to
     * check if its exit policy could have originated that connection, as
     * well as checking is_running/is_valid as in the case of
     * dirdosfilter_guess_indirection_begindir().
     */
    SMARTLIST_FOREACH_BEGIN(nodes_with_src_addr, const node_t *, n) {
      /*
       * If we have a routerstatus, check it too in case we are an authority
       * which disagrees with the consensus about flags.
       */
      if ((n->is_valid && n->is_running) ||
          (n->rs ? (n->rs->is_valid && n->rs->is_flagged_running) : 0)) {
        /* Check if it matches the exit policy for n */
        pol_match = compare_tor_addr_to_node_policy(dst_addr, dst_port, n);
          if (pol_match == ADDR_POLICY_ACCEPTED ||
            pol_match == ADDR_POLICY_PROBABLY_ACCEPTED) {
          /* We have a plausible previous hop for DIRIND_ANON_DIRPORT */
          guess = DIRIND_ANON_DIRPORT;
          break;
        }
      }
    } SMARTLIST_FOREACH_END(n);
    smartlist_free(nodes_with_src_addr);
  }
  /* else no nodes at all at that src_addr, so must be DIRECT_CONN */

  return guess;
}

/**
 * For a given incoming directory connection, try to guess the indirection
 * type the client used.  The args are the same as for dirdosfilter_bump().
 *
 * We can classify incoming connections by whether they are for the dirport
 * or use the begindir mechanism, and whether they seem to be anonymized or
 * not.  The latter is necessarily approximate; the heuristic we use is to
 * assume connections originating from circuits with a previous hop which is
 * a relay in the current consensus are anonymized in the begindir case, and
 * from an origin IP which is a relay in the current consensus allowing exits
 * to our dirport in the case of direct connections.
 */

static dir_indirection_t
dirdosfilter_guess_indirection(const tor_addr_t *src_addr,
                  const tor_addr_t *dst_addr,
                  uint16_t dst_port,
                  uint8_t begindir)
{
  if (begindir) {
    /*
     * We're in DIRIND_ONEHOP or DIRIND_ANONYMOUS, depending on whether
     * src_addr is in the consensus.  If a relay in the consensus also
     * acts as a client this will misclassify DIRIND_ONEHOP as
     * DIRIND_ANONYMOUS.
     */
    return dirdosfilter_guess_indirection_begindir(src_addr);
  } else {
    /*
     * We're in DIRIND_DIRECT_CONN or DIRIND_ANON_DIRPORT, depending on
     * whether src_addr is in the consensus and exits to dst_addr/dst_port;
     * if a relay with this exit policy is in the consensus and also acts
     * as a client, this will misclassify DIRIND_DIRECT_CONN as
     * DIRIND_ANON_DIRPORT.
     */
    return dirdosfilter_guess_indirection_dirport(src_addr,
                                                  dst_addr, dst_port);
  }
}

/**
 * Bump the begindir counter for this circuit and return whether the
 * connection should be allowed through or not.
 */

static int
dirdosfilter_bump_circuit_begindir(uint64_t channel_id, circid_t circ_id)
{
  int allow_req = 1;
  channel_t *chan = NULL;
  circuit_t *circ = NULL;
  or_circuit_t *orcirc = NULL;
  uint32_t max_begindir_per_circuit =
    get_options()->DirDoSFilterMaxBegindirPerCircuit;

  /* First find the channel */
  chan = channel_find_by_global_id(channel_id);
  if (chan) {
    /* Now look for the circuit */
    circ = circuit_get_by_circid_channel(circ_id, chan);
    if (circ) {
      if (CIRCUIT_IS_ORCIRC(circ)) {
        orcirc = TO_OR_CIRCUIT(circ);
        /* Bump the begindir counter */
        ++(orcirc->dirdosfilter_begindir_count);
        if (orcirc->dirdosfilter_begindir_count >
            max_begindir_per_circuit) {
          log_info(LD_NET,
                   "Blocking over-threshold begindir (%u / %u) on circuit %u"
                   ", channel " U64_FORMAT,
                   (unsigned int)(orcirc->dirdosfilter_begindir_count),
                   (unsigned int)(max_begindir_per_circuit),
                   (unsigned int)(circ_id),
                   U64_PRINTF_ARG(channel_id));
          allow_req = 0;
        }
      } else {
        /* Block the request if we have no circuit */
        log_debug(LD_NET,
                  "Got a non-orcirc circuit %u on channel " U64_FORMAT
                  "; this is a bug",
                  (unsigned int)(circ_id), U64_PRINTF_ARG(channel_id));
        allow_req = 0;
      }
    } else {
      /* Block the request if we have no circuit */
      log_debug(LD_NET, "Couldn't find circuit %u on channel " U64_FORMAT,
                (unsigned int)(circ_id), U64_PRINTF_ARG(channel_id));
      allow_req = 0;
    }
  } else {
    /* Block the request if we have no channel (weird) */
    log_debug(LD_NET, "Couldn't find channel " U64_FORMAT,
              U64_PRINTF_ARG(channel_id));
    allow_req = 0;
  }

  return allow_req;
}

/**
 * Bump the counter for DIRIND_ANON_DIRPORT connections to this destination
 * address/port and return whether the connection should be allowed through
 * or not.
 */

static int
dirdosfilter_bump_anon_dirport(const tor_addr_t *dst_addr,
                               uint16_t dst_port)
{
  int rv;
  time_t now = time(NULL);
  const double max_anon_dirport_rate =
    get_options()->DirDoSFilterMaxAnonDirportConnectRate;

  tor_assert(dst_addr != NULL);

  if (!anon_dirport_counter) {
    anon_dirport_counter = dirdosfilter_counter_new_with_time(0.0, now);
  }

  rv = dirdosfilter_counter_increment_and_test_with_time(
      anon_dirport_counter,
      1.0, /* increment is 1.0; just the one incoming connection per call */
      max_anon_dirport_rate, /* threshold is max DIRIND_ANON_DIRPORT rate */
      now);

  return rv;
}

/**
 * Bump the counter for DIRIND_ANONYMOUS connections and return whether the
 * connection should be allowed through or not.
 */

static int
dirdosfilter_bump_anon(void)
{
  int rv;
  time_t now = time(NULL);
  const double max_anon_rate = get_options()->DirDoSFilterMaxAnonConnectRate;

  /* Set up the counter if we don't have one yet */
  if (!anon_counter) {
    anon_counter = dirdosfilter_counter_new_with_time(0.0, now);
  }

  rv = dirdosfilter_counter_increment_and_test_with_time(
      anon_counter,
      1.0, /* increment is 1.0; just the one incoming connection per call */
      max_anon_rate, /* threshold is max allowed rate of DIRIND_ANONYMOUS */
      now);

  return rv;
}

/**
 * Bump the counter for this direct connections from this source address to
 * this destination address/port, and return whether the connection should be
 * allowed through or not.
 */

static int
dirdosfilter_bump_direct(const tor_addr_t *src_addr,
                         const tor_addr_t *dst_addr,
                         uint16_t dst_port)
{
  time_t now = time(NULL);
  const double max_direct_rate =
    get_options()->DirDoSFilterMaxDirectConnRatePerIP;

  tor_assert(src_addr != NULL);
  tor_assert(dst_addr != NULL);

  return dirdosfilter_counter_map_bump(&direct_counters,
                                       src_addr, now, max_direct_rate);
}

/**
 * Bump the counter for DIRIND_ONEHOP connections from this source address
 * and return whether the connection should be allowed through or not.
 */

static int
dirdosfilter_bump_onehop(const tor_addr_t *src_addr)
{
  time_t now = time(NULL);
  const double max_onehop_rate =
    get_options()->DirDoSFilterMaxBegindirRatePerIP;

  tor_assert(src_addr != NULL);

  return dirdosfilter_counter_map_bump(&onehop_counters,
                                       src_addr, now, max_onehop_rate);
}

/**
 * Bump the appropriate counter for a new incoming connection and return
 * whether the connection should be allowed through the filter or not; this
 * is called on incoming connections from connection.c and connection_edge.c.
 *
 * Args:
 *
 *  const tor_addr_t *src_addr
 *    - If this came in on the dirport (DIRIND_DIRECT_CONN or
 *      DIRIND_ANON_DIRPORT), this is the source address for
 *      the TCP connection to the dirport.  We will try to classify
 *      which of these indirection types it is on the basis of whether
 *      the source is a relay allowing exits to our IP/dirport, and
 *      generically we may listen on more than one dirport, so the
 *      destination address and port of the connection are also passed
 *      in.
 *    - If this originated with a begindir cell (DIRIND_ANONYMOUS or
 *      DIRIND_ONEHOP), this is the address of the previous hop in the
 *      circuit.  In the DIRIND_ANONYMOUS case it will be a relay, and
 *      so we use membership in the current consensus to approximately
 *      classify these.
 *
 *  const tor_addr_t *dst_addr
 *  uint16_t dst_port
 *    - In the dirport cases, the destination address and port as described
 *      above under src_addr.  In the begindir cases, these should be NULL
 *      and zero.
 *
 *  uint8_t begindir
 *    - Did this request originated with a begindir cell (1) or a dirport
 *      connection (0)?
 *
 *  uint64_t channel_id
 *  circid_t circ_id
 *    - If begindir == 1, the channel global identifier and circuit ID the
 *      begindir cell was seen on; the (channel_id, circ_id) pair uniquely
 *      identifies a circuit over the lifetime of a Tor process.
 *    - If begindir == 0, these should be zero.
 */

int
dirdosfilter_bump(const tor_addr_t *src_addr,
                  const tor_addr_t *dst_addr,
                  uint16_t dst_port,
                  uint8_t begindir,
                  uint64_t channel_id,
                  circid_t circ_id)
{
  int res;
  dir_indirection_t ind;

  /* Argument validation asserts */

  tor_assert(src_addr); /* We must always have a source address */
  if (begindir) {
    /*
     * If we're using the begindir mechanism, this came in over a circuit
     * and there's no destination address, but we should have a channel
     * and circuit ID.
     */
    tor_assert(!dst_addr);
    tor_assert(dst_port == 0);
  } else {
    /*
     * No begindir, this came in on the dirport, so we must have a
     * destination address/port.
     */
    tor_assert(dst_addr);
    tor_assert(dst_port != 0);
  }

  /*
   * Guess what indirection type the incoming connection was using;
   * note that it's possible for this heuristic to be wrong in the case
   * of DIRIND_ONEHOP or DIRIND_DIRECT_CONN types originating from a
   * client which is also a relay in the current consensus.
   */
  ind = dirdosfilter_guess_indirection(src_addr, dst_addr, dst_port,
                                       begindir);
  switch (ind) {
    case DIRIND_DIRECT_CONN:
      tor_assert(dst_addr);
      tor_assert(dst_port != 0);
      log_debug(LD_DIR,
                "dirdosfilter sees a DIRIND_DIRECT_CONN from %s to %s",
                fmt_addr(src_addr), fmt_addrport(dst_addr, dst_port));
      /*
       * The direct case will need to hash the src address in to find a
       * counter per potential connection source.
       */
      res = dirdosfilter_bump_direct(src_addr, dst_addr, dst_port);
      break;
    case DIRIND_ANON_DIRPORT:
      tor_assert(dst_addr);
      tor_assert(dst_port != 0);
      log_debug(LD_DIR,
                "dirdosfilter sees a DIRIND_ANON_DIRPORT from %s to %s",
                fmt_addr(src_addr), fmt_addrport(dst_addr, dst_port));
      /*
       * ANON_DIRPORT case can only depend on dst port, but we pass those in
       * to leave room to make it possible to set different policy per port
       * if we listen on more than one.
       */
      res = dirdosfilter_bump_anon_dirport(dst_addr, dst_port);
      break;
    case DIRIND_ONEHOP:
      log_debug(LD_DIR,
                "dirdosfilter sees a DIRIND_ONEHOP from %s on channel ID "
                U64_FORMAT ", circuit ID %u",
                fmt_addr(src_addr),
                U64_PRINTF_ARG(channel_id), (unsigned int)(circ_id));
      /*
       * In the ONEHOP case, we could kill it because we have too many
       * recent attempts from this source address (as in DIRECT_CONN), or
       * we've seen too many begindirs on this circuit (and we should keep)
       * a counter in the circuit struct rather than messing with hash tables
       * for that.
       */
      res = dirdosfilter_bump_circuit_begindir(channel_id, circ_id);
      if (res > 0) {
        res = dirdosfilter_bump_onehop(src_addr);
      }
      break;
    case DIRIND_ANONYMOUS:
      log_debug(LD_DIR,
                "dirdosfilter sees a DIRIND_ANONYMOUS from %s on channel"
                " ID " U64_FORMAT ", circuit ID %u",
                fmt_addr(src_addr),
                U64_PRINTF_ARG(channel_id), (unsigned int)(circ_id));
      /* Like ONEHOP, but all anonymized circuits go in the same bucket */
      res = dirdosfilter_bump_circuit_begindir(channel_id, circ_id);
      if (res > 0) {
        res = dirdosfilter_bump_anon();
      }
      break;
    default:
      log_notice(LD_BUG,
                 "dirdosfilter_guess_indirection() returned a weird "
                 "indirection type %d; filter will ignore this",
                 (int)(ind));
      res = 1;
  }

  return res;
}

/**
 * Compact ht by removing all counters below cutoff
 */

static void
dirdosfilter_compact_ht(struct dirdosfilter_counter_map *ht, double cutoff)
{
  dirdosfilter_counter_map_entry_t **i;
  dirdosfilter_counter_t *counter;

  tor_assert(ht != NULL);

  i = HT_START(dirdosfilter_counter_map, ht);
  while (i) {
    counter = (*i != NULL) ? ((*i)->counter) : NULL;

    if (!counter) {
      log_warn(LD_BUG, "Somehow, an HT iterator gave us a NULL counter.");
      break;
    } else {
      if (counter->rate < cutoff) {
        /* Remove this entry */
        i = HT_NEXT_RMV(dirdosfilter_counter_map, ht, i);
        dirdosfilter_counter_free(counter);
      } else {
        /* Keep this one, go to the next */
        i = HT_NEXT(dirdosfilter_counter_map, ht, i);
      }
    }
  }
}

/**
 * Compact the hash tables by removing entries that have decayed close to
 * zero.
 */
void
dirdosfilter_compact(void)
{
  const double direct_conn_drop_cutoff = 
    0.01 * (get_options()->DirDoSFilterMaxDirectConnRatePerIP);
  const double onehop_drop_cutoff = 
    0.01 * (get_options()->DirDoSFilterMaxBegindirRatePerIP);

  /* First, update everything */
  dirdosfilter_counter_update_all(approx_time());
  /* Next, compact both hash tables */
  dirdosfilter_compact_ht(&direct_counters, direct_conn_drop_cutoff);
  dirdosfilter_compact_ht(&onehop_counters, onehop_drop_cutoff);
}

/**
 * Free all dirdosfilter.c data structures before exit
 */
void
dirdosfilter_free_all(void)
{
  /* Free counter for DIRIND_ANONYMOUS */
  if (anon_counter != NULL) {
    dirdosfilter_counter_free(anon_counter);
    anon_counter = NULL;
  }

  /* Free counter for DIRIND_ANON_DIRPORT */
  if (anon_dirport_counter != NULL) {
    dirdosfilter_counter_free(anon_dirport_counter);
    anon_dirport_counter = NULL;
  }

  /* Clear the hash tables; we'll get the counters themselves next */
  dirdosfilter_counter_map_HT_CLEAR(&direct_counters);
  dirdosfilter_counter_map_HT_CLEAR(&onehop_counters);

  /* Free all remaining rate counters */
  if (dirdosfilter_counters != NULL) {
    SMARTLIST_FOREACH_BEGIN(dirdosfilter_counters,
                            dirdosfilter_counter_t *,
                            ctr) {
      free(ctr);
    } SMARTLIST_FOREACH_END(ctr);

    smartlist_free(dirdosfilter_counters);
    dirdosfilter_counters = NULL;
  }
}

/**
 * Adjust the time constant, on config updates
 */

void
dirdosfilter_set_time_constant(double t)
{
  /* t must be positive */
  tor_assert(t > 0.0);

  /*
   * Get the time and do updates
   *
   * XXX something monotonic would be nice
   */
  dirdosfilter_counter_update_all(time(NULL));

  /* Change the rate */
  dirdosfilter_lambda = 1.0 / t;

  log_debug(LD_DIR,
            "dirdosfilter_lambda is now %f",
            dirdosfilter_lambda);
}

