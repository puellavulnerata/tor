/* * Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux_wait_time.c
 * \brief Wait-time circuit selection as a circuitmux_t policy
 **/

#define TOR_CIRCUITMUX_WAIT_TIME_C_

#include "or.h"
#include "circuitmux.h"
#include "circuitmux_wait_time.h"

/** Wait-time policy forward typedefs */

typedef struct wt_policy_data_s wt_policy_data_t;
typedef struct wt_policy_circ_data_s wt_policy_circ_data_t;

/*** Wait-time policy methods ***/

static circuitmux_policy_data_t * wt_alloc_cmux_data(circuitmux_t *cmux);
static void wt_free_cmux_data(circuitmux_t *cmux,
                              circuitmux_policy_data_t *pol_data);
static circuitmux_policy_circ_data_t *
wt_alloc_circ_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data,
                   circuit_t *circ, cell_direction_t direction,
                   unsigned int cell_count);
static void
wt_free_circ_data(circuitmux_t *cmux,
                  circuitmux_policy_data_t *pol_data,
                  circuit_t *circ,
                  circuitmux_policy_circ_data_t *pol_circ_data);
static void
wt_notify_circ_active(circuitmux_t *cmux,
                      circuitmux_policy_data_t *pol_data,
                      circuit_t *circ,
                      circuitmux_policy_circ_data_t *pol_circ_data);
static void
wt_notify_circ_inactive(circuitmux_t *cmux,
                        circuitmux_policy_data_t *pol_data,
                        circuit_t *circ,
                        circuitmux_policy_circ_data_t *pol_circ_data);
static void
wt_set_n_cells(circuitmux_t *cmux,
               circuitmux_policy_data_t *pol_data,
               circuit_t *circ,
               circuitmux_policy_circ_data_t *pol_circ_data,
               unsigned int n_cells);
static void
wt_notify_xmit_cells(circuitmux_t *cmux,
                     circuitmux_policy_data_t *pol_data,
                     circuit_t *circ,
                     circuitmux_policy_circ_data_t *pol_circ_data,
                     unsigned int n_cells);
static circuit_t *
wt_pick_active_circuit(circuitmux_t *cmux,
                       circuitmux_policy_data_t *pol_data);

/** Helper function declarations */

static unsigned int WT_NEXT_ALLOC_THRESHOLD(unsigned int n);
static int compare_timevals(struct timeval t1, struct timeval t2);
static int compare_wt_policy_circ_data(const void *p1, const void *p2);
static void wt_grow_time_buffer(wt_policy_circ_data_t *cdata,
                                unsigned int n_cells);
static void wt_shrink_time_buffer(wt_policy_circ_data_t *cdata,
                                  unsigned int n_cells);

/*** Wait-time circuitmux_policy_t method table ***/

circuitmux_policy_t wt_policy = {
  /*.alloc_cmux_data =*/ wt_alloc_cmux_data,
  /*.free_cmux_data =*/ wt_free_cmux_data,
  /*.alloc_circ_data =*/ wt_alloc_circ_data,
  /*.free_circ_data =*/ wt_free_circ_data,
  /*.notify_circ_active =*/ wt_notify_circ_active,
  /*.notify_circ_inactive =*/ wt_notify_circ_inactive,
  /*.notify_set_n_cells =*/ wt_set_n_cells,
  /*.notify_xmit_cells =*/ wt_notify_xmit_cells,
  /*.pick_active_circuit =*/ wt_pick_active_circuit
};

/** Structs internal to wait-time policy */

/** Wait-time policy instance-wide data */

struct wt_policy_data_s {
  circuitmux_policy_data_t base_;

  /**
   * Priority queue of circuits with queued cells waiting
   * for room to free up on the channel that owns this circuitmux.  Kept
   * in heap order according to max cell wait time.
   */
  smartlist_t *active_circuit_pqueue;
};

/** Wait-time per circuit data */

struct wt_policy_circ_data_s {
  circuitmux_policy_circ_data_t base_;

  /** Circuit this is for */
  circuit_t *circ;

  /**
   * Index into wt_policy_data_t's priority queue, or -1 if this circuit is
   * not active.
   */
  int heap_index;

  /** Number of queued cells/stored wait times we have */
  unsigned int n_cells;

  /** Number of allocated timeval slots */
  unsigned int n_alloced;

  /* Time at which queued cells were queued ordered oldest first */
  struct timeval *timevals;
};

#define WT_POL_DATA_MAGIC 0x356307f8U
#define WT_POL_CIRC_DATA_MAGIC 0xc44ab92aU

/*** Downcasts for the above types ***/

static wt_policy_data_t *
TO_WT_POL_DATA(circuitmux_policy_data_t *);

static wt_policy_circ_data_t *
TO_WT_POL_CIRC_DATA(circuitmux_policy_circ_data_t *);

/**
 * Downcast a circuitmux_policy_data_t to a wt_policy_data_t and assert
 * if the cast is impossible.
 */

static INLINE wt_policy_data_t *
TO_WT_POL_DATA(circuitmux_policy_data_t *pol)
{
  if (!pol) return NULL;
  else {
    tor_assert(pol->magic == WT_POL_DATA_MAGIC);
    return DOWNCAST(wt_policy_data_t, pol);
  }
}

/**
 * Downcast a circuitmux_policy_circ_data_t to a wt_policy_circ_data_t
 * and assert if the cast is impossible.
 */

static INLINE wt_policy_circ_data_t *
TO_WT_POL_CIRC_DATA(circuitmux_policy_circ_data_t *pol)
{
  if (!pol) return NULL;
  else {
    tor_assert(pol->magic == WT_POL_CIRC_DATA_MAGIC);
    return DOWNCAST(wt_policy_circ_data_t, pol);
  }
}

/** Wait-time cmux policy helper functions */

/**
 * Pick the next timeval buffer size larger than n; we grow
 * buffers in power-of-2 sizes to limit the number of reallocs.
 * I think this will probably break if n is maxint; lots of other
 * things will also suck badly if that happens.
 */

static INLINE unsigned int
WT_NEXT_ALLOC_THRESHOLD(unsigned int n)
{
  unsigned int rv = 1;

  while (rv < n) rv <<= 1;

  return rv;
}

/**
 * Compare two timevals to sort in order of which is earlier;
 * return -1 if t1 is earlier than t2, 0 if they are equal and
 * 1 if t2 is earlier than t1.
 */

static int
compare_timevals(struct timeval t1, struct timeval t2)
{
  if (t1.tv_sec < t2.tv_sec) {
    return -1;
  } else if (t1.tv_sec > t2.tv_sec) {
    return 1;
  } else {
    /* t1.tv_sec == t2.tv_sec */
    if (t1.tv_usec < t2.tv_usec) {
      return -1;
    } else if (t1.tv_usec > t2.tv_usec) {
      return 1;
    } else {
      /* t1.tv_usec == t2.tv_usec too */
      return 0;
    }
  }
}

/**
 * Grow the list of timevals in cdata by n_cells, and fill in the new
 * slots with the current time.  This is used when queueing new cells for
 * a circuit.
 */

static void
wt_grow_time_buffer(wt_policy_circ_data_t *cdata,
                    unsigned int n_cells)
{
  unsigned int next_alloc, i;
  struct timeval now;

  tor_assert(cdata);

  /* Do we need to do anything? */
  if (n_cells == 0) return;

  /* Do we need to grow the buffer? */
  if (cdata->n_cells + n_cells > cdata->n_alloced) {
    /* Expand it up to the next threshold */
    next_alloc = WT_NEXT_ALLOC_THRESHOLD(cdata->n_cells + n_cells);
    /* Reallocing or first time? */
    if (cdata->n_cells > 0) {
      tor_assert(cdata->timevals != NULL);
      cdata->timevals =
        tor_realloc(cdata->timevals,
                    sizeof(*(cdata->timevals)) * next_alloc);
    } else {
      tor_assert(cdata->timevals == NULL);
      cdata->timevals = tor_malloc(sizeof(*(cdata->timevals)) * next_alloc);
    }
    cdata->n_alloced = next_alloc;
  }

  /* Now get the time to fill in */
  tor_gettimeofday(&now);

  /* Copy it into the newly allocated slots */
  for (i = 0; i < n_cells; ++i) {
    memcpy(&(cdata->timevals[cdata->n_cells + i]), &now, sizeof(now));
  }

  /* Adjust the counter */
  cdata->n_cells += n_cells;
}

/**
 * Shrink the list of timevals in cdata by n_cells, removing the oldest
 * cells first.  This is used when transmitting cells for a circuit.
 */

static void
wt_shrink_time_buffer(wt_policy_circ_data_t *cdata,
                      unsigned int n_cells)
{
  unsigned int next_alloc;

  tor_assert(cdata);
  tor_assert(n_cells <= cdata->n_cells);

  /* Do we need to do anything? */
  if (n_cells == 0) return;

  /* Move back n_cells slots and adjust the counter */
  if (cdata->n_cells > 0) {
    tor_assert(cdata->timevals);
    if (n_cells < cdata->n_cells) {
      memmove(cdata->timevals, &(cdata->timevals[n_cells]),
              sizeof(*(cdata->timevals)) * (cdata->n_cells - n_cells));
      cdata->n_cells -= n_cells;
    } else {
      /*
       * We're consuming all of them; we can just set the counter
       * to zero and free the buffer.
       */
      tor_free(cdata->timevals);
      cdata->n_cells = 0;
      cdata->n_alloced = 0;
    }
  }

  /* Do we want to shrink the buffer? */
  if (cdata->timevals) {
    next_alloc = WT_NEXT_ALLOC_THRESHOLD(cdata->n_cells);
    if (next_alloc < cdata->n_alloced) {
      /* Yes, shrink it */
      cdata->timevals =
        tor_realloc(cdata->timevals,
                    sizeof(*(cdata->timevals)) * next_alloc);
    }
  }
}

/**
 * Compare two wt_policy_circ_data_t structures to sort the queue;
 * this returns -1 if p1 should sort earlier (be higher priority
 * than) p2, 1 if it should sort later and 0 if they have equal
 * priority.
 */

static int
compare_wt_policy_circ_data(const void *p1, const void *p2)
{
  const wt_policy_circ_data_t *wt1 = p1, *wt2 = p2;

  /*
   * Sort based on the time of the oldest cell, except that a circuit
   * with no queued cells always sorts last.
   */

  if (wt1->n_cells > 0) {
    if (wt2->n_cells > 0) {
      /* Both are non-empty; go by oldest cell */
      return compare_timevals(wt1->timevals[0], wt2->timevals[1]);
    } else {
      /* wt2 has 0 cells, wt1 is non-empty */
      return -1;
    }
  } else {
    /*
     * wt1 has 0 cells, so it's safe to sort it after wt2 whether or not
     * wt2 has any cells.
     */
    return 1;
  }
}

/** CMux policy method implementations */

/** Allocate a new wt_policy_data_t */

static circuitmux_policy_data_t *
wt_alloc_cmux_data(circuitmux_t *cmux)
{
  wt_policy_data_t *pol = NULL;

  tor_assert(cmux);

  pol = tor_malloc_zero(sizeof(*pol));
  pol->base_.magic = WT_POL_DATA_MAGIC;
  pol->active_circuit_pqueue = smartlist_new();

  return TO_CMUX_POL_DATA(pol);
}

/** Free a wt_policy_data_t */

static void
wt_free_cmux_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data)
{
  wt_policy_data_t *pol = NULL;

  tor_assert(cmux);
  if (!pol_data) return;

  pol = TO_WT_POL_DATA(pol_data);

  smartlist_free(pol->active_circuit_pqueue);
  tor_free(pol);
}

/**
 * Allocate a wt_policy_circ_data_t and upcast it to a
 * circuitmux_policy_data_t; this is called when attaching a circuit to a
 * circuitmux_t with wt_policy.
 */

static circuitmux_policy_circ_data_t *
wt_alloc_circ_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data,
                   circuit_t *circ, cell_direction_t direction,
                   unsigned int cell_count)
{
  wt_policy_circ_data_t *cdata = NULL;
  struct timeval now;
  unsigned int i;

  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(direction == CELL_DIRECTION_IN ||
             direction == CELL_DIRECTION_OUT);

  cdata = tor_malloc_zero(sizeof(*cdata));
  cdata->base_.magic = WT_POL_CIRC_DATA_MAGIC;
  cdata->circ = circ;

  /* If we get an initial cell count, use the time of allocation */
  if (cell_count > 0) {
    cdata->n_cells = cell_count;
    cdata->n_alloced = WT_NEXT_ALLOC_THRESHOLD(cell_count);
    cdata->timevals =
      tor_malloc(sizeof(*(cdata->timevals)) * cdata->n_alloced);
    /* Get current time to fill in */
    tor_gettimeofday(&now);
    /* Copy it in cell_count times */
    for (i = 0; i < cdata->n_cells; ++i) {
      memcpy(&(cdata->timevals[i]), &now, sizeof(now));
    }
  } else {
    cdata->n_cells = 0;
    cdata->n_alloced = 0;
    cdata->timevals = NULL;
  }

  /* Circuits are initially inactive */
  cdata->heap_index = -1;

  return TO_CMUX_POL_CIRC_DATA(cdata);
}

/**
 * Free a wt_policy_circ_data_t allocated with wt_alloc_circ_data()
 */

static void
wt_free_circ_data(circuitmux_t *cmux,
                  circuitmux_policy_data_t *pol_data,
                  circuit_t *circ,
                  circuitmux_policy_circ_data_t *pol_circ_data)
{
  wt_policy_circ_data_t *cdata = NULL;

  tor_assert(cmux);
  tor_assert(circ);
  tor_assert(pol_data);

  if (!pol_circ_data) return;

  cdata = TO_WT_POL_CIRC_DATA(pol_circ_data);

  /* If we have timevals, free them */
  tor_free(cdata->timevals);

  tor_free(cdata);
}

/** Make a circuit active */

static void
wt_notify_circ_active(circuitmux_t *cmux,
                      circuitmux_policy_data_t *pol_data,
                      circuit_t *circ,
                      circuitmux_policy_circ_data_t *pol_circ_data)
{
  wt_policy_data_t *pol = NULL;
  wt_policy_circ_data_t *cdata = NULL;

  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  pol = TO_WT_POL_DATA(pol_data);
  cdata = TO_WT_POL_CIRC_DATA(pol_circ_data);

  tor_assert(pol->active_circuit_pqueue);
  tor_assert(cdata->heap_index == -1);

  /* Add to the pqueue using our selected comparator */
  smartlist_pqueue_add(pol->active_circuit_pqueue,
                       compare_wt_policy_circ_data,
                       STRUCT_OFFSET(wt_policy_circ_data_t, heap_index),
                       cdata);
}

/** Make a circuit inactive */

static void
wt_notify_circ_inactive(circuitmux_t *cmux,
                        circuitmux_policy_data_t *pol_data,
                        circuit_t *circ,
                        circuitmux_policy_circ_data_t *pol_circ_data)
{
  wt_policy_data_t *pol = NULL;
  wt_policy_circ_data_t *cdata = NULL;

  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  pol = TO_WT_POL_DATA(pol_data);
  cdata = TO_WT_POL_CIRC_DATA(pol_circ_data);

  tor_assert(pol->active_circuit_pqueue);
  tor_assert(cdata->heap_index != -1);

  /* Remove this from the pqueue */
  smartlist_pqueue_remove(pol->active_circuit_pqueue,
                          compare_wt_policy_circ_data,
                          STRUCT_OFFSET(wt_policy_circ_data_t, heap_index),
                          cdata);
}

/**
 * Update the cell count for a circuit
 */

static void
wt_set_n_cells(circuitmux_t *cmux,
               circuitmux_policy_data_t *pol_data,
               circuit_t *circ,
               circuitmux_policy_circ_data_t *pol_circ_data,
               unsigned int n_cells)
{
  wt_policy_data_t *pol = NULL;
  wt_policy_circ_data_t *cdata = NULL;
  int need_readd = 0;

  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  pol = TO_WT_POL_DATA(pol_data);
  cdata = TO_WT_POL_CIRC_DATA(pol_circ_data);

  /* Are we shrinking or growing the cell count? */
  if (n_cells > cdata->n_cells) {
    /*
     * We're growing it; this is the typical case of new cells being
     * queued.
     *
     * We only need to readd if there were already cells; otherwise the
     * oldest cell time is unchanged.
     *
     * Assumption here: time is monotonic; this might produce odd but
     * transient behavior in the case of the clock being set back; it'd
     * be nice if we could count on clock_gettime(CLOCK_MONOTONIC, ...)
     * being available instead.
     */

    if (cdata->n_cells > 0) {
      need_readd = 1;
    }
    wt_grow_time_buffer(cdata, n_cells - cdata->n_cells);
  } else if (n_cells < cdata->n_cells) {
    /*
     * Not sure this can ever happen, but the implementation handles it
     * on the assumption that it's equivalent to transmitting the cells, so
     * we discard the oldest values first.
     */

    need_readd = 1;
    wt_shrink_time_buffer(cdata, cdata->n_cells - n_cells);
  }
  /* else no change, so it's a no-op */

  if (need_readd) {
    /* Remove it and then add it back to update its queue position */
    smartlist_pqueue_remove(pol->active_circuit_pqueue,
                            compare_wt_policy_circ_data,
                            STRUCT_OFFSET(wt_policy_circ_data_t, heap_index),
                            cdata);
    smartlist_pqueue_add(pol->active_circuit_pqueue,
                         compare_wt_policy_circ_data,
                         STRUCT_OFFSET(wt_policy_circ_data_t, heap_index),
                         cdata);
  }
}

/**
 * Update the circuit's cell queue time history after transmitting some cells
 */

static void
wt_notify_xmit_cells(circuitmux_t *cmux,
                     circuitmux_policy_data_t *pol_data,
                     circuit_t *circ,
                     circuitmux_policy_circ_data_t *pol_circ_data,
                     unsigned int n_cells)
{
  wt_policy_data_t *pol = NULL;
  wt_policy_circ_data_t *cdata = NULL, *tmp;
  int need_readd = 0;

  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  pol = TO_WT_POL_DATA(pol_data);
  cdata = TO_WT_POL_CIRC_DATA(pol_circ_data);

  if (n_cells > 0) {
    /* Grow the buffer with the new cell times */
    wt_grow_time_buffer(cdata, n_cells);
    need_readd = 1;
  }

  if (need_readd) {
    /*
     * Since we just sent on this circuit, it should be at the head of
     * the queue.  Pop the head, assert that it matches, then re-add.
     */
    tmp = smartlist_pqueue_pop(pol->active_circuit_pqueue,
                               compare_wt_policy_circ_data,
                               STRUCT_OFFSET(wt_policy_circ_data_t,
                                             heap_index));
    tor_assert(tmp == cdata);
    smartlist_pqueue_add(pol->active_circuit_pqueue,
                         compare_wt_policy_circ_data,
                         STRUCT_OFFSET(wt_policy_circ_data_t, heap_index),
                         cdata);
  }
}

/**
 * Pick the preferred circuit to send from; this will be the one with
 * the oldest queued cell.
 */

static circuit_t *
wt_pick_active_circuit(circuitmux_t *cmux,
                       circuitmux_policy_data_t *pol_data)
{
  wt_policy_data_t *pol = NULL;
  wt_policy_circ_data_t *cdata = NULL;
  circuit_t *circ = NULL;

  tor_assert(cmux);
  tor_assert(pol_data);

  pol = TO_WT_POL_DATA(pol_data);

  if (smartlist_len(pol->active_circuit_pqueue) > 0) {
    /* Grab the head of the queue and return its circuit */
    cdata = smartlist_get(pol->active_circuit_pqueue, 0);
    circ = cdata->circ;
  }

  return circ;
}

