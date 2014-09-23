/* * Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file scheduler.c
 * \brief Relay scheduling system
 **/

#include "or.h"

#define TOR_CHANNEL_INTERNAL_ /* For channel_flush_some_cells() */
#include "channel.h"

#include "compat_libevent.h"
#include "scheduler.h"

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/event.h>
#else
#include <event.h>
#endif

#define SCHED_Q_LOW_WATER 16384
#define SCHED_Q_HIGH_WATER (2 * SCHED_Q_LOW_WATER)

/*
 * Write scheduling works by keeping track of lists of channels that can
 * accept cells, and have cells to write.  From the scheduler's perspective,
 * a channel can be in four possible states:
 *
 * 1.) Not open for writes, no cells to send
 *     - Not much to do here, and the channel will appear in neither list.
 *     - Transitions from:
 *       - Open for writes/has cells by simultaneously draining all circuit
 *         queues and filling the output buffer.
 *     - Transitions to:
 *       - Not open for writes/has cells by arrival of cells on an attached
 *         circuit (this would be driven from append_cell_to_circuit_queue())
 *       - Open for writes/no cells by a channel type specific path;
 *         driven from connection_or_flushed_some() for channel_tls_t.
 *
 * 2.) Open for writes, no cells to send
 *     - Not much here either; this will be the state an idle but open channel
 *       can be expected to settle in.
 *     - Transitions from:
 *       - Not open for writes/no cells by flushing some of the output
 *         buffer.
 *       - Open for writes/has cells by the scheduler moving cells from
 *         circuit queues to channel output queue, but not having enough
 *         to fill the output queue.
 *     - Transitions to:
 *       - Open for writes/has cells by arrival of new cells on an attached
 *         circuit, in append_cell_to_circuit_queue()
 *
 * 3.) Not open for writes, cells to send
 *     - This is the state of a busy circuit limited by output bandwidth;
 *       cells have piled up in the circuit queues waiting to be relayed.
 *     - Transitions from:
 *       - Not open for writes/no cells by arrival of cells on an attached
 *         circuit
 *       - Open for writes/has cells by filling an output buffer without
 *         draining all cells from attached circuits
 *    - Transitions to:
 *       - Opens for writes/has cells by draining some of the output buffer
 *         via the connection_or_flushed_some() path (for channel_tls_t).
 *
 * 4.) Open for writes, cells to send
 *     - This connection is ready to relay some cells and waiting for
 *       the scheduler to choose it
 *     - Transitions from:
 *       - Not open for writes/has cells by the connection_or_flushed_some()
 *         path
 *       - Open for writes/no cells by the append_cell_to_circuit_queue()
 *         path
 *     - Transitions to:
 *       - Not open for writes/no cells by draining all circuit queues and
 *         simultaneously filling the output buffer.
 *       - Not open for writes/has cells by writing enough cells to fill the
 *         output buffer
 *       - Open for writes/no cells by draining all attached circuit queues
 *         without also filling the output buffer
 *
 * Other event-driven parts of the code move channels between these scheduling
 * states by calling scheduler functions; the scheduler only runs on open-for-
 * writes/has-cells channels and is the only path for those to transition to
 * other states.  The scheduler_run() function gives us the opportunity to do
 * scheduling work, and is called from other scheduler functions whenever a
 * state transition occurs, and periodically from the main event loop.
 */

/* Scheduler global data structures */

/*
 * We keep lists of channels that either have cells queued, can accept
 * writes, or both (states 2, 3 and 4 above) - no explicit list of state
 * 1 channels is kept, so we don't have to worry about registering new
 * channels here or anything.  The scheduler will learn about them when
 * it needs to.  We can check how many channels in state 4 in O(1), so
 * the test whether we have anything to do in scheduler_run() is fast
 * and there's no harm in calling it opportunistically whenever we get
 * the chance.
 *
 * Note that it takes time O(n) to search for a channel in these smartlists
 * or move one; I don't think the number of channels on a relay will be large
 * enough for this to be a severe problem, but this would benefit from using
 * a doubly-linked list rather than smartlist_t, together with a hash map from
 * channel identifiers to pointers to list entries, so we can perform those
 * operations in O(log(n)).
 */

/* List of channels that can write but have no cells (state 2 above) */
static smartlist_t *channels_waiting_for_cells = NULL;

/* List of channels with cells waiting to write (state 3 above) */
static smartlist_t *channels_waiting_to_write = NULL;

/* List of channels that can write and have cells (pending work) */
static smartlist_t *channels_pending = NULL;

/*
 * This event runs the scheduler from its callback, and is manually
 * activated whenever a channel enters open for writes/cells to send.
 */

static struct event *run_sched_ev = NULL;

/*
 * Queue heuristic; this is not the queue size, but an 'effective queuesize'
 * that ages out contributions from stalled channels.
 */

static uint64_t queue_heuristic = 0;

/*
 * Timestamp for last queue heuristic update
 */

static time_t queue_heuristic_timestamp = 0;

/* Scheduler static function declarations */

static void scheduler_evt_callback(evutil_socket_t fd,
                                   short events, void *arg);
static int scheduler_more_work(void);
static void scheduler_retrigger(void);
#if 0
static void scheduler_trigger(void);
#endif
static uint64_t scheduler_get_queue_heuristic(void);
static void scheduler_update_queue_heuristic(time_t now);

/* Scheduler function implementations */

/** Free everything and shut down the scheduling system */

void
scheduler_free_all(void)
{
  log_debug(LD_SCHED, "Shutting down scheduler");

  if (run_sched_ev) {
    event_del(run_sched_ev);
    tor_event_free(run_sched_ev);
    run_sched_ev = NULL;
  }

  if (channels_waiting_for_cells) {
    smartlist_free(channels_waiting_for_cells);
    channels_waiting_for_cells = NULL;
  }

  if (channels_waiting_to_write) {
    smartlist_free(channels_waiting_to_write);
    channels_waiting_to_write = NULL;
  }

  if (channels_pending) {
    smartlist_free(channels_pending);
    channels_pending = NULL;
  }
}

/*
 * Scheduler event callback; this should get triggered once per event loop
 * if any scheduling work was created during the event loop.
 */

static void
scheduler_evt_callback(evutil_socket_t fd, short events, void *arg)
{
  (void)fd;
  (void)events;
  (void)arg;
  log_debug(LD_SCHED, "Scheduler event callback called");

  tor_assert(run_sched_ev);

  /* Run the scheduler */
  scheduler_run();

  /* Do we have more work to do? */
  if (scheduler_more_work()) scheduler_retrigger();
}

/** Mark a channel as no longer ready to accept writes */

void
scheduler_channel_doesnt_want_writes(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(channels_waiting_for_cells);
  tor_assert(channels_waiting_to_write);
  tor_assert(channels_pending);

  /* If it's already in pending, we can put it in waiting_to_write */
  if (smartlist_contains(channels_pending, chan)) {
    /*
     * It's in channels_pending, so it shouldn't be in any of
     * the other lists.  It can't write any more, so it goes to
     * channels_waiting_to_write.
     */
    smartlist_remove(channels_pending, chan);
    smartlist_add(channels_waiting_to_write, chan);
    log_debug(LD_SCHED,
              "Channel " U64_FORMAT " at %p went from pending "
              "to waiting_to_write",
              U64_PRINTF_ARG(chan->global_identifier), chan);
  } else {
    /*
     * It's not in pending, so it can't become waiting_to_write; it's
     * either not in any of the lists (nothing to do) or it's already in
     * waiting_for_cells (remove it, can't write any more).
     */
    if (smartlist_contains(channels_waiting_for_cells, chan)) {
      smartlist_remove(channels_waiting_for_cells, chan);
      log_debug(LD_SCHED,
                "Channel " U64_FORMAT " at %p left waiting_for_cells",
                U64_PRINTF_ARG(chan->global_identifier), chan);
    }
  }
}

/** Mark a channel as having waiting cells */

void
scheduler_channel_has_waiting_cells(channel_t *chan)
{
  int became_pending = 0;

  tor_assert(chan);
  tor_assert(channels_waiting_for_cells);
  tor_assert(channels_waiting_to_write);
  tor_assert(channels_pending);

  /* First, check if this one also writeable */
  if (smartlist_contains(channels_waiting_for_cells, chan)) {
    /*
     * It's in channels_waiting_for_cells, so it shouldn't be in any of
     * the other lists.  It has waiting cells now, so it goes to
     * channels_pending.
     */
    smartlist_remove(channels_waiting_for_cells, chan);
    smartlist_add(channels_pending, chan);
    log_debug(LD_SCHED,
              "Channel " U64_FORMAT " at %p went from waiting_for_cells "
              "to pending",
              U64_PRINTF_ARG(chan->global_identifier), chan);
    became_pending = 1;
  } else {
    /*
     * It's not in waiting_for_cells, so it can't become pending; it's
     * either not in any of the lists (we add it to waiting_to_write)
     * or it's already in waiting_to_write or pending (we do nothing)
     */
    if (!(smartlist_contains(channels_waiting_to_write, chan) ||
          smartlist_contains(channels_pending, chan))) {
      smartlist_add(channels_waiting_to_write, chan);
      log_debug(LD_SCHED,
                "Channel " U64_FORMAT " at %p entered waiting_to_write",
                U64_PRINTF_ARG(chan->global_identifier), chan);
    }
  }

  /*
   * If we made a channel pending, we potentially have scheduling work
   * to do.
   */
  if (became_pending) scheduler_retrigger();
}

/** Set up the scheduling system */

void
scheduler_init(void)
{
  log_debug(LD_SCHED, "Initting scheduler");

  tor_assert(!run_sched_ev);
  run_sched_ev = tor_event_new(tor_libevent_get_base(), -1,
                               0, scheduler_evt_callback, NULL);

  channels_waiting_for_cells = smartlist_new();
  channels_waiting_to_write = smartlist_new();
  channels_pending = smartlist_new();
  queue_heuristic = 0;
  queue_heuristic_timestamp = approx_time();
}

/** Check if there's more scheduling work */

static int
scheduler_more_work(void)
{
  tor_assert(channels_pending);

  return ((scheduler_get_queue_heuristic() < SCHED_Q_LOW_WATER) &&
          ((smartlist_len(channels_pending) > 0))) ? 1 : 0;
}

/** Retrigger the scheduler in a way safe to use from the callback */

static void
scheduler_retrigger(void)
{
  tor_assert(run_sched_ev);
  event_active(run_sched_ev, EV_TIMEOUT, 1);
}

/** Notify the scheduler of a channel being closed */

void
scheduler_release_channel(channel_t *chan)
{
  tor_assert(chan);

  tor_assert(channels_waiting_for_cells);
  tor_assert(channels_waiting_to_write);
  tor_assert(channels_pending);

  smartlist_remove(channels_waiting_for_cells, chan);
  smartlist_remove(channels_waiting_to_write, chan);
  smartlist_remove(channels_pending, chan);
}

/** Run the scheduling algorithm if necessary */

void
scheduler_run(void)
{
  log_debug(LD_SCHED, "We have a chance to run the scheduler");
  smartlist_t *tmp = NULL;
  int n_cells, n_chans_before, n_chans_after;
  uint64_t q_len_before, q_heur_before, q_len_after, q_heur_after;
  ssize_t flushed, flushed_this_time;

  if (scheduler_get_queue_heuristic() < SCHED_Q_LOW_WATER) {
    n_chans_before = smartlist_len(channels_pending);
    q_len_before = channel_get_global_queue_estimate();
    q_heur_before = scheduler_get_queue_heuristic();
    tmp = channels_pending;
    channels_pending = smartlist_new();

    /*
     * For now, just run the old scheduler on all the chans in the list, until
     * we hit the high-water mark.  TODO real channel priority API
     */

    SMARTLIST_FOREACH_BEGIN(tmp, channel_t *, chan) {
      if (scheduler_get_queue_heuristic() <= SCHED_Q_HIGH_WATER) {
        n_cells = channel_num_cells_writeable(chan);
        if (n_cells > 0) {
          log_debug(LD_SCHED,
                    "Scheduler saw pending channel " U64_FORMAT " at %p with "
                    "%d cells writeable",
                    U64_PRINTF_ARG(chan->global_identifier), chan, n_cells);

          flushed = 0;
          while (flushed < n_cells) {
            flushed_this_time =
              channel_flush_some_cells(chan, n_cells - flushed);
            if (flushed_this_time <= 0) break;
            flushed += flushed_this_time;
          }

          log_debug(LD_SCHED,
                    "Scheduler flushed %d cells onto pending channel "
                    U64_FORMAT " at %p",
                    flushed, U64_PRINTF_ARG(chan->global_identifier), chan);
        } else {
          log_info(LD_SCHED,
                   "Scheduler saw pending channel " U64_FORMAT " at %p with "
                   "no cells writeable",
                   U64_PRINTF_ARG(chan->global_identifier), chan);
        }
      } else {
        /* Not getting it this round; put it back on the list */
        smartlist_add(channels_pending, chan);
      }
    } SMARTLIST_FOREACH_END(chan);

    smartlist_free(tmp);

    n_chans_after = smartlist_len(channels_pending);
    q_len_after = channel_get_global_queue_estimate();
    q_heur_after = scheduler_get_queue_heuristic();
    log_debug(LD_SCHED,
              "Scheduler handled %d of %d pending channels, queue size from "
              U64_FORMAT " to " U64_FORMAT ", queue heuristic from "
              U64_FORMAT " to " U64_FORMAT,
              n_chans_before - n_chans_after, n_chans_before,
              U64_PRINTF_ARG(q_len_before), U64_PRINTF_ARG(q_len_after),
              U64_PRINTF_ARG(q_heur_before), U64_PRINTF_ARG(q_heur_after));
  }
}

/** Trigger the scheduling event so we run the scheduler later */

#if 0
static void
scheduler_trigger(void)
{
  log_debug(LD_SCHED, "Triggering scheduler event");

  tor_assert(run_sched_ev);

  event_add(run_sched_ev, EV_TIMEOUT, 1);
}
#endif

/** Mark a channel as ready to accept writes */

void
scheduler_channel_wants_writes(channel_t *chan)
{
  int became_pending = 0;

  tor_assert(chan);
  tor_assert(channels_waiting_for_cells);
  tor_assert(channels_waiting_to_write);
  tor_assert(channels_pending);

  /* If it's already in waiting_to_write, we can put it in pending */
  if (smartlist_contains(channels_waiting_to_write, chan)) {
    /*
     * It's in channels_waiting_to_write, so it shouldn't be in any of
     * the other lists.  It can write now, so it goes to channels_pending.
     */
    smartlist_remove(channels_waiting_to_write, chan);
    smartlist_add(channels_pending, chan);
    log_debug(LD_SCHED,
              "Channel " U64_FORMAT " at %p went from waiting_to_write "
              "to pending",
              U64_PRINTF_ARG(chan->global_identifier), chan);
    became_pending = 1;
  } else {
    /*
     * It's not in waiting_to_write, so it can't become pending; it's
     * either not in any of the lists (we add it to waiting_for_cells)
     * or it's already in waiting_for_cells or pending (we do nothing)
     */
    if (!(smartlist_contains(channels_waiting_for_cells, chan) ||
          smartlist_contains(channels_pending, chan))) {
      smartlist_add(channels_waiting_for_cells, chan);
      log_debug(LD_SCHED,
                "Channel " U64_FORMAT " at %p entered waiting_for_cells",
                U64_PRINTF_ARG(chan->global_identifier), chan);
    }
  }

  /*
   * If we made a channel pending, we potentially have scheduling work
   * to do.
   */
  if (became_pending) scheduler_retrigger();
}

/**
 * Notify the scheduler of a queue size adjustment, to recalculate the
 * queue heuristic.
 */

void
scheduler_adjust_queue_size(channel_t *chan, char dir, uint64_t adj)
{
  time_t now = approx_time();

  /* Get the queue heuristic up to date */
  scheduler_update_queue_heuristic(now);

  /* Adjust as appropriate */
  if (dir >= 0) {
    /* Increasing it */
    queue_heuristic += adj;
  } else {
    /* Decreasing it */
    if (queue_heuristic > adj) queue_heuristic -= adj;
    else queue_heuristic = 0;
  }

  log_debug(LD_SCHED,
            "Queue heuristic is now " U64_FORMAT,
            U64_PRINTF_ARG(queue_heuristic));
}

/**
 * Query the current value of the queue heuristic
 */

static uint64_t
scheduler_get_queue_heuristic(void)
{
  time_t now = approx_time();

  scheduler_update_queue_heuristic(now);

  return queue_heuristic;
}

/**
 * Adjust the queue heuristic value to the present time
 */

static void
scheduler_update_queue_heuristic(time_t now)
{
  time_t diff;

  if (queue_heuristic_timestamp == 0) {
    /*
     * Nothing we can sensibly do; must not have been initted properly.
     * Oh well.
     */
    queue_heuristic_timestamp = now;
  } else if (queue_heuristic_timestamp < now) {
    diff = now - queue_heuristic_timestamp;
    /*
     * This is a simple exponential age-out; the other proposed alternative
     * was a linear age-out using the bandwidth history in rephist.c; I'm
     * going with this out of concern that if an adversary can jam the
     * scheduler long enough, it would cause the bandwidth to drop to
     * zero and render the aging mechanism ineffective thereafter.
     */
    if (0 <= diff && diff < 64) queue_heuristic >>= diff;
    else queue_heuristic = 0;

    queue_heuristic_timestamp = now;

    log_debug(LD_SCHED,
              "Queue heuristic is now " U64_FORMAT,
              U64_PRINTF_ARG(queue_heuristic));
  }
  /* else no update needed, or time went backward */
}

