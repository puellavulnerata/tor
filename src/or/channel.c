/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channel.c
 * \brief OR-to-OR channel abstraction layer
 **/

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */

#define _TOR_CHANNEL_INTERNAL

#include "or.h"
#include "channel.h"
#include "channeltls.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "geoip.h"
#include "relay.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"

/* Cell queue structure */

typedef struct cell_queue_entry_s cell_queue_entry_t;
struct cell_queue_entry_s {
  enum {
    CELL_QUEUE_FIXED,
    CELL_QUEUE_VAR,
    CELL_QUEUE_PACKED
  } type;
  union {
    struct {
      cell_t *cell;
    } fixed;
    struct {
      var_cell_t *var_cell;
    } var;
    struct {
      packed_cell_t *packed_cell;
    } packed;
  } u;
};

/* Global lists of channels */

/* All channel_t instances */
static smartlist_t *all_channels = NULL;

/* All channel_t instances not in ERROR or CLOSED states */
static smartlist_t *active_channels = NULL;

/* All channel_t instances in LISTENING state */
static smartlist_t *listening_channels = NULL;

/* All channel_t instances in ERROR or CLOSED states */
static smartlist_t *finished_channels = NULL;

/* Counter for ID numbers */
static uint64_t n_channels_allocated = 0;

/** Digest->channel map
 *
 * Similar to the one used in connection_or.c, this maps from the identity
 * digest of a remote endpoint to a channel_t to that endpoint.  Channels
 * should be placed here when registered and removed when they close or error.
 * If more than one channel exists, follow the next_with_same_id pointer
 * as a linked list.
 */
static digestmap_t *channel_identity_map = NULL;

/* Functions to maintain the digest map */
static void channel_add_to_digest_map(channel_t *chan);
static void channel_remove_from_digest_map(channel_t *chan);

/*
 * Flush cells from just the outgoing queue without trying to get them
 * from circuits; used internall by channel_flush_some_cells().
 */
static ssize_t
channel_flush_some_cells_from_outgoing_queue(channel_t *chan,
                                             ssize_t num_cells);

/** Indicate whether a given channel state is valid
 */

int
channel_state_is_valid(channel_state_t state)
{
  int is_valid;

  switch (state) {
    case CHANNEL_STATE_CLOSED:
    case CHANNEL_STATE_CLOSING:
    case CHANNEL_STATE_ERROR:
    case CHANNEL_STATE_LISTENING:
    case CHANNEL_STATE_MAINT:
    case CHANNEL_STATE_OPENING:
    case CHANNEL_STATE_OPEN:
      is_valid = 1;
      break;
    case CHANNEL_STATE_LAST:
    default:
      is_valid = 0;
  }

  return is_valid;
}

/** Indicate whether a channel state transition is valid (see the state
 * definitions and transition table in or.h at the channel_state_t typedef).
 */

int
channel_state_can_transition(channel_state_t from, channel_state_t to)
{
  int is_valid;

  switch (from) {
    case CHANNEL_STATE_CLOSED:
      is_valid = (to == CHANNEL_STATE_LISTENING ||
                  to == CHANNEL_STATE_OPENING);
      break;
    case CHANNEL_STATE_CLOSING:
      is_valid = (to == CHANNEL_STATE_CLOSED ||
                  to == CHANNEL_STATE_ERROR);
      break;
    case CHANNEL_STATE_ERROR:
      is_valid = 0;
      break;
    case CHANNEL_STATE_LISTENING:
      is_valid = (to == CHANNEL_STATE_CLOSING ||
                  to == CHANNEL_STATE_ERROR);
      break;
    case CHANNEL_STATE_MAINT:
      is_valid = (to == CHANNEL_STATE_CLOSING ||
                  to == CHANNEL_STATE_ERROR ||
                  to == CHANNEL_STATE_OPEN);
      break;
    case CHANNEL_STATE_OPENING:
      is_valid = (to == CHANNEL_STATE_CLOSING ||
                  to == CHANNEL_STATE_ERROR ||
                  to == CHANNEL_STATE_OPEN);
      break;
    case CHANNEL_STATE_OPEN:
      is_valid = (to == CHANNEL_STATE_CLOSING ||
                  to == CHANNEL_STATE_ERROR ||
                  to == CHANNEL_STATE_MAINT);
      break;
    case CHANNEL_STATE_LAST:
    default:
      is_valid = 0;
  }

  return is_valid;
}

/** Return a human-readable description for a channel state
 */

const char *
channel_state_to_string(channel_state_t state)
{
  const char *descr;

  switch (state) {
    case CHANNEL_STATE_CLOSED:
      descr = "closed";
      break;
    case CHANNEL_STATE_CLOSING:
      descr = "closing";
      break;
    case CHANNEL_STATE_ERROR:
      descr = "channel error";
      break;
    case CHANNEL_STATE_LISTENING:
      descr = "listening";
      break;
    case CHANNEL_STATE_MAINT:
      descr = "temporarily suspended for maintenance";
      break;
    case CHANNEL_STATE_OPENING:
      descr = "opening";
      break;
    case CHANNEL_STATE_OPEN:
      descr = "open";
      break;
    case CHANNEL_STATE_LAST:
    default:
      descr = "unknown or invalid channel state";
  }

  return descr;
}

/******************************
 * Channel refcount functions *
 ******************************/

/** Increment the refcount of a channel_t instance */
channel_t *
channel_ref(channel_t *chan)
{
  tor_assert(chan);

  ++(chan->refcount);

  return chan;
}

/** Return the number of references to a channel_t instance */
size_t
channel_num_refs(channel_t *chan)
{
  tor_assert(chan);

  return chan->refcount;
}

/** Decrement the refcount of a channel_t instance */
void
channel_unref(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(chan->refcount > 0);

  --(chan->refcount);

  /*
   * If the refcount goes to zero, the channel is finished and the channel
   * is not registered, we can free it.
   */

  if (chan->refcount == 0 && !(chan->registered) &&
      (chan->state == CHANNEL_STATE_CLOSED ||
       chan->state == CHANNEL_STATE_ERROR)) {
    channel_free(chan);
  }
}

/***************************************
 * Channel registration/unregistration *
 ***************************************/

void
channel_register(channel_t *chan)
{
  tor_assert(chan);

  /* No-op if already registered */
  if (chan->registered) return;

  log_debug(LD_CHANNEL,
            "Registering channel %p in state %s (%d) with digest %s",
            chan, channel_state_to_string(chan->state), chan->state,
            hex_str(chan->identity_digest, DIGEST_LEN));

  /* Make sure we have all_channels, then add it */
  if (!all_channels) all_channels = smartlist_new();
  smartlist_add(all_channels, chan);

  /* Is it finished? */
  if (chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) {
    /* Put it in the finished list, creating it if necessary */
    if (!finished_channels) finished_channels = smartlist_new();
    smartlist_add(finished_channels, chan);
  } else {
    /* Put it in the active list, creating it if necessary */
    if (!active_channels) active_channels = smartlist_new();
    smartlist_add(active_channels, chan);

    /* Is it a listener? */
    if (chan->state == CHANNEL_STATE_LISTENING) {
      /* Put it in the listening list, creating it if necessary */
      if (!listening_channels) listening_channels = smartlist_new();
      smartlist_add(listening_channels, chan);
    } else if (chan->state != CHANNEL_STATE_CLOSING) {
      /* It should have a digest set */
      if (!tor_digest_is_zero(chan->identity_digest)) {
        /* Yeah, we're good, add it to the map */
        channel_add_to_digest_map(chan);
      } else {
        log_info(LD_CHANNEL,
                 "Channel in state %s registered with no identity digest",
                 channel_state_to_string(chan->state));
      }
    }
  }

  /* Mark it as registered */
  chan->registered = 1;
}

void
channel_unregister(channel_t *chan)
{
  tor_assert(chan);

  /* No-op if not registered */
  if (!(chan->registered)) return;

  /* Is it finished? */
  if (chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) {
    /* Get it out of the finished list */
    if (finished_channels) smartlist_remove(finished_channels, chan);
  } else {
    /* Get it out of the active list */
    if (active_channels) smartlist_remove(active_channels, chan);

    /* Is it listening? */
    if (chan->state == CHANNEL_STATE_LISTENING) {
      /* Get it out of the listening list */
      if (listening_channels) smartlist_remove(listening_channels, chan);
    }
  }

  /* Get it out of all_channels */
 if (all_channels) smartlist_remove(all_channels, chan);

  /* Mark it as unregistered */
  chan->registered = 0;

  /* Should it be in the digest map? */
  if (!tor_digest_is_zero(chan->identity_digest) &&
      !(chan->state == CHANNEL_STATE_LISTENING ||
        chan->state == CHANNEL_STATE_CLOSING ||
        chan->state == CHANNEL_STATE_CLOSED ||
        chan->state == CHANNEL_STATE_ERROR)) {
    /* Remove it */
    channel_remove_from_digest_map(chan);
  }

  /* If the refcount is also zero and it's finished, we can free it now */
  if (chan->refcount == 0 &&
      (chan->state == CHANNEL_STATE_CLOSED ||
       chan->state == CHANNEL_STATE_ERROR)) {
    channel_free(chan);
  }
}

/*********************************
 * Channel digest map maintenance
 *********************************/

static void
channel_add_to_digest_map(channel_t *chan)
{
  channel_t *tmp;

  tor_assert(chan);
  /* Assert that the state makes sense */
  tor_assert(!(chan->state == CHANNEL_STATE_LISTENING ||
               chan->state == CHANNEL_STATE_CLOSING ||
               chan->state == CHANNEL_STATE_CLOSED ||
               chan->state == CHANNEL_STATE_ERROR));
  /* Assert that there is a digest */
  tor_assert(!tor_digest_is_zero(chan->identity_digest));

  /* Allocate the identity map if we have to */
  if (!channel_identity_map) channel_identity_map = digestmap_new();

  /* Insert it */
  tmp = digestmap_set(channel_identity_map, chan->identity_digest, chan);
  if (tmp) {
    /* There already was one, this goes at the head of the list */
    chan->next_with_same_id = tmp;
    chan->prev_with_same_id = NULL;
    tmp->prev_with_same_id = chan;
  } else {
    /* First with this digest */
    chan->next_with_same_id = NULL;
    chan->prev_with_same_id = NULL;
  }

  log_debug(LD_CHANNEL,
            "Added channel %p (%lu) to identity map in state %s (%d) "
            "with digest %s",
            chan, chan->global_identifier,
            channel_state_to_string(chan->state), chan->state,
            hex_str(chan->identity_digest, DIGEST_LEN));
}

static void
channel_remove_from_digest_map(channel_t *chan)
{
  channel_t *tmp, *head;
  tor_assert(chan);
  /* Assert that there is a digest */
  tor_assert(!tor_digest_is_zero(chan->identity_digest));

  /* Make sure we have a map */
  if (!channel_identity_map) {
    /*
     * No identity map, so we can't find it by definition.  This
     * case is similar to digestmap_get() failing below.
     */
    log_warn(LD_BUG,
             "Trying to remove channel %p (%lu) with digest %s from "
             "identity map, but didn't have any identity map",
             chan, chan->global_identifier,
             hex_str(chan->identity_digest, DIGEST_LEN));
    /* Clear out its next/prev pointers */
    if (chan->next_with_same_id)
      chan->next_with_same_id->prev_with_same_id = chan->prev_with_same_id;
    if (chan->prev_with_same_id)
      chan->prev_with_same_id->next_with_same_id = chan->next_with_same_id;
    chan->next_with_same_id = NULL;
    chan->prev_with_same_id = NULL;

    return;
  }

  /* Look for it in the map */
  tmp = digestmap_get(channel_identity_map, chan->identity_digest);
  if (tmp) {
    /* Okay, it's here */
    head = tmp; /* Keep track of list head */
    /* Look for this channel */
    while (tmp && tmp != chan) tmp = tmp->next_with_same_id;
    if (tmp == chan) {
      /* Found it, good */
      if (chan->next_with_same_id) {
        chan->next_with_same_id->prev_with_same_id = chan->prev_with_same_id;
      }
      /* else we're the tail of the list */
      if (chan->prev_with_same_id) {
        /* We're not the head of the list, so we can *just* unlink */
        chan->prev_with_same_id->next_with_same_id = chan->next_with_same_id;
      } else {
        /* We're the head, so we have to point the digest map entry at our
         * next if we have one, or remove it if we're also the tail */
        if (chan->next_with_same_id) {
          digestmap_set(channel_identity_map, chan->identity_digest,
                        chan->next_with_same_id);
        } else {
          digestmap_remove(channel_identity_map, chan->identity_digest);
        }
      }

      /* NULL out its next/prev pointers, and we're finished */
      chan->next_with_same_id = NULL;
      chan->prev_with_same_id = NULL;

      log_debug(LD_CHANNEL,
                "Removed channel %p (%lu) from identity map in state %s (%d) "
                "with digest %s",
                chan, chan->global_identifier,
                channel_state_to_string(chan->state), chan->state,
                hex_str(chan->identity_digest, DIGEST_LEN));
    } else {
      /* This is not good */
      log_warn(LD_BUG,
               "Trying to remove channel %p (%lu) with digest %s from "
               "identity map, but couldn't find it in the list for that "
               "digest",
               chan, chan->global_identifier,
               hex_str(chan->identity_digest, DIGEST_LEN));
      /* Unlink it and hope for the best */
      if (chan->next_with_same_id)
        chan->next_with_same_id->prev_with_same_id = chan->prev_with_same_id;
      if (chan->prev_with_same_id)
        chan->prev_with_same_id->next_with_same_id = chan->next_with_same_id;
      chan->next_with_same_id = NULL;
      chan->prev_with_same_id = NULL;
    }
  } else {
    /* Shouldn't happen */
    log_warn(LD_BUG,
             "Trying to remove channel %p (%lu) with digest %s from "
             "identity map, but couldn't find any with that digest",
             chan, chan->global_identifier,
             hex_str(chan->identity_digest, DIGEST_LEN));
    /* Clear out its next/prev pointers */
    if (chan->next_with_same_id)
      chan->next_with_same_id->prev_with_same_id = chan->prev_with_same_id;
    if (chan->prev_with_same_id)
      chan->prev_with_same_id->next_with_same_id = chan->next_with_same_id;
    chan->next_with_same_id = NULL;
    chan->prev_with_same_id = NULL;
  }
}

/** These are for looking up registered channels by various things;
 * the channel_t returned is refcounted and should be unrefed when the
 * caller is done with it.
 */

channel_t *
channel_find_by_global_id(uint64_t global_identifier)
{
  channel_t *rv = NULL;

  if (all_channels && smartlist_len(all_channels) > 0) {
    SMARTLIST_FOREACH_BEGIN(all_channels, channel_t *, curr) {
      if (curr->global_identifier == global_identifier) {
        rv = channel_ref(curr);
        break;
      }
    } SMARTLIST_FOREACH_END(curr);
  }

  return rv;
}

channel_t *
channel_find_by_remote_digest(char *identity_digest)
{
  channel_t *rv = NULL, *tmp;

  tor_assert(identity_digest);

  /* Search for it in the identity map */
  if (channel_identity_map) {
    tmp = digestmap_get(channel_identity_map, identity_digest);
    /* Ref it */
    rv = channel_ref(tmp);
  }

  return rv;
}

channel_t *
channel_find_by_remote_nickname(char *nickname)
{
  channel_t *rv = NULL;

  tor_assert(nickname);

  if (all_channels && smartlist_len(all_channels) > 0) {
    SMARTLIST_FOREACH_BEGIN(all_channels, channel_t *, curr) {
      if (strncmp(curr->nickname, nickname, MAX_NICKNAME_LEN) == 0) {
        rv = channel_ref(curr);
        break;
      }
    } SMARTLIST_FOREACH_END(curr);
  }

  return rv;
}

/** Channel digest list-walkers; the *_unref versions also unref their
 * argument */

channel_t *
channel_next_with_digest(channel_t *chan)
{
  channel_t *rv = NULL;

  tor_assert(chan);
  if (chan->next_with_same_id) rv = channel_ref(chan->next_with_same_id);

  return rv;
}

channel_t *
channel_next_with_digest_unref(channel_t *chan)
{
  channel_t *rv = NULL;

  tor_assert(chan);
  if (chan->next_with_same_id) rv = channel_ref(chan->next_with_same_id);
  channel_unref(chan);

  return rv;
}

channel_t *
channel_prev_with_digest(channel_t *chan)
{
  channel_t *rv = NULL;

  tor_assert(chan);
  if (chan->prev_with_same_id) rv = channel_ref(chan->prev_with_same_id);

  return rv;
}

channel_t *
channel_prev_with_digest_unref(channel_t *chan)
{
  channel_t *rv = NULL;

  tor_assert(chan);
  if (chan->prev_with_same_id) rv = channel_ref(chan->prev_with_same_id);
  channel_unref(chan);

  return rv;
}

/** Internal-only channel init function
 */

void
channel_init(channel_t *chan)
{
  tor_assert(chan);

  /* Assign an ID and bump the counter */
  chan->global_identifier = n_channels_allocated++;

  /* Init timestamp */
  chan->timestamp_last_added_nonpadding = time(NULL);

  /* Init next_circ_id */
  chan->next_circ_id = crypto_rand_int(1 << 15);

  /* Timestamp it */
  channel_timestamp_created(chan);
}

/** Internal-only channel free function
 */

void
channel_free(channel_t *chan)
{
  tor_assert(chan);
  /* It must be closed or errored */
  tor_assert(chan->state == CHANNEL_STATE_CLOSED ||
             chan->state == CHANNEL_STATE_ERROR);
  /* It must be deregistered */
  tor_assert(!(chan->registered));
  /* It must have no refs */
  tor_assert(chan->refcount == 0);

  /* Call a free method if there is one */
  if (chan->free) chan->free(chan);

  channel_clear_remote_end(chan);

  smartlist_free(chan->active_circuit_pqueue);
  /* TODO cell queue? */

  tor_free(chan);
}

/** Return the current registered listener for a channel
 */

void
(* channel_get_listener(channel_t *chan))
  (channel_t *, channel_t *)
{
  tor_assert(chan);

  if (chan->state == CHANNEL_STATE_LISTENING) return chan->listener;
  else return NULL;
}

/** Set the listener for a channel
 */

void
channel_set_listener(channel_t *chan,
                     void (*listener)(channel_t *, channel_t *) )
{
  tor_assert(chan);
  tor_assert(chan->state == CHANNEL_STATE_LISTENING);

  log_debug(LD_CHANNEL,
           "Setting listener callback for channel %p to %p",
           chan, listener);

  chan->listener = listener;
  if (chan->listener) channel_process_incoming(chan);
}

/** Return the fixed-length cell handler for a channel
 */

void
(* channel_get_cell_handler(channel_t *chan))
  (channel_t *, cell_t *)
{
  tor_assert(chan);

  if (chan->state == CHANNEL_STATE_OPENING ||
      chan->state == CHANNEL_STATE_OPEN ||
      chan->state == CHANNEL_STATE_MAINT) {
    return chan->cell_handler;
  } else {
    return NULL;
  }
}

/** Return the variable-length cell handler for a channel
 */

void
(* channel_get_var_cell_handler(channel_t *chan))
  (channel_t *, var_cell_t *)
{
  tor_assert(chan);

  if (chan->state == CHANNEL_STATE_OPENING ||
      chan->state == CHANNEL_STATE_OPEN ||
      chan->state == CHANNEL_STATE_MAINT) {
    return chan->var_cell_handler;
  } else {
    return NULL;
  }
}

/** Set the fixed-length cell handler for a channel
 */

void
channel_set_cell_handler(channel_t *chan,
                         void (*cell_handler)(channel_t *, cell_t *))
{
  int changed = 0;

  tor_assert(chan);
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
           "Setting cell_handler callback for channel %p to %p",
           chan, cell_handler);

  /*
   * Keep track whether we've changed it so we know if there's any point in
   * re-running the queue.
   */
  if (cell_handler != chan->cell_handler) changed = 1;

  /* Change it */
  chan->cell_handler = cell_handler;

  /* Re-run the queue if we have one and there's any reason to */
  if (chan->cell_queue &&
      (smartlist_len(chan->cell_queue) > 0) &&
      changed &&
      chan->cell_handler) channel_process_cells(chan);
}

/** Set both fixed- and variable-length cell handlers at once
 */

void
channel_set_cell_handlers(channel_t *chan,
                          void (*cell_handler)(channel_t *, cell_t *),
                          void (*var_cell_handler)(channel_t *,
                                                   var_cell_t *))
{
  int try_again = 0;

  tor_assert(chan);
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
           "Setting cell_handler callback for channel %p to %p",
           chan, cell_handler);
  log_debug(LD_CHANNEL,
           "Setting var_cell_handler callback for channel %p to %p",
           chan, var_cell_handler);

  /* Should we try the queue? */
  if (cell_handler &&
      cell_handler != chan->cell_handler) try_again = 1;
  if (var_cell_handler &&
      var_cell_handler != chan->var_cell_handler) try_again = 1;

  /* Change them */
  chan->cell_handler = cell_handler;
  chan->var_cell_handler = var_cell_handler;

  /* Re-run the queue if we have one and there's any reason to */
  if (chan->cell_queue &&
      (smartlist_len(chan->cell_queue) > 0) &&
      try_again &&
      (chan->cell_handler ||
       chan->var_cell_handler)) channel_process_cells(chan);
}

/** Set the variable-length cell handler for a channel
 */

void
channel_set_var_cell_handler(channel_t *chan,
                             void (*var_cell_handler)(channel_t *,
                                                      var_cell_t *))
{
  int changed = 0;

  tor_assert(chan);
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
           "Setting var_cell_handler callback for channel %p to %p",
           chan, var_cell_handler);

  /*
   * Keep track whether we've changed it so we know if there's any point in
   * re-running the queue.
   */
  if (var_cell_handler != chan->var_cell_handler) changed = 1;

  /* Change it */
  chan->var_cell_handler = var_cell_handler;

  /* Re-run the queue if we have one and there's any reason to */
  if (chan->cell_queue &&
      (smartlist_len(chan->cell_queue) > 0) &&
      changed &&
      chan->var_cell_handler) channel_process_cells(chan);
}

/** Try to close a channel, invoking its close() method if it has one, and
 * free the channel_t. */

void
channel_request_close(channel_t *chan)
{
  tor_assert(chan != NULL);
  tor_assert(chan->close != NULL);

  /* If it's already in CLOSING, CLOSED or ERROR, this is a no-op */
  if (chan->state == CHANNEL_STATE_CLOSING ||
      chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) return;

  log_debug(LD_CHANNEL,
            "Closing channel %p by request",
            chan);

  /* Note closing by request from above */
  chan->reason_for_closing = CHANNEL_CLOSE_REQUESTED;

  /* Change state to CLOSING */
  channel_change_state(chan, CHANNEL_STATE_CLOSING);

  /* Tell the lower layer */
  chan->close(chan);

  /*
   * It's up to the lower layer to change state to CLOSED or ERROR when we're
   * ready; we'll try to free channels that are in the finished list and
   * have no refs.  It should do this by calling channel_closed().
   */
}

/** Notify that the channel is being closed due to a non-error condition in
 * the lower layer.  This does not call the close() method, since the lower
 * layer already knows. */

void
channel_close_from_lower_layer(channel_t *chan)
{
  tor_assert(chan != NULL);

  /* If it's already in CLOSING, CLOSED or ERROR, this is a no-op */
  if (chan->state == CHANNEL_STATE_CLOSING ||
      chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) return;

  log_debug(LD_CHANNEL,
            "Closing channel %p due to lower-layer event",
            chan);

  /* Note closing by event from below */
  chan->reason_for_closing = CHANNEL_CLOSE_FROM_BELOW;

  /* Change state to CLOSING */
  channel_change_state(chan, CHANNEL_STATE_CLOSING);
}

/** Notify that the channel is being closed due to an error condition in
  * the lower layer.  This does not call the close method, since the lower
  * layer already knows. */

void
channel_close_for_error(channel_t *chan)
{
  tor_assert(chan != NULL);

  /* If it's already in CLOSING, CLOSED or ERROR, this is a no-op */
  if (chan->state == CHANNEL_STATE_CLOSING ||
      chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) return;

  log_debug(LD_CHANNEL,
            "Closing channel %p due to lower-layer error",
            chan);

  /* Note closing by event from below */
  chan->reason_for_closing = CHANNEL_CLOSE_FOR_ERROR;

  /* Change state to CLOSING */
  channel_change_state(chan, CHANNEL_STATE_CLOSING);
}

/** Notify that the lower layer is finished closing the channel and it
 * should be regarded as inactive. */

void
channel_closed(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(chan->state == CHANNEL_STATE_CLOSING ||
             chan->state == CHANNEL_STATE_CLOSED ||
             chan->state == CHANNEL_STATE_ERROR);

  /* No-op if already inactive */
  if (chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) return;

  if (chan->reason_for_closing == CHANNEL_CLOSE_FOR_ERROR) {
    /* Inform any pending (not attached) circs that they should
     * give up. */
    circuit_n_chan_done(chan, 0);
  }
  /* Now close all the attached circuits on it. */
  circuit_unlink_all_from_channel(chan, END_CIRC_REASON_CHANNEL_CLOSED);

  if (chan->reason_for_closing != CHANNEL_CLOSE_FOR_ERROR) {
    channel_change_state(chan, CHANNEL_STATE_CLOSED);
  } else {
    channel_change_state(chan, CHANNEL_STATE_ERROR);
  }
}

/** Clear the remote end metadata (identity_digest/nickname) of a channel */

void
channel_clear_remote_end(channel_t *chan)
{
  tor_assert(chan);

  memset(chan->identity_digest, 0, sizeof(chan->identity_digest));
  tor_free(chan->nickname);
}

/** Set the remote end metadata (identity_digest/nickname) of a channel */

void
channel_set_remote_end(channel_t *chan,
                       const char *identity_digest,
                       const char *nickname)
{
  tor_assert(chan);

  if (identity_digest) {
    memcpy(chan->identity_digest,
           identity_digest,
           sizeof(chan->identity_digest));
  } else {
    memset(chan->identity_digest, 0, sizeof(chan->identity_digest));
  }

  tor_free(chan->nickname);
  if (nickname) chan->nickname = tor_strdup(nickname);
}

/** Write a cell to a channel using the write_cell() method.  This is
 * equivalent to connection_or_write_cell_to_buf(). */

void
channel_write_cell(channel_t *chan, cell_t *cell)
{
  cell_queue_entry_t *q;

  tor_assert(chan != NULL);
  tor_assert(cell != NULL);
  tor_assert(chan->write_cell != NULL);
  /* Assert that the state makes sense for a cell write */
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
            "Writing cell_t %p to channel %p",
            cell, chan);

  /* Increment the timestamp unless it's padding */
  if (!(cell->command == CELL_PADDING ||
        cell->command == CELL_VPADDING)) {
    chan->timestamp_last_added_nonpadding = approx_time();
  }

  /* Can we send it right out? */
  if (!(chan->outgoing_queue &&
        (smartlist_len(chan->outgoing_queue) > 0)) &&
      chan->state == CHANNEL_STATE_OPEN) {
    channel_ref(chan);
    chan->write_cell(chan, cell);
    channel_unref(chan);
  } else {
    /* No, queue it */
    if (!(chan->outgoing_queue)) chan->outgoing_queue = smartlist_new();
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_FIXED;
    q->u.fixed.cell = cell;
    smartlist_add(chan->outgoing_queue, q);
    /* Try to process the queue? */
    if (chan->state == CHANNEL_STATE_OPEN) channel_flush_cells(chan);
  }
}

/** Write a packed cell to a channel using the write_packed_cell() method.
 * This is equivalent to connection_or_write_cell_to_buf(). */

void
channel_write_packed_cell(channel_t *chan, packed_cell_t *packed_cell)
{
  cell_queue_entry_t *q;

  tor_assert(chan != NULL);
  tor_assert(packed_cell != NULL);
  tor_assert(chan->write_packed_cell != NULL);
  /* Assert that the state makes sense for a cell write */
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
            "Writing packed_cell_t %p to channel %p",
            packed_cell, chan);

  /* Increment the timestamp */
  chan->timestamp_last_added_nonpadding = approx_time();

  /* Can we send it right out? */
  if (!(chan->outgoing_queue &&
        (smartlist_len(chan->outgoing_queue) > 0)) &&
      chan->state == CHANNEL_STATE_OPEN) {
    channel_ref(chan);
    chan->write_packed_cell(chan, packed_cell);
    channel_unref(chan);
  } else {
    /* No, queue it */
    if (!(chan->outgoing_queue)) chan->outgoing_queue = smartlist_new();
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_PACKED;
    q->u.packed.packed_cell = packed_cell;
    smartlist_add(chan->outgoing_queue, q);
    /* Try to process the queue? */
    if (chan->state == CHANNEL_STATE_OPEN) channel_flush_cells(chan);
  }
}

/** Write a var_cell_t to a channel using the write_var_cell() method. This
 * is equivalent to connection_or_write_var_cell_to_buf(). */

void
channel_write_var_cell(channel_t *chan, var_cell_t *var_cell)
{
  cell_queue_entry_t *q;

  tor_assert(chan != NULL);
  tor_assert(var_cell != NULL);
  tor_assert(chan->write_var_cell != NULL);
  /* Assert that the state makes sense for a cell write */
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
            "Writing var_cell_t %p to channel %p",
            var_cell, chan);

  /* Increment the timestamp unless it's padding */
  if (!(var_cell->command == CELL_PADDING ||
        var_cell->command == CELL_VPADDING)) {
    chan->timestamp_last_added_nonpadding = approx_time();
  }

  /* Can we send it right out? */
  if (!(chan->outgoing_queue &&
        (smartlist_len(chan->outgoing_queue) > 0)) &&
      chan->state == CHANNEL_STATE_OPEN) {
    channel_ref(chan);
    chan->write_var_cell(chan, var_cell);
    channel_unref(chan);
  } else {
    /* No, queue it */
    if (!(chan->outgoing_queue)) chan->outgoing_queue = smartlist_new();
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_VAR;
    q->u.var.var_cell = var_cell;
    smartlist_add(chan->outgoing_queue, q);
    /* Try to process the queue? */
    if (chan->state == CHANNEL_STATE_OPEN) channel_flush_cells(chan);
  }
}

/** Internal and subclass use only function to change channel state,
 * performing all transition validity checks. */

void
channel_change_state(channel_t *chan, channel_state_t to_state)
{
  channel_state_t from_state;
  unsigned char was_active, is_active, was_listening, is_listening;
  unsigned char was_in_id_map, is_in_id_map;

  tor_assert(chan);
  from_state = chan->state;

  tor_assert(channel_state_is_valid(from_state));
  tor_assert(channel_state_is_valid(to_state));
  tor_assert(channel_state_can_transition(chan->state, to_state));

  /* Check for no-op transitions */
  if (from_state == to_state) {
    log_debug(LD_CHANNEL,
              "Got no-op transition from \"%s\" to itself on channel %p",
              channel_state_to_string(to_state),
              chan);
    return;
  }

  /* If we're going to a closing or closed state, we must have a reason set */
  if (to_state == CHANNEL_STATE_CLOSING ||
      to_state == CHANNEL_STATE_CLOSED ||
      to_state == CHANNEL_STATE_ERROR) {
    tor_assert(chan->reason_for_closing != CHANNEL_NOT_CLOSING);
  }

  /*
   * We need to maintain the queues here for some transitions:
   * when we enter CHANNEL_STATE_OPEN (especially from CHANNEL_STATE_MAINT)
   * we may have a backlog of cells to transmit, so drain the queues in
   * that case, and when going to CHANNEL_STATE_CLOSED the subclass
   * should have made sure to finish sending things (or gone to
   * CHANNEL_STATE_ERROR if not possible), so we assert for that here.
   */

  log_debug(LD_CHANNEL,
            "Changing state of channel %p from \"%s\" to \"%s\"",
            chan,
            channel_state_to_string(chan->state),
            channel_state_to_string(to_state));

  chan->state = to_state;

  /* Need to add to the right lists if the channel is registered */
  if (chan->registered) {
    was_active = !(from_state == CHANNEL_STATE_CLOSED ||
                   from_state == CHANNEL_STATE_ERROR);
    is_active = !(to_state == CHANNEL_STATE_CLOSED ||
                  to_state == CHANNEL_STATE_ERROR);

    /* Need to take off active list and put on finished list? */
    if (was_active && !is_active) {
      if (active_channels) smartlist_remove(active_channels, chan);
      if (!finished_channels) finished_channels = smartlist_new();
      smartlist_add(finished_channels, chan);
    }
    /* Need to put on active list? */
    else if (!was_active && is_active) {
      if (finished_channels) smartlist_remove(finished_channels, chan);
      if (!active_channels) active_channels = smartlist_new();
      smartlist_add(active_channels, chan);
    }

    was_listening = (from_state == CHANNEL_STATE_LISTENING);
    is_listening = (to_state == CHANNEL_STATE_LISTENING);

    /* Need to put on listening list? */
    if (!was_listening && is_listening) {
      if (!listening_channels) listening_channels = smartlist_new();
      smartlist_add(listening_channels, chan);
    }
    /* Need to remove from listening list? */
    else if (was_listening && !is_listening) {
      if (listening_channels) smartlist_remove(listening_channels, chan);
    }

    /* Now we need to handle the identity map */
    was_in_id_map = !(from_state == CHANNEL_STATE_LISTENING ||
                      from_state == CHANNEL_STATE_CLOSING ||
                      from_state == CHANNEL_STATE_CLOSED ||
                      from_state == CHANNEL_STATE_ERROR);
    is_in_id_map = !(to_state == CHANNEL_STATE_LISTENING ||
                     to_state == CHANNEL_STATE_CLOSING ||
                     to_state == CHANNEL_STATE_CLOSED ||
                     to_state == CHANNEL_STATE_ERROR);

    if (!was_in_id_map && is_in_id_map) channel_add_to_digest_map(chan);
    else if (was_in_id_map && !is_in_id_map)
      channel_remove_from_digest_map(chan);
  }

  /* Tell circuits if we opened and stuff */
  if (to_state == CHANNEL_STATE_OPEN) channel_do_open_actions(chan);

  if (to_state == CHANNEL_STATE_OPEN) {
    /* Check for queued cells to process */
    if (chan->cell_queue && smartlist_len(chan->cell_queue) > 0)
      channel_process_cells(chan);
    if (chan->outgoing_queue && smartlist_len(chan->outgoing_queue) > 0)
      channel_flush_cells(chan);
  } else if (to_state == CHANNEL_STATE_CLOSED) {
    /* Assert that all queues are empty */
    tor_assert(!(chan->cell_queue) ||
                smartlist_len(chan->cell_queue) == 0);
    tor_assert(!(chan->outgoing_queue) ||
                smartlist_len(chan->outgoing_queue) == 0);
    tor_assert(!(chan->incoming_list) ||
                smartlist_len(chan->incoming_list) == 0);
  }
}

/** The lower layer wants more cells; try to oblige if we can. The num_cells
 * parameter indicates approximately how many to flush; use -1 for unlimited.
 */

#define MAX_CELLS_TO_GET_FROM_CIRCUITS_FOR_UNLIMITED 256

ssize_t
channel_flush_some_cells(channel_t *chan, ssize_t num_cells)
{
  unsigned int unlimited = 0;
  ssize_t flushed = 0;
  int num_cells_from_circs;

  tor_assert(chan);
  if (num_cells < 0) unlimited = 1;
  if (!unlimited && num_cells <= flushed) goto done;

  /* If we aren't in CHANNEL_STATE_OPEN, nothing goes through */
  if (chan->state == CHANNEL_STATE_OPEN) {
    /* Try to flush as much as we can that's already queued */
    flushed += channel_flush_some_cells_from_outgoing_queue(chan,
        (unlimited ? -1 : num_cells - flushed));
    if (!unlimited && num_cells <= flushed) goto done;

    if (chan->active_circuits) {
      /* Try to get more cells from any active circuits */
      num_cells_from_circs =
        channel_flush_from_first_active_circuit(chan,
            (unlimited ? MAX_CELLS_TO_GET_FROM_CIRCUITS_FOR_UNLIMITED :
                         (num_cells - flushed)));

      /* If it claims we got some, process the queue again */
      if (num_cells_from_circs > 0) {
        flushed += channel_flush_some_cells_from_outgoing_queue(chan,
          (unlimited ? -1 : num_cells - flushed));
      }
    }
  }

 done:
  return flushed;
}

/** This gets called from channel_flush_some_cells() above to flush cells
 * just from the queue without trying for active_circuits. */

static ssize_t
channel_flush_some_cells_from_outgoing_queue(channel_t *chan,
                                             ssize_t num_cells)
{
  unsigned int unlimited = 0;
  ssize_t flushed = 0;
  cell_queue_entry_t *q = NULL;

  tor_assert(chan);
  tor_assert(chan->write_cell);
  tor_assert(chan->write_var_cell);

  if (num_cells < 0) unlimited = 1;
  if (!unlimited && num_cells <= flushed) return 0;

  /* If we aren't in CHANNEL_STATE_OPEN, nothing goes through */
  if (chan->state == CHANNEL_STATE_OPEN) {
    while ((unlimited || num_cells > flushed) &&
           (chan->outgoing_queue &&
            (smartlist_len(chan->outgoing_queue) > 0))) {
      /*
       * Ewww, smartlist_del_keeporder() is O(n) in list length; maybe a
       * a linked list would make more sense for the queue.
       */

      /* Get the head of the queue */
      q = smartlist_get(chan->outgoing_queue, 0);
      /* That shouldn't happen; bail out */
      if (q) {
        /*
         * Okay, we have a good queue entry, try to give it to the lower
         * layer.
         */
        switch (q->type) {
          case CELL_QUEUE_FIXED:
            if (q->u.fixed.cell) {
              if (chan->write_cell(chan, q->u.fixed.cell)) {
                tor_free(q);
                ++flushed;
              }
              /* Else couldn't write it; leave it on the queue */
            } else {
              /* This shouldn't happen */
              log_info(LD_CHANNEL,
                       "Saw broken cell queue entry of type CELL_QUEUE_FIXED "
                       "with no cell on channel %p.",
                       chan);
              /* Throw it away */
              tor_free(q);
            }
            break;
         case CELL_QUEUE_PACKED:
            if (q->u.packed.packed_cell) {
              if (chan->write_packed_cell(chan, q->u.packed.packed_cell)) {
                tor_free(q);
                ++flushed;
              }
              /* Else couldn't write it; leave it on the queue */
            } else {
              /* This shouldn't happen */
              log_info(LD_CHANNEL,
                       "Saw broken cell queue entry of type CELL_QUEUE_PACKED "
                       "with no cell on channel %p.",
                       chan);
              /* Throw it away */
              tor_free(q);
            }
            break;
         case CELL_QUEUE_VAR:
            if (q->u.var.var_cell) {
              if (chan->write_var_cell(chan, q->u.var.var_cell)) {
                tor_free(q);
                ++flushed;
              }
              /* Else couldn't write it; leave it on the queue */
            } else {
              /* This shouldn't happen */
              log_info(LD_CHANNEL,
                       "Saw broken cell queue entry of type CELL_QUEUE_VAR "
                       "with no cell on channel %p.",
                       chan);
              /* Throw it away */
              tor_free(q);
            }
            break;
          default:
            /* Unknown type, log and free it */
            log_info(LD_CHANNEL,
                     "Saw an unknown cell queue entry type %d on channel %p; "
                     "ignoring it.  Someone should fix this.",
                     q->type, chan);
            tor_free(q); /* tor_free() NULLs it out */
        }
      } else {
        /* This shouldn't happen; log and throw it away */
        log_info(LD_CHANNEL,
                 "Saw a NULL entry in the outgoing cell queue on channel %p; "
                 "this is definitely a bug.",
                 chan);
        /* q is already NULL, so we know to delete that queue entry */
      }

      /* if q got NULLed out, we used it and should remove the queue entry */
      if (!q) smartlist_del_keeporder(chan->outgoing_queue, 0);
      /* No cell removed from list, so we can't go on any further */
      else break;
    }
  }

  return flushed;
}

/** This gets used from the lower layer to check if any more cells are
 * available.
 */

int
channel_more_to_flush(channel_t *chan)
{
  tor_assert(chan);

  /* Check if we have any queued */
  if (chan->cell_queue && smartlist_len(chan->cell_queue) > 0) return 1;

  /* Check if any circuits would like to queue some */
  if (chan->active_circuits) return 1;

  /* Else no */
  return 0;
}

/* Connection.c will call this when we've flushed the output; there's some
 * dirreq-related maintenance to do. */

void
channel_notify_flushed(channel_t *chan)
{
  tor_assert(chan);

  if (chan->dirreq_id != 0)
    geoip_change_dirreq_state(chan->dirreq_id, DIRREQ_TUNNELED,
                              DIRREQ_CHANNEL_BUFFER_FLUSHED);
}

/** Use a listener's registered callback to process the queue of incoming
 * channels. */

void
channel_process_incoming(channel_t *listener)
{
  tor_assert(listener);
  /*
   * CHANNEL_STATE_CLOSING permitted because we drain the queue while
   * closing a listener.
   */
  tor_assert(listener->state == CHANNEL_STATE_LISTENING ||
             listener->state == CHANNEL_STATE_CLOSING);
  tor_assert(listener->listener);

  log_debug(LD_CHANNEL,
            "Processing queue of incoming connections for listening "
            "channel %p",
            listener);

  if (!(listener->incoming_list)) return;

  channel_ref(listener);

  SMARTLIST_FOREACH_BEGIN(listener->incoming_list, channel_t *, chan) {
    log_debug(LD_CHANNEL,
              "Handling incoming connection %p for listener %p",
              chan, listener);
    channel_ref(chan);
    /* Make sure this is set correctly */
    channel_mark_incoming(chan);
    listener->listener(listener, chan);
    channel_unref(chan);
    SMARTLIST_DEL_CURRENT(listener->incoming_list, chan);
  } SMARTLIST_FOREACH_END(chan);

  channel_unref(listener);

  tor_assert(smartlist_len(listener->incoming_list) == 0);
  smartlist_free(listener->incoming_list);
  listener->incoming_list = NULL;
}

/** Handle actions we should do when we know a channel is open; a lot of
 * this comes from the old connection_or_set_state_open() of connection_or.c.
 *
 * Because of this mechanism, future channel_t subclasses should take care
 * not to change a channel to from CHANNEL_STATE_OPENING to CHANNEL_STATE_OPEN
 * until there is positive confirmation that the network is operational.
 * In particular, anything UDP-based should not make this transition until a
 * packet is received from the other side.
 */

void
channel_do_open_actions(channel_t *chan)
{
  int started_here, not_using = 0;
  time_t now = time(NULL);

  tor_assert(chan);

  started_here = channel_is_outgoing(chan);

  if (started_here) {
    circuit_build_times_network_is_live(&circ_times);
    rep_hist_note_connect_succeeded(chan->identity_digest, now);
    if (entry_guard_register_connect_status(chan->identity_digest,
                                            1, 0, now) < 0) {
      /* Close any circuits pending on this channel. We leave it in state
       * 'open' though, because it didn't actually *fail* -- we just
       * chose not to use it. */
      log_debug(LD_OR,
                "New entry guard was reachable, but closing this "
                "connection so we can retry the earlier entry guards.");
      circuit_n_chan_done(chan, 0);
      not_using = 1;
    }
    router_set_status(chan->identity_digest, 1);
  } else {
    /* only report it to the geoip module if it's not a known router */
    if (!router_get_by_id_digest(chan->identity_digest)) {
      /* TODO figure out addressing */
      /*
      geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &(chan->addr),
                             now);
       */
    }
  }

  if (!not_using) circuit_n_chan_done(chan, 1);
}

/** Internal and subclass use only function to queue an incoming channel from
 * a listening one. */

void
channel_queue_incoming(channel_t *listener, channel_t *incoming)
{
  int need_to_queue = 0;

  tor_assert(listener);
  tor_assert(listener->state == CHANNEL_STATE_LISTENING);
  tor_assert(incoming);
  /*
   * Other states are permitted because subclass might process activity
   * on a channel at any time while it's queued, but a listener returning
   * another listener makes no sense.
   */
  tor_assert(incoming->state != CHANNEL_STATE_LISTENING);

  log_debug(LD_CHANNEL,
            "Queueing incoming channel %p on listening channel %p",
            incoming, listener);

  /* Do we need to queue it, or can we just call the listener right away? */
  if (!(listener->listener)) need_to_queue = 1;
  if (listener->incoming_list &&
      (smartlist_len(listener->incoming_list) > 0)) need_to_queue = 1;

  /* If we need to queue and have no queue, create one */
  if (need_to_queue && !(listener->incoming_list)) {
    listener->incoming_list = smartlist_new();
  }

  /* If we don't need to queue, process it right away */
  if (!need_to_queue) {
    tor_assert(listener->listener);
    channel_ref(listener);
    channel_ref(incoming);
    listener->listener(listener, incoming);
    channel_unref(incoming);
    channel_unref(listener);
  }
  /*
   * Otherwise, we need to queue; queue and then process the queue if
   * we can.
   */
  else {
    tor_assert(listener->incoming_list);
    smartlist_add(listener->incoming_list, incoming);
    if (listener->listener) channel_process_incoming(listener);
  }
}

/*
 * Internal and subclass use only function to queue an incoming cell for the
 * callback to handle.
 */

/** Process as many queued cells as we can
 */

void
channel_process_cells(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(chan->state == CHANNEL_STATE_CLOSING ||
             chan->state == CHANNEL_STATE_MAINT ||
             chan->state == CHANNEL_STATE_OPEN);

  log_debug(LD_CHANNEL,
            "Processing as many incoming cells as we can for channel %p",
            chan);

  /* Nothing we can do if we have no registered cell handlers */
  if (!(chan->cell_handler || chan->var_cell_handler)) return;
  /* Nothing we can do if we have no cells */
  if (!(chan->cell_queue)) return;

  /*
   * Process cells until we're done or find one we have no current handler
   * for.
   */
  channel_ref(chan);
  SMARTLIST_FOREACH_BEGIN(chan->cell_queue, cell_queue_entry_t *, q) {
    tor_assert(q);
    tor_assert(q->type == CELL_QUEUE_FIXED ||
               q->type == CELL_QUEUE_VAR);
    if (q->type == CELL_QUEUE_FIXED && chan->cell_handler) {
      /* Handle a fixed-length cell */
      tor_assert(q->u.fixed.cell);
      log_debug(LD_CHANNEL,
                "Processing incoming cell_t %p for channel %p",
                q->u.fixed.cell, chan);
      chan->cell_handler(chan, q->u.fixed.cell);
      SMARTLIST_DEL_CURRENT(chan->cell_queue, q);
      tor_free(q);
    } else if (q->type == CELL_QUEUE_VAR && chan->var_cell_handler) {
      /* Handle a variable-length cell */
      tor_assert(q->u.var.var_cell);
      log_debug(LD_CHANNEL,
                "Processing incoming var_cell_t %p for channel %p",
                q->u.var.var_cell, chan);
      chan->var_cell_handler(chan, q->u.var.var_cell);
      SMARTLIST_DEL_CURRENT(chan->cell_queue, q);
      tor_free(q);
    } else {
      /* Can't handle this one */
      break;
    }
  } SMARTLIST_FOREACH_END(chan);
  channel_unref(chan);

  /* If the list is empty, free it */
  if (smartlist_len(chan->cell_queue) == 0 ) {
    smartlist_free(chan->cell_queue);
    chan->cell_queue = NULL;
  }
}

/** Queue a fixed-length cell for processing, and process it if possible
 */

void
channel_queue_cell(channel_t *chan, cell_t *cell)
{
  int need_to_queue = 0;
  cell_queue_entry_t *q;

  tor_assert(chan);
  tor_assert(cell);
  tor_assert(chan->state == CHANNEL_STATE_OPEN);

  /* Do we need to queue it, or can we just call the handler right away? */
  if (!(chan->cell_handler)) need_to_queue = 1;
  if (chan->cell_queue &&
      (smartlist_len(chan->cell_queue) > 0)) need_to_queue = 1;

  /* If we need to queue and have no queue, create one */
  if (need_to_queue && !(chan->cell_queue)) {
    chan->cell_queue = smartlist_new();
  }

  /* If we don't need to queue we can just call cell_handler */
  if (!need_to_queue) {
    tor_assert(chan->cell_handler);
    log_debug(LD_CHANNEL,
              "Directly handling incoming cell_t %p for channel %p",
              cell, chan);
    channel_ref(chan);
    chan->cell_handler(chan, cell);
    channel_unref(chan);
  } else {
    /* Otherwise queue it and then process the queue if possible. */
    tor_assert(chan->cell_queue);
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_FIXED;
    q->u.fixed.cell = cell;
    log_debug(LD_CHANNEL,
              "Queueing incoming cell_t %p for channel %p",
              cell, chan);
    smartlist_add(chan->cell_queue, q);
    if (chan->cell_handler || chan->var_cell_handler) {
      channel_process_cells(chan);
    }
  }
}

/** Queue a variable-length cell for processing, and process it if possible
 */

void
channel_queue_var_cell(channel_t *chan, var_cell_t *var_cell)
{
  int need_to_queue = 0;
  cell_queue_entry_t *q;

  tor_assert(chan);
  tor_assert(var_cell);
  tor_assert(chan->state == CHANNEL_STATE_OPEN);

  /* Do we need to queue it, or can we just call the handler right away? */
  if (!(chan->var_cell_handler)) need_to_queue = 1;
  if (chan->cell_queue &&
      (smartlist_len(chan->cell_queue) > 0)) need_to_queue = 1;

  /* If we need to queue and have no queue, create one */
  if (need_to_queue && !(chan->cell_queue)) {
    chan->cell_queue = smartlist_new();
  }

  /* If we don't need to queue we can just call cell_handler */
  if (!need_to_queue) {
    tor_assert(chan->cell_handler);
    log_debug(LD_CHANNEL,
              "Directly handling incoming var_cell_t %p for channel %p",
              var_cell, chan);
    channel_ref(chan);
    chan->var_cell_handler(chan, var_cell);
    channel_unref(chan);
  } else {
    /* Otherwise queue it and then process the queue if possible. */
    tor_assert(chan->cell_queue);
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_VAR;
    q->u.var.var_cell = var_cell;
    log_debug(LD_CHANNEL,
              "Queueing incoming var_cell_t %p for channel %p",
              var_cell, chan);
    smartlist_add(chan->cell_queue, q);
    if (chan->cell_handler || chan->var_cell_handler) {
      channel_process_cells(chan);
    }
  }
}

/** Write a destroy cell with circ ID <b>circ_id</b> and reason <b>reason</b>
 * onto channel <b>chan</b>.  Don't perform range-checking on reason:
 * we may want to propagate reasons from other cells.
 *
 * Return 0.
 */

int
channel_send_destroy(circid_t circ_id, channel_t *chan, int reason)
{
  cell_t cell;

  tor_assert(chan);

  memset(&cell, 0, sizeof(cell_t));
  cell.circ_id = circ_id;
  cell.command = CELL_DESTROY;
  cell.payload[0] = (uint8_t) reason;
  log_debug(LD_OR,"Sending destroy (circID %d).", circ_id);

  channel_write_cell(chan, &cell);

  return 0;
}

/** Connect to a given addr/port/digest; this eventually should get replaced
  * with something transport-independent that picks an appropriate subclass
  * constructor to call.
  */

channel_t *
channel_connect(const tor_addr_t *addr, uint16_t port,
                const char *id_digest)
{
  return channel_tls_connect(addr, port, id_digest);
}

/** Return text descriptions provided by the lower layer of the remote
 * endpoint for this channel. */

const char *
channel_get_actual_remote_descr(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(chan->get_remote_descr);

  /* Param 1 indicates the actual description */
  return chan->get_remote_descr(1);
}

const char *
channel_get_canonical_remote_descr(channel_t *chan)
{
  /* Param 0 indicates the canonicalized description */
  return chan->get_remote_descr(0);
}

/** Indicate if either we have queued cells, or if not, whether the underlying
 * lower-layer transport thinks it has an output queue.
 */

int
channel_has_queued_writes(channel_t *chan)
{
  int has_writes = 0;

  tor_assert(chan);
  tor_assert(chan->has_queued_writes);

  if (chan->outgoing_queue && smartlist_len(chan->outgoing_queue) > 0) {
    has_writes = 1;
  } else {
    /* Check with the lower layer */
    has_writes = chan->has_queued_writes(chan);
  }

  return has_writes;
}

/** Get/set is_bad_for_new_circs flag */

int
channel_is_bad_for_new_circs(channel_t *chan)
{
  tor_assert(chan);

  return chan->is_bad_for_new_circs;
}

void
channel_mark_bad_for_new_circs(channel_t *chan)
{
  tor_assert(chan);

  chan->is_bad_for_new_circs = 1;
}

/** Get the client flag; this will be set if command_process_create_cell()
 * in cmd.c thinks this is a connection from a client. */

int
channel_is_client(channel_t *chan)
{
  tor_assert(chan);

  return chan->is_client;
}

/** Set the client flag */

void
channel_mark_client(channel_t *chan)
{
  tor_assert(chan);

  chan->is_client = 1;
}

/** Get the incoming flag; this is set when a listener spawns a channel.
 * If this returns true the channel was remotely initiated. */

int
channel_is_incoming(channel_t *chan)
{
  tor_assert(chan);;

  return chan->is_incoming;
}

/** Set the incoming flag */

void
channel_mark_incoming(channel_t *chan)
{
  tor_assert(chan);

  chan->is_incoming = 1;
}

/** Get local flag; the lower layer should set this when setting up the
 * channel if is_local_addr() is true for all of the destinations it will
 * communicate with on behalf of this channel.  It's used to decide whether
 * to declare the network reachable when seeing incoming traffic on the
 * channel. */

int
channel_is_local(channel_t *chan)
{
  tor_assert(chan);

  return chan->is_local;
}

/* Set the local flag; this internal-only function should be called by the
 * lower layer if the channel is to a local address.  See above or the
 * description of the is_local bit in channel.h */

void
channel_mark_local(channel_t *chan)
{
  tor_assert(chan);

  chan->is_local = 1;
}

/** Get the outgoing flag; this is the inverse of the incoming bit set when
 * a listener spawns a channel.  If this returns true the channel was locally
 * initiated. */

int
channel_is_outgoing(channel_t *chan)
{
  tor_assert(chan);;

  return !(chan->is_incoming);
}

/** Clear the incoming flag */

void
channel_mark_outgoing(channel_t *chan)
{
  tor_assert(chan);

  chan->is_incoming = 0;
}

/** Timestamp updates */

/** Update the created timestamp; this should only be called from
 * channel_init(). */

void
channel_timestamp_created(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);

  chan->timestamp_created = now;
}

/** Update the last active timestamp.  This should be called by the
 * lower layer whenever there is activity on the channel which does
 * not lead to a cell being transmitted or received; the active
 * timestamp is also updated from channel_timestamp_recv() and
 * channel_timestamp_xmit(), but it should be updated for things
 * like the v3 handshake and stuff that produce activity only
 * visible to the lower layer.
 */

void
channel_timestamp_active(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);

  chan->timestamp_active = now;
}

/** Mark a channel relay.c thinks just got used as client */

void
channel_timestamp_client(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);

  chan->timestamp_client = now;
}

/** Update the last drained timestamp.  This is called whenever we
 * transmit a cell which leaves the outgoing cell queue completely
 * empty.  It also updates the xmit time and the active time.
 */

void
channel_timestamp_drained(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);

  chan->timestamp_active = now;
  chan->timestamp_drained = now;
  chan->timestamp_xmit = now;
}

/** Update the recv timestamp.  This is called whenever we get an
 * incoming cell from the lower layer.  This also updates the active
 * timestamp.
 */

void
channel_timestamp_recv(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);

  chan->timestamp_active = now;
  chan->timestamp_recv = now;
}

/** Update the xmit timestamp.  This is called whenever we pass an
 * outgoing cell to the lower layer.  This also updates the active
 * timestamp.
 */

void
channel_timestamp_xmit(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);

  chan->timestamp_active = now;
  chan->timestamp_xmit = now;
}

/** Timestamp queries - see above comments for meaning of the timestamps */

time_t
channel_when_created(channel_t *chan)
{
  tor_assert(chan);

  return chan->timestamp_created;
}

time_t
channel_when_last_active(channel_t *chan)
{
  tor_assert(chan);

  return chan->timestamp_active;
}

time_t
channel_when_last_client(channel_t *chan)
{
  tor_assert(chan);

  return chan->timestamp_client;
}

time_t
channel_when_last_drained(channel_t *chan)
{
  tor_assert(chan);

  return chan->timestamp_drained;
}

time_t
channel_when_last_recv(channel_t *chan)
{
  tor_assert(chan);

  return chan->timestamp_recv;
}

time_t
channel_when_last_xmit(channel_t *chan)
{
  tor_assert(chan);

  return chan->timestamp_xmit;
}

/** Call the lower layer and ask if this channel matches a given
 * extend_info_t */

int
channel_matches_extend_info(channel_t *chan, extend_info_t *extend_info)
{
  tor_assert(chan);
  tor_assert(chan->matches_extend_info);
  tor_assert(extend_info);

  return chan->matches_extend_info(chan, extend_info);
}

/** Set up circuit ID stuff; this replaces connection_or_set_circid_type() */

void
channel_set_circid_type(channel_t *chan, crypto_pk_t *identity_rcvd)
{
  int started_here;
  crypto_pk_t *our_identity;

  tor_assert(chan);

  started_here = channel_is_outgoing(chan);
  our_identity = started_here ?
    get_tlsclient_identity_key() : get_server_identity_key();

  if (identity_rcvd) {
    if (crypto_pk_cmp_keys(our_identity, identity_rcvd) < 0) {
      chan->circ_id_type = CIRC_ID_TYPE_LOWER;
    } else {
      chan->circ_id_type = CIRC_ID_TYPE_HIGHER;
    }
  } else {
    chan->circ_id_type = CIRC_ID_TYPE_NEITHER;
  }
}

