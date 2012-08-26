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

/* Cell queue structure */

typedef struct cell_queue_entry_s cell_queue_entry_t;
struct cell_queue_entry_s {
  enum {
    CELL_QUEUE_FIXED,
    CELL_QUEUE_VAR
  } type;
  union {
    struct {
      cell_t *cell;
    } fixed;
    struct {
      var_cell_t *var_cell;
    } var;
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

  /* If the refcount is also zero and it's finished, we can free it now */
  if (chan->refcount == 0 &&
      (chan->state == CHANNEL_STATE_CLOSED ||
       chan->state == CHANNEL_STATE_ERROR)) {
    channel_free(chan);
  }
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

/** Try to close a channel, invoking its close() method if it has one, and free the
 * channel_t. */

void
channel_request_close(channel_t *chan)
{
  tor_assert(chan != NULL);
  /* If it's already in CLOSING, CLOSED or ERROR, this is a no-op */
  if (chan->state == CHANNEL_STATE_CLOSING ||
      chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) return;

  log_debug(LD_CHANNEL,
            "Closing channel %p",
            chan);

  /* Change state to CLOSING */
  channel_change_state(chan, CHANNEL_STATE_CLOSING);

  /*
   * No assert here since maybe the lower layer just needs to free the
   * channel_t and wants to leave this NULL.
   */
  if (chan->close) chan->close(chan);

  /*
   * It's up to the lower layer to change state to CLOSED or ERROR when we're
   * ready; we'll try to free channels that are in the finished list and
   * have no refs.
   */

  channel_clear_remote_end(chan);

  smartlist_free(chan->active_circuit_pqueue);

  tor_free(chan);
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
  tor_assert(chan);
  tor_assert(channel_state_is_valid(chan->state));
  tor_assert(channel_state_is_valid(to_state));
  tor_assert(channel_state_can_transition(chan->state, to_state));

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
    listener->listener(listener, chan);
    channel_unref(chan);
    SMARTLIST_DEL_CURRENT(listener->incoming_list, chan);
  } SMARTLIST_FOREACH_END(chan);

  channel_unref(listener);

  tor_assert(smartlist_len(listener->incoming_list) == 0);
  smartlist_free(listener->incoming_list);
  listener->incoming_list = NULL;
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

/** Mark a channel with the current time for rate-limiting tracking purposes */

void
channel_touched_by_client(channel_t *chan)
{
  tor_assert(chan);

  chan->client_used = time(NULL);
}

