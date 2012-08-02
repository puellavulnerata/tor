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

  chan->listener = listener;
  if (chan->listener) channel_process_incoming(chan);
}

/** Close a channel, invoking its close() method if it has one, and free the
 * channel_t. */

void
channel_close(channel_t *chan)
{
  tor_assert(chan != NULL);

  /*
   * No assert here since maybe the lower layer just needs to free the
   * channel_t and wants to leave this NULL.
   */
  if (chan->close) chan->close(chan);

  tor_free(chan);
}

/** Write a cell to a channel using the write_cell() method.  This is
 * equivalent to connection_or_write_cell_to_buf(). */

void
channel_write_cell(const cell_t *cell, channel_t *chan)
{
  tor_assert(cell != NULL);
  tor_assert(chan != NULL);
  tor_assert(chan->write_cell != NULL);

  chan->write_cell(cell, chan);
}

/** Write a var_cell_t to a channel using the write_var_cell() method. This
 * is equivalent to connection_or_write_var_cell_to_buf(). */

void
channel_write_var_cell(const var_cell_t *cell, channel_t *chan)
{
  tor_assert(cell != NULL);
  tor_assert(chan != NULL);
  tor_assert(chan->write_var_cell != NULL);

  chan->write_var_cell(cell, chan);
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

  chan->state = to_state;
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

  if (!(listener->incoming_list)) return;

  SMARTLIST_FOREACH_BEGIN(listener->incoming_list, channel_t *, chan) {
    listener->listener(listener, chan);
    SMARTLIST_DEL_CURRENT(listener->incoming_list, chan);
  } SMARTLIST_FOREACH_END(chan);

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
    listener->listener(listener, incoming);
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

/** Process as many queued cells as we can
 */

void
channel_process_cells(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(chan->state == CHANNEL_STATE_CLOSING ||
             chan->state == CHANNEL_STATE_MAINT ||
             chan->state == CHANNEL_STATE_OPEN);

  /* Nothing we can do if we have no registered cell handlers */
  if (!(chan->cell_handler || chan->var_cell_handler)) return;
  /* Nothing we can do if we have no cells */
  if (!(chan->cell_queue)) return;

  /*
   * Process cells until we're done or find one we have no current handler
   * for.
   */
  SMARTLIST_FOREACH_BEGIN(chan->cell_queue, cell_queue_entry_t *, q) {
    tor_assert(q);
    tor_assert(q->type == CELL_QUEUE_FIXED ||
               q->type == CELL_QUEUE_VAR);
    if (q->type == CELL_QUEUE_FIXED && chan->cell_handler) {
      /* Handle a fixed-length cell */
      tor_assert(q->u.fixed.cell);
      chan->cell_handler(chan, q->u.fixed.cell);
      SMARTLIST_DEL_CURRENT(chan->cell_queue, q);
      tor_free(q);
    } else if (q->type == CELL_QUEUE_VAR && chan->var_cell_handler) {
      /* Handle a variable-length cell */
      tor_assert(q->u.var.var_cell);
      chan->var_cell_handler(chan, q->u.var.var_cell);
      SMARTLIST_DEL_CURRENT(chan->cell_queue, q);
      tor_free(q);
    } else {
      /* Can't handle this one */
      break;
    }
  } SMARTLIST_FOREACH_END(chan);

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
    chan->cell_handler(chan, cell);
  } else {
    /* Otherwise queue it and then process the queue if possible. */
    tor_assert(chan->cell_queue);
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_FIXED;
    q->u.fixed.cell = cell;
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
    chan->var_cell_handler(chan, var_cell);
  } else {
    /* Otherwise queue it and then process the queue if possible. */
    tor_assert(chan->cell_queue);
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_VAR;
    q->u.var.var_cell = var_cell;
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

  channel_write_cell(&cell, chan);

  return 0;
}

