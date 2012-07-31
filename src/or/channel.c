/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channel.c
 * \brief OR-to-OR channel abstraction layer
 **/

#include "or.h"
#include "channel.h"

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
