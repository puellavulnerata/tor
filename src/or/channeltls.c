/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channeltls.c
 * \brief channel_t concrete subclass using or_connection_t
 **/

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */

#define _TOR_CHANNEL_INTERNAL

#include "or.h"
#include "channel.h"
#include "channeltls.h"
#include "connection_or.h"

typedef struct channel_tls_s channel_tls_t;
struct channel_tls_s {
  /* Base channel_t struct */
  channel_t _base;
  /* or_connection_t pointer */
  or_connection_t *conn;
};

#define BASE_CHAN_TO_TLS(c) ((channel_tls_t *)(c))
#define TLS_CHAN_TO_BASE(c) ((channel_t *)(c))

/* channel_tls_t method declarations */

static void channel_tls_close_method(channel_t *chan);
static void channel_tls_write_cell_method(channel_t *chan,
                                          cell_t *cell);
static void channel_tls_write_var_cell_method(channel_t *chan,
                                              var_cell_t *var_cell);

/** Launch a new OR connection to <b>addr</b>:<b>port</b> and expect to
 * handshake with an OR with identity digest <b>id_digest</b>.
 *
 * If <b>id_digest</b> is me, do nothing. If we're already connected to it,
 * return that connection. If the connect() is in progress, set the
 * new conn's state to 'connecting' and return it. If connect() succeeds,
 * call connection_tls_start_handshake() on it.
 *
 * This function is called from router_retry_connections(), for
 * ORs connecting to ORs, and circuit_establish_circuit(), for
 * OPs connecting to ORs.
 *
 * Return the launched conn, or NULL if it failed.
 */

channel_t *
channel_tls_connect(const tor_addr_t *addr, uint16_t port,
                    const char *id_digest)
{
  channel_tls_t *tlschan = tor_malloc_zero(sizeof(*tlschan));
  channel_t *chan = TLS_CHAN_TO_BASE(tlschan);
  chan->state = CHANNEL_STATE_OPENING;
  chan->close = channel_tls_close_method;
  chan->write_cell = channel_tls_write_cell_method;
  chan->write_var_cell = channel_tls_write_var_cell_method;

  /* Set up or_connection stuff */
  tlschan->conn = connection_or_connect(addr, port, id_digest);
  if (!(tlschan->conn)) {
    channel_change_state(chan, CHANNEL_STATE_ERROR);
    goto err;
  }

  channel_change_state(chan, CHANNEL_STATE_OPEN);

  goto done;

 err:
  tor_free(tlschan);
  chan = NULL;

 done:
  return chan;
}

/** Given a channel_tls_t and a cell_t, transmit the cell_t */

static void
channel_tls_write_cell_method(channel_t *chan, cell_t *cell)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  
  tor_assert(tlschan);
  tor_assert(cell);
  tor_assert(tlschan->conn);

  connection_or_write_cell_to_buf(cell, tlschan->conn);
}

/** Given a channel_tls_t and a var_cell_t, transmit the var_cell_t */

static void
channel_tls_write_var_cell_method(channel_t *chan, var_cell_t *var_cell)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  
  tor_assert(tlschan);
  tor_assert(var_cell);
  tor_assert(tlschan->conn);

  connection_or_write_var_cell_to_buf(var_cell, tlschan->conn);
}

