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

/** Handle incoming cells for the handshake stuff here rather than
 * passing them on up. */

static void channel_tls_process_versions_cell(var_cell_t *cell,
                                              channel_tls_t *tlschan);
static void channel_tls_process_netinfo_cell(cell_t *cell,
                                             channel_tls_t *tlschan);
static void channel_tls_process_certs_cell(var_cell_t *cell,
                                           channel_tls_t *tlschan);
static void channel_tls_process_auth_challenge_cell(var_cell_t *cell,
                                                    channel_tls_t *tlschan);
static void channel_tls_process_authenticate_cell(var_cell_t *cell,
                                                  channel_tls_t *tlschan);
static int enter_v3_handshake_with_cell(var_cell_t *cell,
                                        channel_tls_t *tlschan);

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
  tlschan->conn = connection_or_connect(addr, port, id_digest, tlschan);
  if (!(tlschan->conn)) {
    channel_change_state(chan, CHANNEL_STATE_ERROR);
    goto err;
  }

  goto done;

 err:
  tor_free(tlschan);
  chan = NULL;

 done:
  return chan;
}

/** Close a channel_tls_t */

static void
channel_tls_close_method(channel_t *chan)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);

  /* TODO */
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

/** Handle events on an or_connection_t in these functions */

/** connection_or.c will call this when the or_connection_t associated
 * with this channel_tls_t changes state. */

void
channel_tls_handle_state_change_on_orconn(channel_tls_t *chan,
                                          or_connection_t *conn,
                                          uint8_t old_state,
                                          uint8_t state)
{
  channel_t *base_chan;

  tor_assert(chan);
  tor_assert(conn);
  tor_assert(conn->chan == chan);
  tor_assert(chan->conn == conn);
  /* -Werror appeasement */
  tor_assert(old_state == old_state);

  base_chan = TLS_CHAN_TO_BASE(chan);

  /* Make sure the base connection state makes sense - shouldn't be error,
   * closed or listening. */

  tor_assert(base_chan->state == CHANNEL_STATE_OPENING ||
             base_chan->state == CHANNEL_STATE_OPEN ||
             base_chan->state == CHANNEL_STATE_MAINT ||
             base_chan->state == CHANNEL_STATE_CLOSING);

  /* Did we just go to state open? */
  if (state == OR_CONN_STATE_OPEN) {
    /*
     * We can go to CHANNEL_STATE_OPEN from CHANNEL_STATE_OPENING or
     * CHANNEL_STATE_MAINT on this.
     */
    channel_change_state(base_chan, CHANNEL_STATE_OPEN);
  } else {
    /*
     * Not open, so from CHANNEL_STATE_OPEN we go to CHANNEL_STATE_MAINT,
     * otherwise no change.
     */
    if (base_chan->state == CHANNEL_STATE_OPEN) {
      channel_change_state(base_chan, CHANNEL_STATE_MAINT);
    }
  }
}
