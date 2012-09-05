/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channeltls.h
 * \brief Header file for channeltls.c
 **/

#ifndef _TOR_CHANNEL_TLS_H
#define _TOR_CHANNEL_TLS_H

#include "or.h"
#include "channel.h"

#define BASE_CHAN_TO_TLS(c) ((channel_tls_t *)(c))
#define TLS_CHAN_TO_BASE(c) ((channel_t *)(c))

channel_t * channel_tls_connect(const tor_addr_t *addr, uint16_t port,
                                const char *id_digest);

/* Things for connection_or.c to call back into */
ssize_t channel_tls_flush_some_cells(channel_tls_t *chan, ssize_t num_cells);
int channel_tls_more_to_flush(channel_tls_t *chan);
void channel_tls_handle_cell(cell_t *cell, or_connection_t *conn);
void channel_tls_handle_state_change_on_orconn(channel_tls_t *chan,
                                               or_connection_t *conn,
                                               uint8_t old_state,
                                               uint8_t state);
void channel_tls_handle_var_cell(var_cell_t *var_cell,
                                 or_connection_t *conn);

#endif

