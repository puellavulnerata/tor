/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channel.h
 * \brief Header file for channel.c
 **/

#ifndef _TOR_CHANNEL_H
#define _TOR_CHANNEL_H

#include "or.h"

/*
 * Channel struct; see thw channel_t typedef in or.h.  A channel is an
 * abstract interface for the OR-to-OR connection, similar to connection_or_t,
 * but without the strong coupling to the underlying TLS implementation.  They
 * are constructed by calling a protocol-specific function to open a channel
 * to a particular node, and once constructed support the abstract operations
 * defined below.
 */

struct channel_s {
  /* Function pointers for channel ops */
  void (*close)(channel_t *);
  void (*write_cell)(const cell_t *, channel_t *);
  void (*write_var_cell)(const var_cell_t *, channel_t *);
};

/* Abstract channel operations */

void channel_close(channel_t *chan);
void channel_write_cell(const cell_t *cell, channel_t *chan);
void channel_write_var_cell(const var_cell_t *cell, channel_t *chan);

/* Helper functions to perform operations on channels */

int channel_send_destroy(circid_t circ_id, channel_t *chan,
                         int reason);

#endif

