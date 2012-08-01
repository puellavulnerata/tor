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
  /* Current channel state */
  channel_state_t state;

  /* Registered listen handler to call on incoming connection */
  void (*listener)(channel_t *, channel_t *);
  /* List of pending incoming connections */
  smartlist_t *incoming_list;

  /*
   * Function pointers for channel ops
   */

  /* Close an open channel */
  void (*close)(channel_t *);
  /* Write a cell to an open channel */
  void (*write_cell)(const cell_t *, channel_t *);
  /* Write a variable-length cell to an open channel */
  void (*write_var_cell)(const var_cell_t *, channel_t *);
};

/* Channel state manipulations */

int channel_state_is_valid(channel_state_t state);
int channel_state_can_transition(channel_state_t from, channel_state_t to);
const char * channel_state_to_string(channel_state_t state);

/* Abstract channel operations */

void channel_close(channel_t *chan);
void channel_write_cell(const cell_t *cell, channel_t *chan);
void channel_write_var_cell(const var_cell_t *cell, channel_t *chan);

/* Channel callback registrations */
void (* channel_get_listener(channel_t *chan))(channel_t *, channel_t *);
void channel_set_listener(channel_t *chan,
                          void (*listener)(channel_t *, channel_t *) );

#ifdef _TOR_CHANNEL_INTERNAL

/* Channel operations for subclasses and internal use only */

void channel_change_state(channel_t *chan, channel_state_t to_state);
void channel_process_incoming(channel_t *listener);
void channel_queue_incoming(channel_t *listener, channel_t *incoming);

#endif

/* Helper functions to perform operations on channels */

int channel_send_destroy(circid_t circ_id, channel_t *chan,
                         int reason);

#endif

