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

  /* Registered handlers for incoming cells */
  void (*cell_handler)(channel_t *, cell_t *);
  void (*var_cell_handler)(channel_t *, var_cell_t *);
  /* List of incoming cells to handle */
  smartlist_t *cell_queue;

  /* List of queued outgoing cells */
  smartlist_t *outgoing_queue;

  /** Hash of the public RSA key for the other side's identity key, or zeroes
   * if the other side hasn't shown us a valid identity key.
   */
  char identity_digest[DIGEST_LEN];
  /** Nickname of the OR on the other side, or NULL if none. */
  char *nickname;

  /** When we last used this conn for any client traffic. If not
   * recent, we can rate limit it further. */
  time_t client_used;

  /*
   * Function pointers for channel ops
   */

  /* Close an open channel */
  void (*close)(channel_t *);
  /* Write a cell to an open channel */
  void (*write_cell)(channel_t *, cell_t *);
  /* Write a variable-length cell to an open channel */
  void (*write_var_cell)(channel_t *, var_cell_t *);
};

/* Channel state manipulations */

int channel_state_is_valid(channel_state_t state);
int channel_state_can_transition(channel_state_t from, channel_state_t to);
const char * channel_state_to_string(channel_state_t state);

/* Abstract channel operations */

void channel_close(channel_t *chan);
void channel_write_cell(channel_t *chan, cell_t *cell);
void channel_write_var_cell(channel_t *chan, var_cell_t *cell);

/* Channel callback registrations */

/* Listener callback */
void (* channel_get_listener(channel_t *chan))(channel_t *, channel_t *);
void channel_set_listener(channel_t *chan,
                          void (*listener)(channel_t *, channel_t *) );

/* Incoming cell callbacks */
void (* channel_get_cell_handler(channel_t *chan))
  (channel_t *, cell_t *);
void (* channel_get_var_cell_handler(channel_t *chan))
  (channel_t *, var_cell_t *);
void channel_set_cell_handler(channel_t *chan,
                              void (*cell_handler)(channel_t *, cell_t *));
void channel_set_cell_handlers(channel_t *chan,
                               void (*cell_handler)(channel_t *, cell_t *),
                               void (*var_cell_handler)(channel_t *,
                                                        var_cell_t *));
void channel_set_var_cell_handler(channel_t *chan,
                                  void (*var_cell_handler)(channel_t *,
                                                           var_cell_t *));

#ifdef _TOR_CHANNEL_INTERNAL

/* Channel operations for subclasses and internal use only */

/* State/metadata setters */

void channel_change_state(channel_t *chan, channel_state_t to_state);
void channel_clear_remote_end(channel_t *chan);
void channel_set_remote_end(channel_t *chan,
                            const char *identity_digest,
                            const char *nickname);

/* Incoming channel handling */
void channel_process_incoming(channel_t *listener);
void channel_queue_incoming(channel_t *listener, channel_t *incoming);

/* Incoming cell handling */
void channel_process_cells(channel_t *chan);
void channel_queue_cell(channel_t *chan, cell_t *cell);
void channel_queue_var_cell(channel_t *chan, var_cell_t *var_cell);

/* Outgoing cell handling */
void channel_flush_cells(channel_t *chan);

#endif

/* Helper functions to perform operations on channels */

int channel_send_destroy(circid_t circ_id, channel_t *chan,
                         int reason);

/*
 * Outside abstract interfaces that should eventually get turned into
 * something transport/address format independent.
 */

channel_t * channel_connect(const tor_addr_t *addr, uint16_t port,
                            const char *id_digest);

channel_t * channel_get_for_extend(const char *digest,
                                   const tor_addr_t *target_addr,
                                   const char **msg_out,
                                   int *launch_out);

/*
 * Metadata queries
 */

const char * channel_get_remote_descr(channel_t *chan);

#endif

