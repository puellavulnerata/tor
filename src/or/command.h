/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file command.h
 * \brief Header file for command.c.
 **/

#ifndef _TOR_COMMAND_H
#define _TOR_COMMAND_H

#include "channel.h"

void command_process_cell(channel_t *chan, cell_t *cell);
void command_process_var_cell(channel_t *chan, var_cell_t *cell);
void command_setup_channel(channel_t *chan);

extern uint64_t stats_n_padding_cells_processed;
extern uint64_t stats_n_create_cells_processed;
extern uint64_t stats_n_created_cells_processed;
extern uint64_t stats_n_relay_cells_processed;
extern uint64_t stats_n_destroy_cells_processed;

#endif

