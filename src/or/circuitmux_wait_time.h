/* * Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux_wait_time.h
 * \brief Header file for circuitmux_wait_time.c
 **/

#ifndef TOR_CIRCUITMUX_WAIT_TIME_H
#define TOR_CIRCUITMUX_WAIT_TIME_H

#include "or.h"
#include "circuitmux.h"

/* Everything but circuitmux_wait_time.c should see this extern */
#ifndef TOR_CIRCUITMUX_WAIT_TIME_C_

extern circuitmux_policy_t wt_policy;

#endif /* !(TOR_CIRCUITMUX_WAIT_TIME_C_) */

#endif /* TOR_CIRCUITMUX_WAIT_TIME_H */

