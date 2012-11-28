/* Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay.c
 * \brief Handle relay cell encryption in worker threads and related
 * job dispatching and signaling.
 **/

#include "or.h"
#include "relaycrypt.h"

#ifdef TOR_USES_THREADED_RELAYCRYPT

#error Threaded relaycrypt is not finished yet; turn it off.

/* TODO */

#endif

