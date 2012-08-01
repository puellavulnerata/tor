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

channel_t * channel_tls_connect(const tor_addr_t *addr, uint16_t port,
                                const char *id_digest);

#endif

