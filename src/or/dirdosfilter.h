/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dirdosfilter.h
 * \brief Header file for dirdosfilter.c.
 **/

#ifndef TOR_DIRDOSFILTER_H
#define TOR_DIRDOSFILTER_H

int dirdosfilter_bump(const tor_addr_t *src_addr,
                           const tor_addr_t *dst_addr,
                           uint16_t dst_port,
                           uint8_t begindir,
                           uint64_t channel_id,
                           circid_t circ_id);
void dirdosfilter_free_all(void);

#ifdef DIRDOSFILTER_PRIVATE

/* TODO STATICS to expose for testing go here */

#endif /* defined(DIRDOSFILTER_PRIVATE) */

#endif /* !defined(TOR_DIRDOSFILTER_H) */

