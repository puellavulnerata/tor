/* Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relaycrypt.h
 * \brief Header file for relaycrypt.c.
 **/

#ifndef TOR_RELAYCRYPT_H
#define TOR_RELAYCRYPT_H
#ifdef TOR_USES_THREADED_RELAYCRYPT

#include "or.h"

/* The corresponding structs are defined in relaycrypt.c */
typedef struct relaycrypt_dispatcher_s relaycrypt_dispatcher_t;
typedef struct relaycrypt_thread_s relaycrypt_thread_t;

/*
 * Declarations for relaycrypt functions intended to be called  from
 * the main thread; see relaycrypt.c for static declarations of worker-
 * thread functions.
 */

/**
 * This is intended to be called by the main thread to give a cell to
 * the relaycrypt workers.  It adds (circuit_t, direction) to the
 * work queue if it is not already present, and will either queue it
 * or wake up a worker if one is idle.  The main thread will
 * receive the crypted cell back in TODO.
 */

void relaycrypt_queue_cell(circuit_t *circ, cell_direction_t dir,
                           cell_t *cell);

/**
 * Call this from the main thread periodically or when notified to handle
 * crypted cells.  It iterates through all relaydispatcher_job_t instances
 * with available output and moves the cells onto the corresponding
 * circuit's output queue.  This corresponds to the second half (after
 * relay_crypt()) part of the old circuit_receive_relay_cell().
 *
 * TODO how does this get called promptly when output becomes available?
 */

void relaycrypt_handle_output(void);

/**
 * Alternately, call this to handle crypted cells on just one (circuit,
 * direction) tuple.
 */

void relaycrypt_handle_one_circuit(circuit_t *circ, cell_direction_t dir);

/*
 * Initialization/management functions for the main thread to call
 */

/**
 * Call this at startup to initialize relaycrypt; note that this does not
 * start any worker threads, so you should use relaycrypt_set_num_workers()
 * after this.
 */

void relaycrypt_init(void);

/**
 * Call this to shut down all active workers, join them and then free
 * all relaycrypt data.
 */

void relaycrypt_free_all(void);

/**
 * Get the number of worker threads
 */

int relaycrypt_get_num_workers(void);

/**
 * Set the number of worker threads; this may start more workers or tell some
 * to shut down as needed; if it shuts workers down it does not wait for them
 * to exit before returning, but no more jobs will be dispatched to them.
 */

void relaycrypt_set_num_workers(int threads);

/**
 * Get the current job size
 */

int relaycrypt_get_cells_per_dispatch(void);

/**
 * Set the job size for all future job dispatches; this controls the maximum
 * number of cells a worker thread will try to process before returning the
 * job to the dispatcher and requesting a fresh one.
 *
 * This is an important parameter; it controls how often a worker thread
 * becomes available, and so how long a circuit may have to wait for service
 * when there are more queued jobs than workers.  Setting it too high may
 * cause problematic latency, but lower values have more threading overhead.
 * For now, it'll be a tunable, but... TODO measure speed and set this to
 * something sane by default at runtime.
 */

void relaycrypt_set_cells_per_dispatch(int cells);

#endif
#endif

