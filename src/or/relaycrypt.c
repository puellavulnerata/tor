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

/* #error Threaded relaycrypt is not finished yet; turn it off. */

/*
 * This is the master data structure tracking threaded relaycrypt status;
 * only one should exist per Tor process, and it gets created in
 * relaycrypt_init() and freed in relaycrypt_free_all().  It has two
 * lists of tracked objects: a list of active worker thread structures
 * of type relaycrypt_thread_t and a list of jobs of type
 * relaycrypt_job_t.
 */

struct relaycrypt_dispatcher_s {
  /*
   * How many worker threads do we want to have?  Use this in
   * relaycrypt_set_num_workers() to figure out how many to start
   * or stop.
   */
  int num_workers_wanted;
  /*
   * List of relaycrypt_thread_t instances; no lock needed since these
   * are always added and removed in the main thread.
   */
  smartlist_t *threads;
  /*
   * List of relaycrypt_job_t instances; jobs are added and may have their
   * status changed by the main thread if it tries to queue a cell to a
   * (circuit, direction) tuple which does not already have one, and
   * may have their status modified by a worker thread, or be removed
   * if the worker thread finishes the job and it has been marked dead
   * (circuit closed) by the main thread while the worker held it.
   * Main or worker threads should hold jobs_lock for access to this.
   * If locking both jobs_lock and the per-job lock in relaycrypt_job_t,
   * lock this one first so we know we can't deadlock.
   */
  smartlist_t *jobs;
  /*
   * TODO need jobs_lock mutex - check if we have a portable tor_mutex_t
   * or equivalent or need to implement one.
   */
};

/*
 * State of a relaycrypt job and cell queues
 */

struct relaycrypt_job_s {
  /* TODO mutex for state changes and queue access */
  /*
   * Circuit this job is for *outgoing* cells on, or NULL if the circuit
   * has been closed and this job should go away.  This should be constant
   * for the lifetime of the job except that the main thread may change it
   * to NULL once if a circuit dies; since writing a pointer should be atomic
   * on reasonable machines it'll be safe to check without locking if the
   * workers want to poll this to see if they should give up and exit early.
   */
  circuit_t *circ;
  /*
   * Direction on circ this job crypts
   */
  cell_direction_t dir;
  /*
   * State of this job object:
   *
   * RELAYCRYPT_JOB_IDLE:
   *
   *   No cells are queued to be crypted, but the job object sticks around
   *   for when some next show up and to hold any crypted cells the main
   *   thread hasn't seen yet.  The worker field should be NULL and the input
   *   queue should be empty.
   *
   * RELAYCRYPT_JOB_READY:
   *
   *   Cells are available on the input queue and this job is eligible for
   *   dispatch, but hasn't been dispatched yet.  The worker field should be
   *   NULL and the input queue should be non-empty.
   *
   * RELAYCRYPT_JOB_RUNNING:
   *
   *   A worker is processing cells on this job; the worker field should point
   *   to it.
   *
   * RELAYCRYPT_JOB_DEAD:
   *
   *   A worker finished this and found the circuit field had been set to
   *   NULL, indicating a dead circuit.  It should be freed at some point.
   *   The worker field should be NULL.
   */
  enum {
    RELAYCRYPT_JOB_IDLE,
    RELAYCRYPT_JOB_READY,
    RELAYCRYPT_JOB_RUNNING,
    RELAYCRYPT_JOB_DEAD
  } state;
  /* If this is in RELAYCRYPT_JOB_RUNNING, what worker has it? */
  relaycrypt_thread_t *worker;
  /*
   * TODO cell queues - simple smartlist at first, maybe, but we probably
   * want an efficient way for the worker thread to snarf a whole block of
   * cells at once from the input without having to repeatedly lock/unlock
   * or hold a lock that the main thread might want while doing CPU-intensive
   * crypto ops.
   */
};

/*
 * State of a relaycrypt worker
 */

struct relaycrypt_thread_s {
  /* TODO lock for worker state access/changes */
  /*
   * State of this worker:
   *
   * RELAYCRYPT_WORKER_STARTING:
   *
   *   The worker was just created and hasn't set its state to IDLE yet;
   *   the job field should be NULL.
   *
   * RELAYCRYPT_WORKER_IDLE:
   *
   *   The worker is waiting to be dispatched; the job field should be NULL
   *
   * RELAYCRYPT_WORKER_WORKING:
   *
   *   The worker is working; the job field should be the relaycrypt_job_t
   *   it is working on.
   *
   * RELAYCRYPT_WORKER_DEAD:
   *
   *   The worker has been told to exit and either has or is about to; the
   *   main thread should join and clean up dead workers at some point.
   */
  enum {
    RELAYCRYPT_WORKER_STARTING,
    RELAYCRYPT_WORKER_IDLE,
    RELAYCRYPT_WORKER_WORKING,
    RELAYCRYPT_WORKER_DEAD
  } state;
  /*
   * Flag to indicate the worker should be told to exit next time it asks
   * for more work; this is initially 0 and may be set to 1 once by the main
   * thread.
   */
  unsigned int exit_flag:1;
  /*
   * Job the worker is currently working on, if in RELAYCRYPT_WORKER_WORKING
   */
  relaycrypt_job_t *working_on;
  /*
   * TODO thread object - check if we have a portable tor_thread_t or need to
   * write one.
   */
};

/*
 * Static relaycrypt function declarations and descriptive comments
 */

/**
 * Main loop for relaycrypt worker threads; takes the thread structure
 * as an argument and returns when the thread exits.
 */

static void relaycrypt_worker_main(relaycrypt_thread_t *thr);

/**
 * Get a relaycrypt_job_t for this thread to work on, or block until one is
 * available.  This returns NULL to signal that this worker should exit.
 */

static relaycrypt_job_t * relaycrypt_worker_get_job(relaycrypt_thread_t *thr);

/**
 * Release a relaycrypt job and become idle from a worker thread
 */

static void
relaycrypt_worker_release_job(relaycrypt_thread_t *thr,
                              relaycrypt_job_t *job);

/*
 * Global variables
 */

static relaycrypt_dispatcher_t *rc_dispatch = NULL;

/*
 * Function implementations (main thread functions)
 */

void
relaycrypt_init(void)
{
  tor_assert(!rc_dispatch);

  rc_dispatch = tor_malloc_zero(sizeof(*rc_dispatch));

  /*
   * We do not create any threads here - that happens in
   * relaycrypt_set_num_workers() later on.
   */
}

/*
 * Function implementations (worker thread functions)
 */

/**
 * Main loop for relaycrypt worker threads; takes the thread structure
 * as an argument and returns when the thread exits.
 */

static void
relaycrypt_worker_main(relaycrypt_thread_t *thr)
{
  relaycrypt_job_t *job = NULL;

  tor_assert(rc_dispatch);
  tor_assert(thr);

  while ((job = relaycrypt_worker_get_job(thr))) {
    /* Done with this job, return it to the dispatcher */
    relaycrypt_worker_release_job(thr, job);
  }

  /* If relaycrypt_worker_get_job(), time to exit */
}

#endif

