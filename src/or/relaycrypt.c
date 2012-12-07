/* Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay.c
 * \brief Handle relay cell encryption in worker threads and related
 * job dispatching and signaling.
 **/

#include "or.h"
#include "relaycrypt.h"
#include "tor_queue.h"

#ifdef TOR_USES_THREADED_RELAYCRYPT

/* #error Threaded relaycrypt is not finished yet; turn it off. */

/*
 * Several of these structures have mutexes; observe these rules to avoid
 * deadlock:
 *
 * 1.) Never hold the mutexes for two relaycrypt_job_t or relaycrypt_thread_t
 *     structures simultaneously.
 *
 * 2.) If you hold more than one mutex for different types of structure at
 *     once, acquire them in this order:
 *
 *     [relaycrypt_dispatcher_t], relaycrypt_thread_t, relaycrypt_job_t
 *
 *     where [relaycrypt_dispatcher_t] could be jobs_lock, jobs_lock
 *     then threads_lock, or threads_lock, but not threads_lock then
 *     jobs_lock.
 */

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
   * Lock this for access to the threads list
   */
  tor_mutex_t *threads_lock;
  /*
   * How many worker threads do we want to have?  Use this in
   * relaycrypt_set_num_workers() to figure out how many to start
   * or stop.  This should be the number of entries in the worker
   * list which are not in the RELAY_WORKER_DEAD state and do
   * not have exit_flag set.
   */
  int num_workers;
  /*
   * List of relaycrypt_thread_t instances; no lock needed since these
   * are always added and removed in the main thread.
   */
  LIST_HEAD(relaycrypt_thread_list_s, relaycrypt_thread_s) threads;

  /*
   * Lock this for access to the jobs list
   */
  tor_mutex_t *jobs_lock;
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
};

/*
 * State of a relaycrypt job and cell queues
 */

struct relaycrypt_job_s {
  /* Mutex for state changes and queue access */
  tor_mutex_t *job_lock;

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
  /*
   * Lock this for worker state access
   */
  tor_mutex_t *thread_lock;
  /*
   * Condition variable to wake up this worker; when the worker blocks
   * in relaycrypt_worker_get_job(), it will wait on this while holding
   * thread_lock.  To wake it up (if you are either queueing a job and
   * find this idle thread to start it right away, or you are
   * relaycrypt_slay_worker() and have just set exit_flag, signal this
   * and then release the lock to let the worker thread run.
   */
  tor_cond_t *thread_cond;

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
   *   The worker is waiting to be dispatched; the job field should be NULL.
   *   The worker thread should enter this state right before it waits on
   *   thread_cond, which releases and re-acquires thread_lock, so if from
   *   some other thread you see state == RELAYCRYPT_WORKER_IDLE *while
   *   holding thread_lock*, it is safe to infer that the worker is currently
   *   waiting on the condition variable, or the condition variable has been
   *   signalled already and the worker is waiting to re-acquire the lock.
   *   If only the main thread or the worker thread ever hold thread_lock and
   *   only the main thread ever signals thread_cond, then only the former
   *   case is possible.
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
   * The thread for this worker
   */
  tor_thread_t *thread;

  /*
   * LIST_ENTRY() keeps pointer to next and prev worker in the dispatcher
   * thread list.
   */
  LIST_ENTRY(relaycrypt_thread_s) list_entry;
};

/*
 * Static relaycrypt function declarations and descriptive comments
 *
 * Main thread functions:
 */

/**
 * Kill a worker or schedule it to exit if possible, and return 1 if we
 * did so or 0 otherwise; this is used as a helper function for
 * relaycrypt_set_num_workers().  Call this while holding worker->
 * thread_lock.
 */

static int relaycrypt_slay_worker(relaycrypt_thread_t *worker);

/**
 * Create a new worker thread and add it to the dispatcher list; this is
 * a helper function for relaycrypt_set_num_workers(), and you should call
 * it while holding rc_dispatch->threads_lock.
 */

static int relaycrypt_spawn_worker(void);

/**
 * Check if a worker is eligible to be killed at a given pass of
 * relaycrypt_set_num_workers(); call this while holding worker->
 * thread_lock.
 */

static int
relaycrypt_worker_eligible_for_death(relaycrypt_thread_t *worker,
                                     int pass);

/**
 * Join all workers in the RELAYCRYPT_WORKER_DEAD state or, if the block
 * flag is true, also with the exit_flag set, and when they have exited
 * remove them from the worker list.
 */

static void relaycrypt_join_workers(int block);

/*
 * Worker thread functions:
 */

/**
 * Entry point to satisfy thread func prototype and call worker_main
 */

static void * relaycrypt_worker_entry_point(void *arg);

/**
 * Main loop for relaycrypt worker threads; takes the thread structure
 * as an argument and returns NULL when the thread exits.
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

/**
 * Call this at startup to initialize relaycrypt; note that this does not
 * start any worker threads, so you should use relaycrypt_set_num_workers()
 * after this.
 */

void
relaycrypt_init(void)
{
  tor_assert(!rc_dispatch);

  rc_dispatch = tor_malloc_zero(sizeof(*rc_dispatch));

  /* We'll need threads_lock */
  rc_dispatch->threads_lock = tor_mutex_new();
  /*
   * We do not create any threads here - that happens in
   * relaycrypt_set_num_workers() later on.  Just initialize
   * an empty list for now.
   */
  rc_dispatch->num_workers = 0;
  LIST_INIT(&(rc_dispatch->threads));

  /* We'll need jobs_lock too, but ... TODO implement job list */
  rc_dispatch->jobs_lock = tor_mutex_new();
}

/**
 * Call this to shut down all active workers, join them and then free
 * all relaycrypt data.
 */

void
relaycrypt_free_all(void)
{
  if (rc_dispatch) {
    /* First, tell all active workers to shut down */
    relaycrypt_set_num_workers(0);
    /* Wait for them to exit and join them */
    relaycrypt_join_workers(1);
    /* TODO free job/worker lists */
    /* Free the locks */
    tor_mutex_free(rc_dispatch->threads_lock);
    tor_mutex_free(rc_dispatch->jobs_lock);
    tor_free(rc_dispatch);
    rc_dispatch = NULL;
  }
}

/**
 * Get the number of worker threads
 */

int
relaycrypt_get_num_workers(void)
{
  int rv;

  if (rc_dispatch) {
    tor_assert(rc_dispatch->threads_lock);
    /* Acquire the lock */
    tor_mutex_acquire(rc_dispatch->threads_lock);
    rv = rc_dispatch->num_workers;
    /* Release */
    tor_mutex_release(rc_dispatch->threads_lock);

    return rv;
  } else {
    /* If we're not inited, there are plainly zero workers */
    return 0;
  }
}

/**
 * Check if a worker is eligible to be killed on a particular pass of
 * relaycrypt_set_num_workers(); see comments in that function for
 * definitions of the passes.
 */

static int
relaycrypt_worker_eligible_for_death(relaycrypt_thread_t *worker,
                                     int pass)
{
  int result;

  tor_assert(worker);

  switch (pass) {
    case 0:
      /*
       * On the first pass, we only kill workers that are in
       * RELAYCRYPT_WORKER_IDLE and do not already have their
       * exit flag set.
       */
      result = ((worker->state == RELAYCRYPT_WORKER_IDLE) &&
                !(worker->exit_flag));
      break;
    case 1:
      /*
       * Like pass 0, but RELAYCRYPT_WORKER_STARTING is also
       * eligible.
       */
      result = (((worker->state == RELAYCRYPT_WORKER_IDLE) ||
                 (worker->state == RELAYCRYPT_WORKER_STARTING)) &&
                !(worker->exit_flag));
      break;
    case 2:
      /*
       * In pass 2, we resort to delayed exits from RELAYCRYPT_WORKER_WORKING
       */
      result = (((worker->state == RELAYCRYPT_WORKER_IDLE) ||
                 (worker->state == RELAYCRYPT_WORKER_STARTING) ||
                 (worker->state == RELAYCRYPT_WORKER_WORKING)) &&
                !(worker->exit_flag));
      break;
    default:
      /* This shouldn't happen, just say it's not eligible */
      result = 0;
      break;
  }

  return result;
}

/**
 * Kill a worker or schedule it to exit if possible, and return 1 if we
 * did so or 0 otherwise; this is used as a helper function for
 * relaycrypt_set_num_workers().  Call this while holding worker->
 * thread_lock.
 */

static int
relaycrypt_slay_worker(relaycrypt_thread_t *worker)
{
  int rv = 0;

  tor_assert(worker);

  /*
   * We already hold the lock, so we just have to check the state of
   * the worker, and adjust the state and/or exit_flag and possibly
   * signal the condition variable.  Then when we release the lock,
   * nature takes its course.
   */
  switch (worker->state) {
    case RELAYCRYPT_WORKER_STARTING:
      /* We'll need a wire coat hanger for this... or maybe just exit_flag */
      if (!(worker->exit_flag)) {
        worker->exit_flag = 1;
        /*
         * When it tries to get its first job, it'll see this instead and go
         * directly to RELAYCRYPT_WORKER_DEAD.
         */
        rv = 1;
      }
      /* else someone already got here */
      break;
    case RELAYCRYPT_WORKER_IDLE:
      /*
       * Yay, we get to wake it up and murder it while it's still stumbling
       * around cursing and trying to find coffee!
       *
       * Set exit_flag and signal; when it wakes up and sees it's still
       * in RELAYCRYPT_WORKER_IDLE and has exit flag, off it goes.
       */
      if (!(worker->exit_flag)) {
        worker->exit_flag = 1;
        rv = 1;
      }
      /*
       * Else we must have gotten to it before it re-acquired the lock
       * after waking up.  Fortunately, executions are idempotent.
       */
      tor_cond_signal_one(worker->thread_cond);
      break;
    case RELAYCRYPT_WORKER_WORKING:
      /*
       * It's working, so we set exit_flag to subtly suggest that coffins
       * are cheaper than retirement homes.  It'll get the bad news when it
       * finishes and requests a new job, and then go to
       * RELAYCRYPT_WORKER_DEAD and exit.
       */
      if (!(worker->exit_flag)) {
        worker->exit_flag = 1;
        rv = 1;
      }
      /* or else it has to die twice? */
      break;
    case RELAYCRYPT_WORKER_DEAD:
      /*
       * This worker is no more; it has ceased to be.  It's gone to meet its
       * top stack frame.  It's run down the curtain and joined the free
       * memory pool.  This is an ex-thread!
       *
       * Yeah, this is a no-op case.
       */
      break;
    default:
      /* Bogus state */
      tor_assert(0);
      break;
  }

  return rv;
}

/**
 * Create a new worker thread and add it to the dispatcher list; this is
 * a helper function for relaycrypt_set_num_workers(), and you should call
 * it while holding rc_dispatch->threads_lock.
 */

static int
relaycrypt_spawn_worker(void)
{
  relaycrypt_thread_t *worker;
  int rv = 0;

  worker = tor_malloc_zero(sizeof(*worker));
  worker->thread_lock = tor_mutex_new();
  worker->thread_cond = tor_cond_new();
  /*
   * Acquire the lock so that once we start the thread, it can't look
   * at its own state until we're done inserting it into the list.
   */
  tor_mutex_acquire(worker->thread_lock);
  /*
   * Set the initial state; the worker will go to RELAYCRYPT_WORKER_IDLE
   * later.
   */
  worker->state = RELAYCRYPT_WORKER_STARTING;
  /* Start up the thread */
  worker->thread = tor_thread_start(relaycrypt_worker_entry_point, worker);
  /* Success? */
  if (worker->thread) {
    rv = 1;
    /* Insert it */
    LIST_INSERT_HEAD(&(rc_dispatch->threads), worker, list_entry);
  }
  /* We're done now, release the lock and let the worker get started */
  tor_mutex_release(worker->thread_lock);

  /* If we failed, log a warning and free */
  if (rv == 0) {
    log_warn(LD_GENERAL,
             "Threaded relaycrypt failed to spawn a worker (had %d already)",
             rc_dispatch->num_workers);
    tor_mutex_free(worker->thread_lock);
    tor_free(worker);
  }

  /* Return the status code */
  return rv;
}

/**
 * Set the number of worker threads; this may start more workers or tell some
 * to shut down as needed; if it shuts workers down it does not wait for them
 * to exit before returning, but no more jobs will be dispatched to them.
 *
 * TODO Important edge case!: make sure that when the number of threads goes
 * to zero *and all the slain threads have actually exited*, we finish off
 * any queued jobs from the main thread to complete the transition to non-
 * threaded mode cleanly.
 */

void
relaycrypt_set_num_workers(int threads)
{
  const int max_pass = 3;
  int workers_slain, pass, workers_started;
  relaycrypt_thread_t *curr;

  tor_assert(rc_dispatch);
  tor_assert(threads >= 0);
  tor_assert(rc_dispatch->threads_lock);

  /* First, get the lock */
  tor_mutex_acquire(rc_dispatch->threads_lock);

  /* Now spawn or kill workers as needed */
  if (threads > rc_dispatch->num_workers) {
    /* We need to spawn some new worker threads */
    workers_started = 0;
    while (workers_started < threads - rc_dispatch->num_workers) {
      if (relaycrypt_spawn_worker()) {
        ++workers_started;
      } else {
        /* If for some reason we can't start one, don't try any more */
        break;
      }
    }
    /* Adjust the worker count */
    rc_dispatch->num_workers += workers_started;
  } else if (threads < rc_dispatch->num_workers) {
    /*
     * We need to tell some worker threads to die; this is the more complex
     * case because we should kill idle workers first so they can go away
     * immediately, and only after the workers in RELAYCRYPT_WORKER_IDLE
     * or RELAYCRYPT_WORKER_STARTING should we set exit_flag on the worker.
     *
     * Count how many we've told to die so far in workers_slain, and how
     * many passes we've made in pass:
     *
     * First pass:
     *
     *   Only kill workers in RELAYCRYPT_WORKER_IDLE with no exit flag set.
     *
     * Second pass:
     *
     *   Now RELAYCRYPT_WORKER_STARTING with no exit flag already set is
     *   eligible as well.
     *
     * Third pass:
     *
     *   Workers in RELAYCRYPT_WORKER_WORKING become eligible as well; these
     *   will be delayed exits when they finish their job or notice
     *   exit_flag.
     *
     * We use the helper function relaycrypt_worker_eligible_for_death() with
     * the worker and our pass number; only call this on a worker for which the
     * lock is held.
     */

    workers_slain = pass = 0;
    curr = NULL;

    while ((workers_slain < rc_dispatch->num_workers - threads) &&
           (pass < max_pass)) {
      if (!curr) {
        /* We're just starting this pass, so put it at the head of the list */
        curr = LIST_FIRST(&(rc_dispatch->threads));
      }

      /*
       * It's safe to check this without locking curr, since this function is
       * the only thing that changes exit_flag, and it holds threads_lock for
       * the dispatcher, so there can't be another instance active in this
       * loop.
       */
      if (curr && !(curr->exit_flag)) {
        /*
         * We do need to have the worker lock for this bit, since it looks
         * at the worker state and the worker thread itself might mess with
         * that.
         */
        tor_assert(curr->thread_lock);
        tor_mutex_acquire(curr->thread_lock);
        /* Can we pack this one off to Hades on this pass? */
        if (relaycrypt_worker_eligible_for_death(curr, pass)) {
          /* Yes! */
          if (relaycrypt_slay_worker(curr)) {
            ++workers_slain;
          }
        }
        /* No, we'll have to try on a future pass */
        tor_mutex_release(curr->thread_lock);
      }
      /* else it's already on the way out, so we can't kill it */

      /*
       * Now advance curr, and if we hit the end of the list, also advance
       * pass, and we'll start curr over at the head of the list on the next
       * iteration if we aren't finished yet.
       */
      if (curr) curr = LIST_NEXT(curr, list_entry);

      if (!curr) {
        ++pass;
      }
    }

    /* Adjust the worker count */
    rc_dispatch->num_workers -= workers_slain;
  }
  /* else no change, so nothing to do */

  /* Release the lock, and we're done */
  tor_mutex_release(rc_dispatch->threads_lock);
}

/*
 * Function implementations (worker thread functions)
 */

/**
 * Entry point to satisfy thread func prototype and call worker_main
 */

static void *
relaycrypt_worker_entry_point(void *arg)
{
  relaycrypt_thread_t *thr = (relaycrypt_thread_t *)arg;

  tor_assert(thr);
  relaycrypt_worker_main(thr);

  return NULL;
}

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

