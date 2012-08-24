/* @@@LICENSE
*
*      Copyright (c) 2009-2012 Hewlett-Packard Development Company, L.P.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

/**
 * *****************************************************************************
 * @file psl_multi_fd_watch.c
 * @ingroup psl_internal 
 * 
 * @brief  Efficient multi-file descriptor watch GSource
 *         implementation.  For use by the non-blocking
 *         psl_host_lookup, SSL GIOChannel GSource, and possibly
 *         for monitoring of the SSL socket.
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>
#include <time.h>
#include <glib.h>

#include "palmsockerror.h"

#include "psl_common.h"
#include "psl_log.h"
#include "psl_assert.h"
#include "psl_time_utils.h"
#include "psl_multi_fd_watch.h"

/// Represents infinite timeout
#define MULTI_FD_WATCH_INFINITE_MSEC    (-1)

/// GIOCondition result values that indicate premanent failure
#define MULTI_FD_WATCH_PERM_FAILURE_IO_CONDS PSL_FAIL_GIOCONDITIONS


/**
 * A file descriptor container.
 *
 * @note Instances of the structure that are passed to glib for
 *       polling must preserve their memory address until we
 *       explicitly remove them from glib's poll set.
 */
typedef struct {
    bool                    pollAdded;  ///< via g_source_add_poll()
    GPollFD                 pollFd;
} PslMultiFdDescriptor;


/**
 * Our private source data type
 */
struct PslMultiFdWatchSourceInfo_ {
    GSource             base;   ///< MUST BE FIRST DATA MEMBER!

    /// Set to TRUE whenever the timer needs to be restarted at the
    /// beginning of the next poll cycle (next time our _prepare handler is
    /// called)
    gboolean            restartTimer;

    /// Timeout (in milliseconds) requested by user; -1 = "infinite";
    /// defaults to -1 (infinite)
    gint                timeoutMillisec;

    /// Our timeout expiry in monotonic time;
    /// @note Valid only when timeout is not infinite
    struct timespec     when;

    /// Our table of file descriptors of type PslMultiFdDescriptor
    /// keyed by the raw fd number.
    /// 
    /// @note We don't expect excessively frequent churn of file descriptors,
    /// so this simple schema should suffice for performance.
    /// 
    GHashTable*         descTable;

    /// Cached array of PslMultiFdPollRec elements for passing ready file
    /// descriptor info to the user via PslMultiFdWatchSourceCb.  
    /// 
    /// @note We have to pass copies (versus pointers to our internal 
    /// structures) because the user may make calls from his callback that would
    /// cause some of the internal PollFD strctures to be modified or deleted
    GArray*             cachedReadyPollFdArray;

};


static gboolean
multi_fd_watch_prepare(GSource* source, gint* timeout);

static gboolean
multi_fd_watch_check(GSource* source);

static gboolean
multi_fd_watch_dispatch(GSource* source,
                        GSourceFunc callback,
                        gpointer user_data);

static void
multi_fd_watch_finalize(GSource* source);

static gint
multi_fd_watch_update_expiry_time(PslMultiFdWatchSource* source);

static gboolean
multi_fd_watch_is_timer_expired(PslMultiFdWatchSource* source);

/**
 * Table of GSource methods for the multi-fd watch source
 *
 * @note g_source_new is declared to acept this table as
 *       non-const
 */
static GSourceFuncs psl_multi_fd_watch_funcs = {
    &multi_fd_watch_prepare,
    &multi_fd_watch_check,
    &multi_fd_watch_dispatch,
    &multi_fd_watch_finalize,
    NULL,
    NULL
};

/** ===========================================================================
 *                            FUNCTIONS
 * ============================================================================
 */


/** ========================================================================
 * =========================================================================
 */
PslMultiFdWatchSource*
psl_multi_fd_watch_new(void)
{
    GSource* const base = g_source_new(&psl_multi_fd_watch_funcs,
                                       sizeof(PslMultiFdWatchSource));
    PslMultiFdWatchSource* const source = (PslMultiFdWatchSource*)base;

    if (!base) {
        goto error_cleanup;
    }

    /**
     * @note g_source_new returns a zero-initialized structure with
     *       the base (GSource) "class" properly set up and with
     *       reference count = 1.
     */

    source->restartTimer = true;
    source->timeoutMillisec = MULTI_FD_WATCH_INFINITE_MSEC;

    source->descTable = g_hash_table_new_full(&g_direct_hash,
                                              &g_direct_equal,
                                              NULL /*key_destroy_func*/,
                                              &g_free/*value_destroy_func*/);
    
    if (!source->descTable) {
        goto error_cleanup;
    }

    PSL_LOG_DEBUGLOW("%s (watch=%p): descriptor table=%p",
                     __func__, source, source->descTable);

    source->cachedReadyPollFdArray = g_array_new(false/*zero_terminated*/,
                                                 false/*clear_*/,
                                                 sizeof(PslMultiFdPollRec));
    if (!source->cachedReadyPollFdArray) {
        goto error_cleanup;
    }

    PSL_LOG_DEBUG("%s (watch=%p): new watch created", __func__, source);
    return source;

error_cleanup:
    PSL_LOG_FATAL("%s: FAILED (out of mem?)", __func__);
    if (base) {

        g_source_unref(base);
    }
    return NULL;
}


/** ========================================================================
 * =========================================================================
 */
PslError
psl_multi_fd_watch_set_poll_timeout(PslMultiFdWatchSource* source,
                                    int const timeoutMillisec)
{
    PSL_LOG_DEBUG("%s (watch=%p), timeout=%d millisec",
                  __func__, source, (int)timeoutMillisec);

    if (timeoutMillisec < -1) {
        PSL_LOG_ERROR("%s (watch=%p): ERROR: passed negative timemeout, " \
                      "but not -1: %d",
                      __func__, source, (int)timeoutMillisec);
        return PSL_ERR_INVAL;
    }

    source->restartTimer = true;

    if (timeoutMillisec == -1) {
        source->timeoutMillisec = MULTI_FD_WATCH_INFINITE_MSEC;
    }

    else { // timeoutMillisec >= 0
        source->timeoutMillisec = timeoutMillisec;
    }

    return 0;
}



/** ========================================================================
 * =========================================================================
 */
PslError
psl_multi_fd_watch_add_or_update_fd(PslMultiFdWatchSource*  const source,
                                    int                     const fd,
                                    GIOCondition            const condition)
{
    PslMultiFdDescriptor* desc;

    PSL_LOG_DEBUG("%s (watch=%p): fd=%d, GIOCondition=0x%lX",
                  __func__, source, (int)fd, (unsigned long)condition);

    desc = (PslMultiFdDescriptor*) g_hash_table_lookup(source->descTable,
                                                       GINT_TO_POINTER(fd));

    /**
     * @note multi_fd_watch_prepare() takes care of adding/removing
     *       our pollFd's from the source's poll list as needed
     */

    if (desc) {
        PSL_LOG_DEBUGLOW(
            "%s (watch=%p): found desc=%p with fd=%d in descriptor table=%p",
            __func__, source, desc, (int)fd, source->descTable);

        desc->pollFd.events = condition;
    }
    else { /// create a new descriptor and add it to the poll set
        desc = g_new0(PslMultiFdDescriptor, 1);
        if (!desc) {
            PSL_LOG_FATAL("%s (watch=%p): ERROR: g_new0 failed",
                          __func__, source);
            return PSL_ERR_MEM;
        }

        desc->pollFd.fd = fd;
        desc->pollFd.events = condition;
        g_hash_table_insert(source->descTable,
                            GINT_TO_POINTER(desc->pollFd.fd),
                            desc);
        PSL_LOG_DEBUGLOW(
            "%s (watch=%p): allocated desc=%p for fd=%d in descriptor table=%p",
            __func__, source, desc, (int)fd, source->descTable);
    }

    return 0;
}



/** ========================================================================
 * =========================================================================
 */
int
psl_multi_fd_watch_get_fd_count(PslMultiFdWatchSource* source)
{
    PSL_LOG_DEBUGLOW("%s (watch=%p)", __func__, source);

    return g_hash_table_size (source->descTable);
}



/** ========================================================================
 * =========================================================================
 */
PslError
psl_multi_fd_watch_remove_fd(PslMultiFdWatchSource* source, int const fd)
{
    gboolean removed;
    PslMultiFdDescriptor* desc;

    PSL_LOG_DEBUGLOW("%s (watch=%p), fd=%d", __func__, source, (int)fd);

    desc = (PslMultiFdDescriptor*) g_hash_table_lookup(source->descTable,
                                                       GINT_TO_POINTER(fd));

    if (!desc) {
        PSL_LOG_ERROR("%s (watch=%p): ERROR: fd=%d not found", __func__,
                      source, (int)fd);
        return PSL_ERR_INVAL;
    }

    if (desc->pollAdded) {
        g_source_remove_poll((GSource*)source, &desc->pollFd);
    }

    removed = g_hash_table_remove(source->descTable, GINT_TO_POINTER(fd));
    PSL_ASSERT(removed);

    return 0;
}



/** ========================================================================
 * =========================================================================
 */
PslError
psl_multi_fd_watch_reset(PslMultiFdWatchSource* source)
{
    PSL_LOG_DEBUG("%s (watch=%p): ENTERING", __func__, source);

    source->restartTimer = true;
    source->timeoutMillisec = MULTI_FD_WATCH_INFINITE_MSEC;

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, source->descTable);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        PslMultiFdDescriptor* desc = (PslMultiFdDescriptor*)value;
        const gint fd = GPOINTER_TO_INT(key);
        PSL_ASSERT(fd == desc->pollFd.fd);

        if (desc->pollAdded) {
            g_source_remove_poll((GSource*)source, &desc->pollFd);
        }
        g_hash_table_iter_remove(&iter);
    }

    PSL_LOG_DEBUGLOW("%s (watch=%p): LEAVING", __func__, source);
    return 0;
}



/** ========================================================================
 * The 'prepare' function of GSourceFuncs
 * 
 * @param base
 * @param timeout @see GSourceFuncs
 * 
 * @return gboolean @see GSourceFuncs
 * 
 * =========================================================================
 */
static gboolean
multi_fd_watch_prepare(GSource* base, gint* timeout)
{
    PSL_LOG_DEBUGLOW("%s (watch=%p)", __func__, base);

    PslMultiFdWatchSource* const source = (PslMultiFdWatchSource*)base;

    /// Clear revents of our pollrecs
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, source->descTable);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        PslMultiFdDescriptor* const desc = (PslMultiFdDescriptor*)value;
        desc->pollFd.revents = 0;

        if (desc->pollFd.events) {
            if (!desc->pollAdded) {
                g_source_add_poll(base, &desc->pollFd);
                desc->pollAdded = true;
            }
        }
        else if (desc->pollAdded) {
            g_source_remove_poll(base, &desc->pollFd);
            desc->pollAdded = false;
        }

        PSL_LOG_DEBUGLOW(
            "%s (watch=%p): iter: table=%p, desc=%p, fd=%d, " \
            "monitoring GIOCondition=0x%lX",
            __func__, source, source->descTable, desc, (int)desc->pollFd.fd,
            (unsigned long)desc->pollFd.events);
    }

    /// Calc remaining timeout
    *timeout = multi_fd_watch_update_expiry_time(source);

    gboolean const readyNow = (0 == *timeout);


    PSL_LOG_DEBUGLOW("%s (watch=%p): %s", __func__, base,
                     readyNow ? "READY" : "NOT READY");
    return readyNow;
}



/** ========================================================================
 * The 'check' function of GSourceFuncs
 * 
 * @param base
 * 
 * @return gboolean @see GSourceFuncs
 * 
 * =========================================================================
 */
static gboolean
multi_fd_watch_check(GSource* base)
{
    PSL_LOG_DEBUGLOW("%s (watch=%p)", __func__, base);

    PslMultiFdWatchSource* const source = (PslMultiFdWatchSource*)base;

    /// If the timer is ready, there is no need to check the fd's
    if (multi_fd_watch_is_timer_expired(source)) {
        PSL_LOG_DEBUGLOW("%s (watch=%p): READY: timeout expired", __func__, base);
        return true;
    }

    /// Check if any of the file descriptors is ready
    gpointer key, value;
    GHashTableIter iter;
    g_hash_table_iter_init(&iter, source->descTable);
    while (g_hash_table_iter_next(&iter, &key, &value)) {

        const GPollFD* const pollFd = &((PslMultiFdDescriptor*)value)->pollFd;

        PSL_LOG_DEBUGLOW(
            "%s (watch=%p): iter: table=%p, desc=%p, fd=%d, " \
            "GIOCondition=(mon:0x%lX, ind:0x%lX)",
            __func__, source, source->descTable, value, (int)pollFd->fd,
            (unsigned long)pollFd->events, (unsigned long)pollFd->revents);


        if ((pollFd->revents &
             (pollFd->events | MULTI_FD_WATCH_PERM_FAILURE_IO_CONDS)) != 0) {
            PSL_LOG_DEBUGLOW("%s (watch=%p): fd=%d is READY", __func__, base,
                             (int)pollFd->fd);
            return true;
        }
    }

    PSL_LOG_DEBUGLOW("%s (watch=%p): NOT READY", __func__, base);
    return false;
}



/** ========================================================================
 * The 'dispatch' function of GSourceFuncs
 * 
 * @param base
 * @param opaqueCb @see GSourceFuncs
 * @param userData @see GSourceFuncs
 * 
 * @return gboolean @see GSourceFuncs
 * 
 * =========================================================================
 */
static gboolean
multi_fd_watch_dispatch(GSource* const base,
                        GSourceFunc opaqueCb,
                        gpointer userData)
{
    PslMultiFdWatchSource* const source = (PslMultiFdWatchSource*)base;
    PslMultiFdWatchSourceCb* const cb = (PslMultiFdWatchSourceCb*)opaqueCb;

    source->restartTimer = true; ///< so it will restart at next poll prepare
    
    if (!cb) {
        PSL_LOG_ERROR("%s (watch=%p): ERROR: multi-fd watch dispatch with " \
                      "NULL user callback ptr: did you forget to call " \
                      "g_source_set_callback()?", __func__, base);
        return false;
    }

    PSL_LOG_DEBUGLOW("%s (watch=%p): preparing to call user's callback",
                     __func__, base);

    /// Construct an array of ready PollFD's
    if (source->cachedReadyPollFdArray->len > 0) {
        g_array_set_size(source->cachedReadyPollFdArray, 0);
    }

    gpointer key, value;
    GHashTableIter iter;
    g_hash_table_iter_init(&iter, source->descTable);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        const GPollFD* const pollFd = &((PslMultiFdDescriptor*)value)->pollFd;

        PSL_LOG_DEBUGLOW(
            "%s (watch=%p): iter: table=%p, desc=%p, fd=%d, " \
            "GIOCondition=(mon:0x%lX, ind:0x%lX)",
            __func__, source, source->descTable, value, (int)pollFd->fd,
            (unsigned long)pollFd->events, (unsigned long)pollFd->revents);

        if ((pollFd->revents & MULTI_FD_WATCH_PERM_FAILURE_IO_CONDS) != 0) {
            PSL_LOG_ERROR("%s: (watch=%p): I/O FAILURE on fd=%d: indicated " \
                          "GIOCondition=0x%lX", __func__, source,
                          (int)pollFd->fd, (unsigned long)pollFd->revents);
        }


        const GIOCondition currentCondition = pollFd->revents &
            (pollFd->events | MULTI_FD_WATCH_PERM_FAILURE_IO_CONDS);
        if (currentCondition) {
            const PslMultiFdPollRec pollRec = {
                .fd = pollFd->fd,
                .reqEvents = pollFd->events,
                .indEvents = currentCondition
            };

            g_array_append_vals(source->cachedReadyPollFdArray, &pollRec, 1);
        }
    }

    /// Dispatch the callback
    const gint numrecs = source->cachedReadyPollFdArray->len;
    const PslMultiFdPollRec* const pollrecs  =
        ((numrecs > 0)
         ? (PslMultiFdPollRec*)source->cachedReadyPollFdArray->data
         : NULL);

    PSL_LOG_DEBUGLOW("%s (watch=%p): Calling user's callback: " \
                     "pollrec array=%p, numelts=%d",
                     __func__, base, pollrecs, (int)numrecs);

    const gboolean stayAttached = cb(userData, pollrecs, numrecs);

    if (!stayAttached) {
        PSL_LOG_DEBUG("%s (watch=%p): user cb requested removal of source",
                      __func__, base);
    }
    return stayAttached;
} //multi_fd_watch_dispatch



/** ========================================================================
 * The 'finalize' function of GSourceFuncs
 * 
 * @param base
 * 
 * =========================================================================
 */
static void
multi_fd_watch_finalize(GSource* base)
{
    PSL_LOG_DEBUG("%s (watch=%p)", __func__, base);

    PslMultiFdWatchSource* const source = (PslMultiFdWatchSource*)base;

    /**
     * @note We may be called with our own data members in a
     *       partially-constructed (but initialized) state if
     *       psl_multi_fd_watch_new failed part way through and
     *       called g_source_unref.
     */

    if (source->descTable) {
        /**
         * @note our "superclass" GSource takes care of removing
         *       our pollFds record pointers from the source's and the
         *       gmain context's pollFd lists when the GSource instance
         *       is being detached from the gmain context, so we don't
         *       need to do it ourselves.
         */

        g_hash_table_destroy(source->descTable);
    }

    if (source->cachedReadyPollFdArray) {
        (void)g_array_free(source->cachedReadyPollFdArray,
                           true/*free_segment*/);
    }
}



/** ========================================================================
 * Update the timeout expiry time
 * 
 * @param source
 * 
 * @return gint: number of milliseconds that remain, or
 *         MULTI_FD_WATCH_INFINITE_MSEC if infinite
 * 
 * =========================================================================
 */
static gint
multi_fd_watch_update_expiry_time(PslMultiFdWatchSource* source)
{
    if (MULTI_FD_WATCH_INFINITE_MSEC == source->timeoutMillisec) {
        PSL_LOG_DEBUGLOW("%s (watch=%p): using infinite timeout", __func__,
                         source);

        source->restartTimer = false;
        return MULTI_FD_WATCH_INFINITE_MSEC;
    }

    gint remainingMillisec;

    if (source->restartTimer) {
        source->restartTimer = false;

        psl_time_get_current_mono_time(&source->when);
        psl_time_add_millisec_to_timespec(&source->when,
                                          source->timeoutMillisec);
        remainingMillisec = source->timeoutMillisec;
    }
    else {

        struct timespec time;
        psl_time_get_current_mono_time(&time);

        bool wouldUnderflow;

        /// 'time - when'
        psl_time_subtract_timespec_abs(&time, &source->when, &wouldUnderflow);
        /// 'time' is now the absolute value of 'time - when'
        if (wouldUnderflow) { /// expiry is still in the future
            remainingMillisec = psl_time_convert_timespec_to_millisec(&time);
        }
        else {
            remainingMillisec = 0; ///< already expired
        }

    }

    PSL_LOG_DEBUGLOW("%s (watch=%p): new mono expiry time: sec=%ld, nsec=%ld",
                     __func__, source, (long)source->when.tv_sec,
                     (long)source->when.tv_nsec);

    return remainingMillisec;

}




/** ========================================================================
 * 
 * @param source
 * 
 * @return TRUE if timer has expired, FALSE if not.
 * 
 * =========================================================================
 */
static gboolean
multi_fd_watch_is_timer_expired(PslMultiFdWatchSource* source)
{
    PSL_LOG_DEBUGLOW("%s (watch=%p)", __func__, source);

    PSL_ASSERT(!source->restartTimer);

    if (MULTI_FD_WATCH_INFINITE_MSEC == source->timeoutMillisec) {
        PSL_LOG_DEBUGLOW("%s (watch=%p): using infinite timeout", __func__,
                         source);
        return false;
    }

    struct timespec now;
    if (!psl_time_get_current_mono_time(&now)) {
        return false;
    }

    if (psl_time_compare_timespecs(&now, &source->when) >= 0) {
        return true;
    }
    else {
        return false;
    }
}




