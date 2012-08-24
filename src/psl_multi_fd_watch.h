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
 * @file psl_multi_fd_watch.h
 * @ingroup psl_internal 
 * 
 * @brief  Efficient multi-file descriptor watch GSource
 *         implementation.  For use by the non-blocking
 *         psl_host_lookup, SSL GIOChannel GSource, and possibly
 *         for monitoring of the SSL socket.
 * 
 * *****************************************************************************
 */
#ifndef PSL_MULTI_FD_WATCH_H__
#define PSL_MULTI_FD_WATCH_H__

#include "psl_build_config.h"

#include <sys/select.h>
#include <glib.h>

#include "palmsockerror.h"


#if defined(__cplusplus)
extern "C" {
#endif

/**
 * PslMultiFdWatchSource - Opaque type definition of our
 * multi-fd watch source.
 *
 * A PslMultiFdWatchSource pointer may be cast directly to
 * GSource pointer for use with g_source functions.
 */
typedef struct PslMultiFdWatchSourceInfo_ PslMultiFdWatchSource;


/**
 * Poll record provided by the PslMultiFdWatchSourceCb callback for
 * each ready file descriptor.
 */
typedef struct {
    /**
     * file descriptor from the watch set
     */
    int             fd; 

    /**
     * Events requested for fd via
     * psl_multi_fd_watch_add_or_update_fd()
     */
    GIOCondition    reqEvents;

    /**
     * Events that were indicated on fd
     * 
     * @note Any of the following failure conditions may be
     *       indicated independent of the requested conditions:
     *       G_IO_ERR, G_IO_HUP, and G_IO_NVAL. _WARNING_: once they
     *       occur, these failure conditions are permanent; so, in
     *       order to avoid an infinite loop, the corresponding FD
     *       MUST be removed from the watch set.
     */
    GIOCondition    indEvents;
} PslMultiFdPollRec;


/**
 * PslMultiFdWatchSourceCb: the type of user callback function to set
 * when calling g_source_set_callback() on instances of
 * PslMultiFdWatchSource.
 * 
 * @param userData The data pointer that was passed to
 *                 g_source_set_callback()
 * 
 * @param pollrecs An array of PslMultiFdPollRec structures
 *            representing ready file descriptors, or NULL if
 *            none were ready.
 * 
 * @param numrecs Number of elements in the pollrecs array, or 0
 *               if none.
 * 
 * @return gboolean It should return FALSE if the source should
 *         be removed from the gmain context (which would be
 *         equivalent to calling g_source_destroy() on the
 *         PslMultiFdWatchSource instance that emitted this
 *         callback);
 */
typedef gboolean PslMultiFdWatchSourceCb(gpointer userData,
                                         const PslMultiFdPollRec* pollrecs,
                                         int numrecs);

/**
 * Create a new multi-fd watch instance with a default timeout
 * value of -1 (infinite poll wait) and reference count of 1.
 * 
 * @return PslMultiFdWatchSource* A new multi-fd watch source
 *         instance on success, NULL on failure.
 * 
 * @note The usual g_source semantics apply (g_source_unref(),
 *       etc.)
 * 
 * @see g_source_attach, g_source_set_callback,
 *      g_source_destroy, g_source_unref
 */
PslMultiFdWatchSource*
psl_multi_fd_watch_new(void);


/**
 * Sets/updates the timeout value on the source.  This will
 * cause the source to dispatch the user callback at
 * expiry_time=(next poll start time + timeout) if none of the
 * file descriptors are ready before that time.
 * 
 * If sockets are ready before the timer's expiration, and the
 * timeout value has not been changed by a new call to
 * psl_multi_fd_watch_set_poll_timeout, the same timeout shall
 * be re-applied at the beginning of the poll cycle following
 * the user callback dispatch.
 * 
 * @note A timeout may be set and continues to function even if
 *       there are no file descriptors in the watch set.  When
 *       the watch set is empty, this source will operate like a
 *       repeating interval timer (unless set to infinite
 *       timeout)
 * 
 * @param source A non-NULL PslMultiFdWatchSource instance
 * @param timeoutMillisec either non-negative (>= 0) timeout in
 *                        milliseconds or -1 for infinite
 * 
 * @return 0 on success, non-zero PslError error code on error
 */
PslError
psl_multi_fd_watch_set_poll_timeout(PslMultiFdWatchSource* source,
                                    int timeoutMillisec);


/**
 * Add a new file-descriptor to the watch set.  Your callback
 * function (PslMultiFdWatchSourceCb) will be called when the
 * requested conditions (or any of G_IO_ERR, G_IO_HUP, and
 *       G_IO_NVAL) are detected.
 * 
 * @param source A non-NULL PslMultiFdWatchSource instance
 * 
 * @param fd The file descriptor to either add or update
 * 
 * @param conditions The set of conditions to monitor on the
 *                  file descriptor (G_IO_IN, G_IO_OUT, etc.);
 *                  this will replace the prior conditions for
 *                  an fd that was alredy in the watch set; you
 *                  may pass zero (cast to GIOCondition) to
 *                  suspend monitoring.
 * 
 * @note If conditions arg is non-zero, any of the following
 *       failure conditions may be indicated independent of the
 *       specific requested conditions: G_IO_ERR, G_IO_HUP, and
 *       G_IO_NVAL. _WARNING_: once they occur, these failure
 *       conditions are permanent; so, in order to avoid an
 *       infinite loop, the watch instance MUST be destroyed.
 * 
 * @return 0 on success, non-zero PslError error code on error
 */
PslError
psl_multi_fd_watch_add_or_update_fd(PslMultiFdWatchSource* source,
                                    int fd,
                                    GIOCondition conditions);

/**
 * Obtains the count of file descriptors in the watch set.
 * 
 * @param source A non-NULL PslMultiFdWatchSource instance
 * 
 * @return the count of file descriptors in the watch set
 */
int
psl_multi_fd_watch_get_fd_count(PslMultiFdWatchSource* source);


/**
 * Remove a file descriptor from the watch set
 * 
 * @param source A non-NULL PslMultiFdWatchSource instance
 * @param fd the file-descriptor to be removed;
 * 
 * @return 0 on success, non-zero PslError error code on error
 */
PslError
psl_multi_fd_watch_remove_fd(PslMultiFdWatchSource* source, int fd);



/**
 * Removes all file descriptors and sets timeout to
 * "infinite" so it won't get dispatched again until we tell it
 * otherwise.
 * 
 * @param source A non-NULL PslMultiFdWatchSource instance
 * 
 * @return 0 on success, non-zero PslError error code on error
 */
PslError
psl_multi_fd_watch_reset(PslMultiFdWatchSource* source);



#if defined(__cplusplus)
}
#endif

#endif // PSL_MULTI_FD_WATCH_H__
