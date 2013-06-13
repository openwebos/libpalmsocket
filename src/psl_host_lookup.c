/* @@@LICENSE
*
*      Copyright (c) 2009-2013 LG Electronics, Inc.
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
 * @file psl_host_lookup.c
 * @ingroup psl_internal 
 * 
 * @brief  Non-blocking host address lookup.  Implemented as a
 *         wrapper around c-ares API; uses gmainloop context as
 *         execution environment.
 * 
 * @todo Need to make sure that EINTR is handled either by
 *       c-ares or by us
 *
 * @todo Need to take care of SIGPIPE
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <string.h>
#include <netdb.h>
#include <sys/select.h>
#include <glib.h>
#include <ares.h>

#include "palmsocket.h"
#include "palmhostlookup.h"

#include "psl_log.h"
#include "psl_assert.h"
#include "psl_error_utils.h"
#include "psl_multi_fd_watch.h"


enum PslHostLookupState {
    kPslHostLookupState_initializing,
    kPslHostLookupState_initialized,
    kPslHostLookupState_running,
    kPslHostLookupState_finished,
    kPslHostLookupState_destroying
};

/**
 * Our private definition of the lookup session structure
 */
struct PmSockHostLookupSession_ {
    enum PslHostLookupState lookupState; ///< set to true

    char*           userLabel;  ///< duplicated string for logging

    char*           hostname;   ///< name to resolve; duplicated string

    int             family;     ///< Requested address family (e.g., AF_INET)

    PmSockHostLookupCb* userCb; ///< user's completion callback
    void*           userCbData; ///< user's callback data

    GMainContext*   gmainCtx;   ///< referenced g_main execution context

    ares_channel    aresChan;

    /// psl_multi_fd_watch source instance; MUST be ready before
    /// calling ares_gethostbyname.
    PslMultiFdWatchSource*  multiFdWatch;

    /// idle source that is used to kick-start the query
    GSource*        queryStarter;

    /**
     * inAresHostCallbackCnt - Incremented when our
     * ares_host_callback enters and decremented when it exits.
     * This is used to detect if PmSockHostLookupDestroy is being
     * called re-entrantly, in which case we will just set
     * needDestroy, and perform destruction when the call chain
     * unwinds.
     */
    int             inAresHostCallbackCnt;
    bool            needDestroy;

    /// Records c-ares error that was passed to us via completion callback
    /// (ares_host_callback) from the scope of our calls into ares_gethostbyaddr
    /// and ares_process/ares_process_fd (ARES_SUCCESS, etc.)
    bool            aresHostCbWasCalled; ///< true if callback was called
    int             aresHostCbStatus;    ///< error code passed to callback
};

static PslError
pslerror_from_ares(int aresErr);

static void
psl_host_lookup_destroy_internal(PmSockHostLookupSession* ses);

static void
psl_host_lookup_free_ares_and_multi_fd_watch(PmSockHostLookupSession* ses);

static gboolean
psl_kick_start_ares_idle_cb(gpointer userData);

static void
psl_ares_sock_state_cb(void *userData, ares_socket_t socket_fd,
                       int readable, int writable);

static void
psl_ares_host_callback(void *arg, int status, int timeouts,
                       struct hostent *hostent);

static gboolean
psl_host_lookup_fd_watch_cb(gpointer userData,
                            const PslMultiFdPollRec* pollrecs,
                            int numrecs);
/// Declare in terms of PslMultiFdWatchSourceCb to make sure we got the args right
static PslMultiFdWatchSourceCb psl_host_lookup_fd_watch_cb;

static void
psl_host_lookup_update_fd_watch_timeout(PmSockHostLookupSession* ses);

static gint
psl_host_lookup_tv_to_millisec(const struct timeval* tvp);


/* ============================================================================
 *                            FUNCTIONS
 * ============================================================================
 */


/* =========================================================================
 * =========================================================================
 */
PslError
PmSockHostLookupNew(PmSockHostLookupSession**   const   pSession,
                    const char*                 const   hostname,
                    int                         const   family,
                    void*                       const   userData,
                    PmSockHostLookupCb*         const   cb,
                    const char*                 const   userLabel,
                    GMainContext*                       gmainCtx)
{
    PSL_LOG_DEBUG("%s: pSess=%p, host=\"%s\", family=%d, userData=%p, " \
                  "cb=%p, userLabel=\"%s\", gmaincxt=%p", 
                  __func__, pSession, PSL_LOG_OBFUSCATE_STR(hostname),
                  family, userData, cb, PSL_LOG_MAKE_SAFE_STR(userLabel),
                  gmainCtx);

    PSL_ASSERT(pSession); *pSession = NULL;
    PSL_ASSERT(hostname);
    PSL_ASSERT(cb);

    struct PmSockHostLookupSession_* const ses =
        g_new0(struct PmSockHostLookupSession_, 1);

    PslError pslerr = 0;

    if (!ses) {
        pslerr = PSL_ERR_MEM;
        goto error_cleanup;
    }

    ses->lookupState = kPslHostLookupState_initializing;

    // Copy user args

    ses->userLabel = g_strdup(userLabel ? userLabel : "PSL_user");
    ses->hostname = g_strdup(hostname);
    if (!ses->userLabel || !ses->hostname) {
        pslerr = PSL_ERR_MEM;
        goto error_cleanup;
    }

    gmainCtx = gmainCtx ? gmainCtx : g_main_context_default();
    ses->gmainCtx = g_main_context_ref(gmainCtx);
    ses->family = family;
    ses->userCb = cb;
    ses->userCbData = userData;

    // Set up our multi-fd watch source for monitoring c-ares's fds
    ses->multiFdWatch = psl_multi_fd_watch_new();
    if (!ses->multiFdWatch) {
        pslerr = PSL_ERR_MEM;
        goto error_cleanup;
    }
    g_source_set_can_recurse((GSource*)ses->multiFdWatch, false);
    g_source_set_callback((GSource*)ses->multiFdWatch,
                          (GSourceFunc)&psl_host_lookup_fd_watch_cb, ses, NULL);
    g_source_attach((GSource*)ses->multiFdWatch, ses->gmainCtx);


    // Create a c-ares instance
    struct ares_options aresOpt;
    memset(&aresOpt, 0, sizeof(aresOpt));
    int aresOptMask = 0;
    aresOpt.sock_state_cb = &psl_ares_sock_state_cb;
    aresOpt.sock_state_cb_data = ses;
    aresOptMask |= ARES_OPT_SOCK_STATE_CB;
    int aresRes = ares_init_options(&ses->aresChan, &aresOpt, aresOptMask);
    if (ARES_SUCCESS != aresRes) {
        PSL_LOG_FATAL("%s: ares_init_options() failed; ares error=%d",
                      __func__, (int)aresRes);
        pslerr = pslerror_from_ares(aresRes);
        goto error_cleanup;
    }

    PSL_LOG_DEBUG("%s: (%s): PSL host lookup session created: session=%p",
                  __func__, ses->userLabel, ses);
    ses->lookupState = kPslHostLookupState_initialized;
    *pSession = ses;
    return 0;

error_cleanup:
    PSL_ASSERT(pslerr);
    PSL_LOG_FATAL("%s (%s): FAILED: PslError=%d (%s)",
                  __func__, PSL_LOG_MAKE_SAFE_STR(userLabel), pslerr,
                  PmSockErrStringFromError(pslerr));
    if (ses) {
        psl_host_lookup_destroy_internal(ses);
    }
    return pslerr;
} //PmSockHostLookupNew


/* =========================================================================
 * =========================================================================
 */
PslError
PmSockHostLookupStart(PmSockHostLookupSession* const ses)
{
    PSL_ASSERT(ses);
    PSL_ASSERT(kPslHostLookupState_initialized == ses->lookupState);


    PSL_LOG_DEBUG("%s (%s): starting lookup session: session=%p",
                  __func__, ses->userLabel, ses);

    ses->lookupState = kPslHostLookupState_running;

    /**
     * @note Our goal is to fire off a call to ares_gethostbyname;
     *       however, ares_gethostbyname may issue an immediate
     *       ares_host_callback, and we would like to avoid doing
     *       this in the scope of user's call to us, as this type of
     *       reentrancy might be unexpected by the caller and is
     *       somewhat error-prone.  So, we're going to schedule an
     *       idle source to get things rolling from a gmainloop
     *       context instead.
     */


    ses->lookupState = kPslHostLookupState_running;

    ses->queryStarter = g_idle_source_new();
    g_source_set_priority(ses->queryStarter, G_PRIORITY_DEFAULT);
    g_source_set_can_recurse(ses->queryStarter, false);
    g_source_set_callback(ses->queryStarter, psl_kick_start_ares_idle_cb, ses,
                          NULL);
    g_source_attach(ses->queryStarter, ses->gmainCtx);

    return 0;
}


/* =========================================================================
 * =========================================================================
 */
void
PmSockHostLookupDestroy(PmSockHostLookupSession* const ses)
{
    PSL_ASSERT(ses);

    if (ses->inAresHostCallbackCnt) {
        ses->needDestroy = true;
        PSL_LOG_DEBUG("%s (%s): called re-entrantly from user callback; " \
                      "will finish destruction when call chain unwinds",
                      __func__, ses->userLabel);
        return;
    }


    PSL_LOG_DEBUG("%s (%s): destroying session=%p", __func__, ses->userLabel,
                  ses);
    psl_host_lookup_destroy_internal(ses);
}



/* =========================================================================
 * =========================================================================
 */
static PslError
pslerror_from_ares(int aresErr)
{
    /// @todo translate more c-ares errors
    switch (aresErr) {
    case ARES_SUCCESS:
        return PSL_ERR_NONE;
        break;
    case ARES_ENOMEM:
        return PSL_ERR_MEM;
        break;
    default:
        return PSL_ERR_GETADDRINFO; 
        break;
    }
}


/* =========================================================================
 * =========================================================================
 */
static void
psl_host_lookup_destroy_internal(PmSockHostLookupSession* ses)
{
    PSL_LOG_DEBUG("%s: ses=%p", __func__, ses);

    PSL_ASSERT(ses);

    // Suppress ares callbacks
    ses->lookupState = kPslHostLookupState_destroying;

    /**
     * Free the session's ares channel and its multi-fd watch source
     * 
     * @note Since ares destruction may trigger callbacks, the ares
     *       channel must be destroyed BEFORE other data members of
     *       the lookup session instance.
     */
    psl_host_lookup_free_ares_and_multi_fd_watch(ses);

    if (ses->queryStarter) {
        g_source_destroy(ses->queryStarter);
        g_source_unref(ses->queryStarter); 
    }

    g_free(ses->hostname);
    g_free(ses->userLabel);

    if (ses->gmainCtx) {
        g_main_context_unref(ses->gmainCtx);
    }

    g_free(ses);
}



/** ========================================================================
 * Safely destroys the session's ares channel and the multi-fd
 * watch source, if they were created
 * 
 * @note calling ares_destroy may result in our callbacks being
 *       called from areas (both host and socket callbacks may
 *       be called).  Therefore, the ares channel must be
 *       destroyed BEFORE other objects.
 * @param ses
 * =========================================================================
 */
static void
psl_host_lookup_free_ares_and_multi_fd_watch(PmSockHostLookupSession* ses)
{
    if (ses->aresChan) {
        // @note may trigger callbacks from ares channel
        ares_destroy(ses->aresChan);
        ses->aresChan = NULL;
    }

    // This multi-fd watch source will be freed as soon as
    // as the gmainloop dispatch call-chain unwinds
    if (ses->multiFdWatch) {
        (void)psl_multi_fd_watch_reset(ses->multiFdWatch);
        g_source_destroy((GSource*)ses->multiFdWatch);
        g_source_unref((GSource*)ses->multiFdWatch);
        ses->multiFdWatch = NULL;
    }
}



/** ========================================================================
 * Called by our ses->queryStarter idle source to kick-start the
 * query
 * 
 * @param userData Should be a PmSockHostLookupSession*
 *                 instance
 * 
 * @return gboolean We always return FALSE here to trigger
 *          removal and destruction of this idle source
 * =========================================================================
 */
static gboolean
psl_kick_start_ares_idle_cb(gpointer userData)
{
    if (PSL_CONFIG_DEEP_ERROR_CHECKS) {
        GSource* thisSource = g_main_current_source();
        if (g_source_is_destroyed(thisSource)) {
            /**
             * @note This should not happen since the user should use the
             *       lookup session instance only from the same gmainloop
             *       context as the one the running on, but better be safe
             *       than sorry.
             */
            PSL_LOG_FATAL("%s: UNEXPECTED: MY IDLE SOURCE=%p WAS DESTROYED",
                          __func__, thisSource);
            return false;
        }
    }

    struct PmSockHostLookupSession_* ses =
        (struct PmSockHostLookupSession_*)userData;

    PSL_ASSERT(ses->queryStarter);

    g_source_unref(ses->queryStarter);  //< don't need it any more
    ses->queryStarter = NULL;           //< so it won't get destroyed again

    /**
     * Get ready, set, go!
     * 
     * @note ares_gethostbyname may complete and call our
     *       psl_ares_host_callback() function immediately before
     *       returning if it can or needs to because of error
     * 
     * @note ares_gethostbyname may also cause our
     *       psl_ares_sock_state_cb() function to be called
     *       immediately before it returns.
     */
    ares_gethostbyname(ses->aresChan, ses->hostname, ses->family,
                       &psl_ares_host_callback, ses);

    /**
     * @note If ares_gethostbyname completes and calls our
     *       psl_ares_host_callback function immediately, The user
     *       may have already called PmSockHostLookupDestroy from the
     *       scope of the user's callback.
     */
    if (ses->needDestroy) {
        PmSockHostLookupDestroy(ses);
        ses = NULL; //< it's unsafe to access this session now
    }
    else {
        // If completion callback executed, we close the c-ares channel and 
        // the multi-fd watch source to free up resources
        if (ses->aresHostCbWasCalled) {
            psl_host_lookup_free_ares_and_multi_fd_watch(ses);
        }
        else {
            psl_host_lookup_update_fd_watch_timeout(ses);
        }
    }

    return false; //< false, so the source will be removed & destroyed
} //psl_kick_start_ares_idle_cb



/** ========================================================================
 * psl_ares_sock_state_cb - called by c-ares from the scope of
 * our call to inform us about its socket monitoring needs
 * 
 * @note WARNING: this may be called immediately from
 *       ares_gethostbyname or from
 *       ares_process/ares_process_fd, ares_cancel, or
 *       ares_destroy calls.
 * 
 * @param userData Our lookup session instance
 * @param socket_fd File descriptor of socket that changed state
 * @param readable Non-zero if socket is waiting to become
 *                 readable; zero if not.
 * @param writable Non-zero if the socket is waiting to become
 *                 writable; zero if not.
 * =========================================================================
 */
static void
psl_ares_sock_state_cb(void* const userData,
                       ares_socket_t const socket_fd,
                       int const readable,
                       int const writable)
{
    PSL_ASSERT(userData);

    struct PmSockHostLookupSession_* ses =
        (struct PmSockHostLookupSession_*)userData;

    PSL_LOG_DEBUG("%s (%s): session=%p, " \
                  "socket_fd=%d, readable=%d, writable=%d", __func__,
                  ses->userLabel, userData, (int)socket_fd, (int)readable,
                  (int)writable);

    GIOCondition condition = 0;

    if (readable) {
        condition |= G_IO_IN;
    }
    if (writable) {
        condition |= G_IO_OUT;
    }

    if (condition) {
        (void)psl_multi_fd_watch_add_or_update_fd(ses->multiFdWatch,
                                                  socket_fd,
                                                  condition);
    }
    else {
        /**
         * c-ares appears to pass both readable & writable as false
         * after closing the fd (makes sense, since it would normally
         * want to read anything that's coming in to free up socket
         * buffers, if for no other reason).  In the worst case, we'll
         * add it to the watch set again if c-ares decides to monitor it
         * again.
         */
        (void)psl_multi_fd_watch_remove_fd(ses->multiFdWatch, socket_fd);
    }

    return;
}



/** ========================================================================
 * Check if this lookup session is in the proper state to
 * handle an ares_host_callback.
 * 
 * @param ses
 * @param funcName Non-NULL name of regequesting function (for
 *                 logging)
 * 
 * @return bool True if okay to handle a c-ares callback, false
 * if not.
 * =========================================================================
 */
static bool
psl_is_ares_host_callback_allowed(PmSockHostLookupSession* ses,
                                  const char* funcName)
{
    PSL_ASSERT(ses);
    PSL_ASSERT(funcName);

    if (kPslHostLookupState_running != ses->lookupState) {
        PSL_LOG_DEBUG("%s: (%s): called in non-running lookup state=%d, " \
                      "suppressing", funcName, ses->userLabel,
                      ses->lookupState);
        return false;
    }
    if (ses->needDestroy) {
        PSL_LOG_DEBUG("%s: (%s): called, but needDestroy=true (state=%d), " \
                      "suppressing", funcName, ses->userLabel,
                      ses->lookupState);
        return false;
    }

    return true;
}



/** ========================================================================
 * psl_ares_host_callback - ares_host_callback registered with
 * ares_gethostbyname.  Called to notify us that the requested
 * lookup has completed.
 * 
 * @note WARNING: this may be called immediately from
 *       ares_gethostbyname or from
 *       ares_process/ares_process_fd, ares_cancel, or
 *       ares_destroy calls.
 * 
 * @param userData Our lookup session instance
 * @param status c-ares query completion status (ARES_SUCCESS or
 *               one of the error codes)
 * @param timeouts Number of query timeouts during execution of
 *                 this request
 * @param hostent pointer to 'struct hostent' on success; NULL
 *                on failure
 * 
 * =========================================================================
 */
static void
psl_ares_host_callback(void* const userData, int const status,
                       int const timeouts, struct hostent* const hostent)
{

    PSL_ASSERT(userData);

    struct PmSockHostLookupSession_* ses =
        (struct PmSockHostLookupSession_*)userData;

    PSL_LOG_DEBUG("%s (%s): ares host lookup completed: session=%p, " \
                  "ares status=%d (%s), timeouts=%d, hostent=%p", __func__,
                  ses->userLabel, userData, (int)status,
                  ARES_SUCCESS == status ? "success" : "FAILED",
                  (int)timeouts, hostent);

    PSL_ASSERT(!ses->aresHostCbWasCalled);
    ses->aresHostCbWasCalled = true;
    ses->aresHostCbStatus = status;


    if (!psl_is_ares_host_callback_allowed(ses, __func__)) {
        return;
    }

    /**
     * Protect the session instance from immediate deletion while
     * nested in the user callback
     */
    ses->inAresHostCallbackCnt++;

    ses->lookupState = kPslHostLookupState_finished;

    PslError const pslerr = (ARES_SUCCESS == status
                             ? 0
                             : pslerror_from_ares(status));


    // Notify user that request completed
    // 
    // @note User may call PmSockHostLookupDestroy immediately from its callback
    ses->userCb(ses->userCbData, ses, hostent, pslerr);

    ses->inAresHostCallbackCnt--;
    return;
} // psl_ares_host_callback



/** ========================================================================
 * psl_host_lookup_fd_watch_cb - called by our instance of
 * multi-fd watch source as PslMultiFdWatchSourceCb when requested
 * condition(s) are satifisfied on one or more file descriptors
 * being monitored
 * 
 * @param userData @see PslMultiFdWatchSourceCb
 * @param pollrecs @see PslMultiFdWatchSourceCb
 * @param numrecs @see PslMultiFdWatchSourceCb
 * 
 * @return gboolean TRUE to avoid being destroyed by gmainloop
 *         dispatcher
 * =========================================================================
 */
static gboolean
psl_host_lookup_fd_watch_cb(gpointer userData,
                            const PslMultiFdPollRec* pollrecs,
                            int numrecs)
{
    if (PSL_CONFIG_DEEP_ERROR_CHECKS) {
        GSource* thisSource = g_main_current_source();
        if (g_source_is_destroyed(thisSource)) {
            /**
             * @note This should not happen since the user should use the
             *       lookup session instance only from the same gmainloop
             *       context as the one the running on, but better be safe
             *       than sorry.
             */
            PSL_LOG_FATAL("%s: UNEXPECTED: MULTI-FD SOURCE=%p WAS DESTROYED",
                          __func__, thisSource);
            return true;
        }
    }

    PSL_ASSERT(userData);

    struct PmSockHostLookupSession_* ses =
        (struct PmSockHostLookupSession_*)userData;

    fd_set rfd_set, wfd_set;
    FD_ZERO(&rfd_set);
    FD_ZERO(&wfd_set);


    bool somethingSet = false;
    gint i;
    for (i=0; i < numrecs; i++, pollrecs++) {
        GIOCondition const ioerrBits = pollrecs->indEvents &
            ~(G_IO_IN | G_IO_OUT);

        if ((pollrecs->reqEvents & G_IO_IN) != 0) {
            if (ioerrBits || (pollrecs->indEvents & G_IO_IN) != 0) {
                FD_SET(pollrecs->fd, &rfd_set);
                somethingSet = true;
            }
        }

        if ((pollrecs->reqEvents & G_IO_OUT) != 0) {
            if (ioerrBits || (pollrecs->indEvents & G_IO_OUT) != 0) {
                FD_SET(pollrecs->fd, &wfd_set);
                somethingSet = true;
            }
        }
    }

    if (!somethingSet) {
        PSL_LOG_DEBUG("%s (%s): cb called, but nothing of " \
                      "interest was set: probably timed out",
                      __func__, ses->userLabel);
    }

    /**
     * Handle input/output events in our c-ares channel instance
     * 
     * @note ares_process may complete and call our
     *       psl_ares_host_callback() function synchronously before
     *       returning if it's done or needs to because of error
     * 
     * @note ares_process may also cause our
     *       psl_ares_sock_state_cb() function to be called
     *       synchronously before it returns.
     */
    ares_process(ses->aresChan, &rfd_set, &wfd_set);


    /**
     * @note If ares_process completes and calls our
     *       psl_ares_host_callback function immediately, the user
     *       may have already called PmSockHostLookupDestroy from the
     *       scope of the user's callback.
     */
    if (ses->needDestroy) {
        PmSockHostLookupDestroy(ses);
        ses = NULL; //< it's unsafe to access this session now
    }
    else {

        // If completion callback executed, we close the c-ares channel and 
        // the multi-fd watch source to free up resources
        if (ses->aresHostCbWasCalled) {
            // @note The multi-fd watch source will be freed as soon as
            //       as this gmainloop dispatch call-chain unwinds
            psl_host_lookup_free_ares_and_multi_fd_watch(ses);
        }
        else {
            psl_host_lookup_update_fd_watch_timeout(ses);
        }

    }

    return true; //< we don't want main loop to destroy us implicitly
} // psl_host_lookup_fd_watch_cb


/** ========================================================================
 * Get timeout value from our c-ares channel instance and update
 * our our multi-fd watch source instance.
 * 
 * @param ses
 * =========================================================================
 */
static void
psl_host_lookup_update_fd_watch_timeout(PmSockHostLookupSession* ses)
{
    struct timeval tv, *tvp;

    /**
     * @note ares_timeout may return NULL (the value of maxtv arg
     *       that we pass to it) if there are no timeouts pending in
     *       the ares channel (e.g., when there are no pending
     *       queries)
     */
    tvp = ares_timeout(ses->aresChan, NULL, &tv);

    (void)psl_multi_fd_watch_set_poll_timeout(ses->multiFdWatch,
                                         psl_host_lookup_tv_to_millisec(tvp));
}


/** ========================================================================
 * Convert a 'struct timeval' value to milliseconds
 * 
 * @param tvp Timeout expressed via 'struct timeval' or NULL for
 *            "infinite"
 * 
 * @return gint Positive millesecond equivalent of the passed
 *         'struct timeval" or
 * =========================================================================
 */
static gint
psl_host_lookup_tv_to_millisec(const struct timeval* tvp)
{
    if (!tvp) {
        return -1;
    }

    /// @todo need to optimize
    gint res;
    gdouble temp = (tvp->tv_sec * 1000.0);
    if (tvp->tv_usec > 1000) {
        temp += (tvp->tv_usec / 1000);
    }
    if (temp > G_MAXINT) {
        res = G_MAXINT;
    }
    else {
        res = temp;
        if (!res && tvp->tv_usec) {
            res = 1;
        }
    }

    return res;
}
