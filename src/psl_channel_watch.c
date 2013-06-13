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
 * @file psl_channel_watch.c
 * @ingroup psl_internal 
 * 
 * @brief  palmsocket watch GSource implementation.
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>

#include <glib.h>

#include "palmsocket.h"

#include "psl_common.h"
#include "psl_log.h"
#include "psl_assert.h"
#include "psl_error_utils.h"

#include "psl_channel.h"


/// Represents an invalid FD (a valid file descriptor is >= 0)
#define CHAN_WATCH_INVALID_FD               PSL_INVALID_FD


/**
 * @note These are technically output-only conditions from the
 *       posix poll() function family. If a file descriptor
 *       (e.g., socket) is being monitored for any other
 *       condition, and one of these errors occurs, glib will
 *       keep calling us with these flags until the condition is
 *       cleared.  So, even if the user didn't request these
 *       conditions, we'll still be called continuously until
 *       the source of these errors is cleared by the user
 *       (e.g., by closing the watch and the socket).
 */
#define CHAN_WATCH_ERR_GIOCONDITIONS   PSL_FAIL_GIOCONDITIONS


/// We support only these GIOCondition flags
#define CHAN_WATCH_SUPPORTED_CONDITIONS     \
    (G_IO_IN | G_IO_OUT | G_IO_PRI | CHAN_WATCH_ERR_GIOCONDITIONS)

/**
 * Our private PmSockWatch implementation structure
 */
struct PmSockWatch_ {
    GSource                 base;   ///< MUST BE FIRST DATA MEMBER!


    PmSockIOChannel*        channel;    ///< the channel being watched

    GIOCondition            conditions; ///< requested conditions

    bool                    pollAdded;  ///< via g_source_add_poll()
    GPollFD                 pollfd;
};



/**
 * GSourceFuncs::prepare method
 * 
 * @param source
 * @param timeout
 * 
 * @return gboolean
 */
static gboolean
chan_watch_prepare(GSource* source, gint* timeout);

/**
 * GSourceFuncs::check method
 * 
 * @param source
 * 
 * @return gboolean
 */
static gboolean
chan_watch_check(GSource* source);

/**
 * GSourceFuncs::dispatch method
 * 
 * @param source
 * @param callback
 * @param userData
 * 
 * @return gboolean
 */
static gboolean
chan_watch_dispatch(GSource* source,
                    GSourceFunc callback,
                    gpointer userData);

/**
 * GSourceFuncs::finalize method
 * 
 * @param source
 */
static void
chan_watch_finalize(GSource* source);


static GIOCondition
chan_watch_check_what_is_ready(PmSockWatch* const watch);


/**
 * Table of GSource methods for the palmsocket channel watch
 * source
 *
 * @note g_source_new is declared to acept this table as
 *       non-const
 */
static GSourceFuncs gChanWatchFuncs = {
    &chan_watch_prepare,
    &chan_watch_check,
    &chan_watch_dispatch,
    &chan_watch_finalize,
    NULL,
    NULL
};


/** ========================================================================
 * =========================================================================
 */
PslError
PmSockWatchUpdate(PmSockWatch* const watch, GIOCondition const conditions)
{
    PSL_LOG_DEBUG("%s (watch=%p): new GIOCondition=0x%lX", __func__, watch,
                  (unsigned long)conditions);

    if (0 != (conditions & ~CHAN_WATCH_SUPPORTED_CONDITIONS)) {
        /// @note It's possible that some additional poll conditions will
        ///       be exposed by glib in the future, but this warning may be
        ///       helpful for now in alerting the app developer of invalid input
        PSL_LOG_WARNING(
            "%s (watch=%p): WARNING: unexpected GIOCondition values: 0x%lX",
            __func__, watch,
            (unsigned long)(conditions & ~CHAN_WATCH_SUPPORTED_CONDITIONS));
    }

    watch->conditions = conditions;

    return 0;
}


/** ========================================================================
 * =========================================================================
 */
PslError
psl_chan_watch_new(PmSockWatch**    const pWatch,
                   PmSockIOChannel* const ch,
                   GIOCondition     const conditions)
{
    PSL_LOG_DEBUG("%s (ch=%p): initial GIOCondition=0x%lX", __func__, ch,
                  (unsigned long)conditions);

    PSL_ASSERT(pWatch);
    PSL_ASSERT(ch);

    *pWatch = NULL;

    GSource* const base = g_source_new(&gChanWatchFuncs,
                                       sizeof(struct PmSockWatch_));
    PmSockWatch* const watch = (PmSockWatch*)base;

    if (!base) {
        return PSL_ERR_MEM;
    }

    watch->channel = psl_chan_header_ref(ch);

    watch->conditions = conditions;

    if ((conditions & ~CHAN_WATCH_SUPPORTED_CONDITIONS) != 0) {
        /// @note It's possible that some additional poll conditions will
        ///       be exposed by glib in the future, but this warning may be
        ///       helpful for now in alerting the app developer of invalid input
        PSL_LOG_WARNING(
            "%s (watch=%p): WARNING: unexpected GIOCondition values: 0x%lX",
            __func__, watch,
            (unsigned long)(conditions & ~CHAN_WATCH_SUPPORTED_CONDITIONS));
    }

    /**
     * @note We add poll (g_source_add_poll) dynamically in our
     *       'prepare', 'check', and 'dispatch' methods because an
     *       FD is not always available in our channel.
     */
    watch->pollfd.fd = CHAN_WATCH_INVALID_FD;

    PSL_LOG_INFO("%s (ch=%p): new watch=%p, initial GIOCondition=0x%lX",
                 __func__, ch, watch, (unsigned long)conditions);

    *pWatch = watch;
    return 0;
}



/** ========================================================================
 * =========================================================================
 */
static gboolean
chan_watch_prepare(GSource* const base, gint* const timeout)
{
    PmSockWatch* const watch = (PmSockWatch*)base;

    PSL_LOG_DEBUG("%s (watch=%p): monitoring GIOCondition=0x%lX", __func__,
                  base, (unsigned long)watch->conditions);

    *timeout = -1;
    bool isReadyNow = false;

    watch->pollfd.events = watch->pollfd.revents = 0;

    PslChanIOReadiness pfinfo;
    psl_chan_do_io_readiness_preflight(watch->channel, watch->conditions,
                                       &pfinfo);
    watch->pollfd.fd = pfinfo.fd;
    watch->pollfd.events = pfinfo.pollCond;

    isReadyNow = !!pfinfo.readyCond;


    /// Request polling if we have events and and FD to poll for
    if (watch->pollfd.events && watch->pollfd.fd >= 0) {
        if (!watch->pollAdded) {
            PSL_LOG_DEBUGLOW("%s (watch=%p): adding pollfd", __func__, base);
            g_source_add_poll (base, &watch->pollfd);
            watch->pollAdded = true;
        }
    }

    else { /// Nothing to monitor, so remove our pollrec
        watch->pollfd.events = 0;
        if (watch->pollAdded) { 
            PSL_LOG_DEBUGLOW("%s (watch=%p): removing pollfd", __func__, base);
            g_source_remove_poll(base, &watch->pollfd);
            watch->pollAdded = false;
        }
    }


    PSL_LOG_DEBUG("%s (watch=%p): %s, isClosed=%d, fd=%d, timeout=%d, " \
                  "GIOCondition=(mon:0x%lX, ready:0x%lX, polling:0x%lX)",
                  __func__, base, isReadyNow ? "READY" : "NOT READY",
                  (int)pfinfo.isClosed, (int)watch->pollfd.fd, *timeout,
                  (unsigned long)watch->conditions,
                  (unsigned long)pfinfo.readyCond,
                  (unsigned long)watch->pollfd.events);

    return isReadyNow;
}//chan_watch_prepare



/** ========================================================================
 * =========================================================================
 */
static gboolean
chan_watch_check(GSource* const base)
{
    PmSockWatch* const watch = (PmSockWatch*)base;

    PSL_LOG_DEBUG("%s (watch=%p): GIOCondition=(mon:0x%lX, revents:0x%lX)",
                  __func__, base,
                  (unsigned long)watch->conditions,
                  (unsigned long)watch->pollfd.revents);

    GIOCondition const cond = chan_watch_check_what_is_ready(watch);
    if (cond) {
        PSL_LOG_DEBUG("%s (watch=%p): READY: effective GIOCondition=0x%lX",
                      __func__, base, (unsigned long)cond);
        return true;
    }
    else {
        PSL_LOG_DEBUG("%s (watch=%p): NOT READY: effective GIOCondition=0",
                      __func__, base);
        return false;
    }
}



/** ========================================================================
 * =========================================================================
 */
static gboolean
chan_watch_dispatch(GSource*    const base,
                    GSourceFunc const callback,
                    gpointer    const userData)
{
    PmSockWatch* const watch = (PmSockWatch*)base;

    PSL_LOG_DEBUG("%s (watch=%p): GIOCondition=(mon:0x%lX, revents:0x%lX)",
                  __func__, base,
                  (unsigned long)watch->conditions,
                  (unsigned long)watch->pollfd.revents);

    GIOFunc const func = (GIOFunc)callback;
    if (!func) {
        PSL_LOG_ERROR("%s: watch=%p: ERROR: PmSockWatch with " \
                      "NULL user callback: did you forget to call " \
                      "g_source_set_callback()?", __func__, base);
        return false; ///< force detach from gmainloop context
    }

    /**
     * Check again, because dispatch to user from another source may
     * have altered the channel's IO conditions.
     */
    GIOCondition const cond = chan_watch_check_what_is_ready(watch);
    if (cond) {
        PSL_LOG_DEBUG(
            "%s (watch=%p): dispatching to user: effective GIOCondition=0x%lX",
            __func__, base, (unsigned long)cond);

        bool const stayAttached = func((GIOChannel*)watch->channel, cond,
                                       userData);

        PSL_LOG_DEBUGLOW(
            "%s (watch=%p): user dispatch returned: stayAttached=%d; " \
            "isDestroyed=%d, refCnt=%u",
            __func__, base, (int)stayAttached, (int)g_source_is_destroyed(base),
            (unsigned)base->ref_count);

        return stayAttached;
    }
    else {
        /// Requested condition must have changed after 'check' was called
        PSL_LOG_DEBUG("%s (watch=%p): suppressing dispatch to user: " \
                      "effective GIOCondition=0", __func__, base);
        return true; ///< don't force detach from gmainloop context
    }
}//chan_watch_dispatch



/** ========================================================================
 * =========================================================================
 */
static void
chan_watch_finalize(GSource* const base)
{
    PSL_LOG_INFO("%s (watch=%p)", __func__, base);

    PmSockWatch* const watch = (PmSockWatch*)base;

    if (watch->channel) {
        psl_chan_header_unref(watch->channel);
    }
}



/** ========================================================================
 * Sync up with channel and check which of the monitored
 * conditions are ready based on channel hints and current
 * pollfd->revents value.
 * 
 * @param watch
 * 
 * @return GIOCondition
 * 
 * =========================================================================
 */
static GIOCondition
chan_watch_check_what_is_ready(PmSockWatch* const watch)
{
    PslChanIOReadiness pfinfo;
    psl_chan_do_io_readiness_preflight(watch->channel, watch->conditions,
                                       &pfinfo);

    GIOCondition const cond = (pfinfo.readyCond |
                               (watch->pollfd.revents & pfinfo.pollCond));
    return cond;
}
